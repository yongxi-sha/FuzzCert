import time
import traceback
import numpy as np
import time
import sys
from verapak.parse_args.tools import parse_args
import os
from config import Config, ConfigError
from verapak.parse_args.tools import parse_args
from algorithm import main
from verapak.utilities.sets import Reporter, DoneInterrupt

from verapak.verification.ve import ALL_SAFE, ALL_UNSAFE, SOME_UNSAFE, TOO_BIG, UNKNOWN, BOUNDARY
from verapak.utilities.point_tools import point_in_region
from verapak.utilities.sets import make_sets

def load_config_from_corpus(corpus_dir):
    for filename in os.listdir(corpus_dir):
        path=os.path.join(corpus_dir,filename)
        fuzz_args=[
            f"--config_file={path}",
            "--output_dir=/src/out",
            "--halt_on_first=loose",
        ]
        break

    return fuzz_args


def get_params(config, reporter):
    start_time = time.time()
    reporter.setup(config, start_time)

    sets = make_sets(reporter)

    safety_predicate = config["safety_predicate"]
    # Check initial point safety
    if config["initial_point"] is not None and not safety_predicate(config["initial_point"]):
        # UNSAFE: Add I to SOME_UNSAFE queue
        sets[SOME_UNSAFE](config["initial_region"], config["initial_point"], reporter.total_area)
    else:
        # SAFE: Add I to UNKNOWN set
        sets[UNKNOWN](config["initial_region"], reporter.total_area)

    if config['timeout'] <= 0:
        timed_out = lambda: False
    else:
        timed_out = lambda: reporter.get_elapsed_time() > config['timeout']

    # Main Loop: Stop if timeout expires or if UNKNOWN and SOME_UNSAFE are both empty
    while True: #(sets[UNKNOWN].set.size() > 0 or not sets[SOME_UNSAFE].queue.empty()) \
            #and not (config['timeout'] > 0 and reporter.get_elapsed_time() > config['timeout']):
        reporter.report_status()

        if timed_out():
            # If timeout expires, stop.
            break

        if len(sets[UNKNOWN]) > 0:
            # Pull from UNKNOWN first, if any (TODO: prove maintains largest-first)
            region = sets[UNKNOWN].get_next()
            adv_example = None
            was_unsafe = False
        elif len(sets[SOME_UNSAFE]) > 0:
            # If UNKNOWN is empty, pull from SOME_UNSAFE
            region, adv_example = sets[SOME_UNSAFE].get_next()
            was_unsafe = True
        else:
            # If both are empty, we're done!
            break

        if region.low.shape != config['graph'].input_shape:
            region.low = region.low.reshape(config['graph'].input_shape).astype(config['graph'].input_dtype)
        if region.high.shape != config['graph'].input_shape:
            region.high = region.high.reshape(config['graph'].input_shape).astype(config['graph'].input_dtype)
        region_area = reporter.get_area(region)

        if ((region.high - region.low) <= 0).any(): # NOTE: Only necessary for UNKNOWN
            # Empty regions should be pretty rare, but they are possible in discrete cases
            continue # Grab the next one

        '''
        if was_unsafe: # We grabbed an unsafe region
            partition = config['strategy']['partitioning'].partition(region)
            for r in partition:
                r_area = reporter.get_area(r)
                if adv_example is not None and point_in_region(r, adv_example):
                    sets[SOME_UNSAFE].append((r, adv_example))
                    #reporter.move_area(SOME_UNSAFE, SOME_UNSAFE, r_area) # Redundant
                    #reporter.add_adversarial_example(adv_example) # Already known
                    # TODO: Handle case where verifier can improve some_unsafe to all_unsafe
                else:
                    sets[UNKNOWN](r, r_area, from_=SOME_UNSAFE)
            continue # Regions added to the Unknown set will be the only ones there, and will be processed first
            # NOTE: This does NOT preserve largest-first ordering
        '''


        # falsify(config, partition[0], sets['reporter'].get_area(partition[0]), sets, from_=UNKNOWN)
        return config, region, sets

def create_witness(config, adversarial_example):
    input_values = adversarial_example.flatten(),
    output_values = config['graph'].evaluate(adversarial_example).flatten()

    witness = "("
    for idx, x in np.ndenumerate(input_values):
        witness += f"(X_{idx[0]} {x})\\n"
    for idx, y in np.ndenumerate(output_values):
        witness += f"(Y_{idx[0]} {y})\\n"
    witness += ")"
    return witness

def write_results(config, adversarial_examples, halt_reason, elapsed_time):
    witness = ""
    adv_count = 0
    if adversarial_examples and adversarial_examples.size() > 0:
        witness = create_witness(next(adversarial_examples.elements()))
        adv_count = adversarial_examples.size()
        adv_examples_numpy = np.array([x for x in adversarial_examples.elements()])
        output_file = os.path.join(config['output_dir'], 'adversarial_examples.npy')
        np.save(output_file, adv_examples_numpy)
    if halt_reason in ["done", "first"]:
        halt_reason = "sat" if (adv_count > 0) else "unsat"

    if "output_dir" in config:
        output_file = os.path.join(config['output_dir'], 'report.csv')
        output_file = open(output_file, 'w')
        output_file.write(f"{halt_reason},{witness},{adv_count},{elapsed_time}\n")
        output_file.close()


def run(config):
    reporter = Reporter()
    try:
        # Get Initial falsify parameters
        initial_params = get_params(config, reporter)
        # print(f"initial parameters for Falsify: {initial_params}")
    except KeyboardInterrupt as e:
        reporter.halt_reason = "keyboard"
    except DoneInterrupt as e:
        pass
    except BaseException as e:
        reporter.halt_reason = "error"
        traceback.print_exception(type(e), e, e.__traceback__)

    if reporter.started:
        reporter.give_final_report()
        et = reporter.get_elapsed_time()
    else:
        et = 0
    adversarial = reporter.get_adversarial_examples()
    halt_reason = reporter.get_halt_reason
    write_results(config, adversarial, halt_reason, et)
    print('done')
    return initial_params

def get_fal_paras(args):
    print(args)
    config = parse_args(args, prog="falsify_interface2.py")
    #print(config)
    if "error" in config:
        print(f"\033[38;2;255;0;0mERROR: {config['error']}\033[0m")
        write_results(config, None, "error_" + config["error"], 0)
    else:
        try:
            config = Config(config)
        except ConfigError as ex:
            print(ex)
        else: # Valid Config
            for strategy in config["strategy"].values():
                strategy.set_config(config)

            params=run(config)

            for strategy in config["strategy"].values():
                strategy.shutdown()

            #print(params)
            return params