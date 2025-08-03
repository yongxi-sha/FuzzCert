import os
import sys
import traceback
import numpy as np
import time

from config import Config, ConfigError
from verapak.parse_args.tools import parse_args
from algorithm import main
from verapak.utilities.sets import Reporter, DoneInterrupt, make_sets
from verapak.verification.ve import ALL_SAFE, ALL_UNSAFE, SOME_UNSAFE, TOO_BIG, UNKNOWN, BOUNDARY
from verapak.utilities.point_tools import point_in_region


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


def get_params(config, reporter):
    start_time = time.time()
    reporter.setup(config, start_time)

    sets = make_sets(reporter)

    safety_predicate = config["safety_predicate"]
    # Check initial point safety
    if config["initial_point"] is not None and not safety_predicate(config["initial_point"]):
        # UNSAFE: Add I to SOME_UNSAFE queue
        sets[UNKNOWN](config["initial_region"], config["initial_point"], reporter.total_area)
    else:
        # SAFE: Add I to UNKNOWN set
        sets[UNKNOWN](config["initial_region"], reporter.total_area)

    if sets[UNKNOWN].set.size() > 0:
        # Pull from UNKNOWN first, if any (TODO: prove maintains largest-first)
        region = sets[UNKNOWN].set.pop_random()[1]
        adv_example = None
        was_unsafe = False
    elif sets[SOME_UNSAFE].set.size() > 0:
        # If UNKNOWN is empty, pull from SOME_UNSAFE
        region, adv_example = sets[SOME_UNSAFE].queue.get_nowait()
        was_unsafe = True
    else:
        # If both are empty, we're done!
        return -1

    region = (
        region[0].reshape(config['graph'].input_shape).astype(config['graph'].input_dtype),
        region[1].reshape(config['graph'].input_shape).astype(config['graph'].input_dtype),
        region[2]
    )
    region_area = reporter.get_area(region)

    if ((region[1] - region[0]) <= 0).any():  # NOTE: Only necessary for UNKNOWN
        # Empty regions should be pretty rare, but they are possible in discrete cases
        return -1  # empty regions

    # Verify is modified to just get the partitions and return parameters for falsify
    config, partitions, sets = verify(config, region, region_area, sets)
    # example showing a call to falsify with the returned parameters - here partitions is a list
    # with multiple possible partitioned regions - [0] in this case is the first one
    # from_=UNKNOWN -> no longer check the initial region and thus it is all unknown and resides in this
    # set prior to any falsify calls
    # falsify(config, partitions[0], sets['reporter'].get_area(partitions[0]), sets, from_=UNKNOWN)
    return config, partitions, sets


def verify(config, region, area, sets, from_=UNKNOWN):
    # TODO: Check confidence level, and sometimes send directly to Falsify

    partitions = config['strategy']['partitioning'].partition_impl(region)
    return (config, partitions, sets)

def falsify(config, region, area, sets, from_=UNKNOWN):
    # TODO: Pass parent data to child
    abstraction_engine = config['strategy']['abstraction'].abstraction_impl
    n = config['num_abstractions']
    safety_predicate = config['safety_predicate']

    abstractions = abstraction_engine(region, n)

    for point in abstractions:
        if not safety_predicate(point):
            if point_in_region(region, point):
                sets[SOME_UNSAFE](region, point, area, from_=from_)
                break
            else: # In case our abstraction engine gives a point outside this region
                # Only check UNKNOWN because SOME_UNSAFE is redundant, and ALL_UNSAFE and ALL_SAFE should be impossible
                found, found_region = sets[UNKNOWN].set.get_and_remove_region_containing_point(point)
                if found:
                    found_region = [x.reshape(config['graph'].input_shape)
                                    .astype(config['graph'].input_dtype)
                                    for x in found_region]
                    # TODO: define get_area(partition) in a better location
                    found_region_area = sets['reporter'].get_area(found_region)
                    sets[SOME_UNSAFE](found_region, point, found_region_area, from_=from_)
    else:
        # All abstracted points were safe
        sets[UNKNOWN](region, area, from_=from_)


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


