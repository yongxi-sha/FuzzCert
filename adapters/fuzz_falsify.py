import sys
import os
import atheris
import random
import numpy as np
import pickle
import coverage
from algorithm import main, verify
from config import Config
from verapak.abstraction.ae import AbstractionEngine
from falsify_interface2 import *

cov=coverage.Coverage()
cov.start()

with atheris.instrument_imports():
    from verapak.utilities.sets import make_sets, Reporter
    from verapak.verification.ve import UNKNOWN
    from verapak.parse_args.tools import parse_args
    from algorithm import falsify

corpus_dir="corpus"
for filename in os.listdir(corpus_dir):
    path=os.path.join(corpus_dir,filename)
    fuzz_args=[
        f"--config_file={path}",
        "--output_dir=/src/out",
        "--halt_on_first=loose",
    ]
    break

params=get_fal_paras(fuzz_args)

config, partitions, sets=params

pre_set = {
  "UNKNOWN": sets[UNKNOWN].set.size(),    
  "SAFE": sets[ALL_SAFE].set.size(),
  "UNSAFE": sets[ALL_UNSAFE].set.size(),
  "SOME_UNSAFE": sets[SOME_UNSAFE].queue.qsize()
}

counter=0

def falsify_predicate(pre_size, post_size):
    total_pre=sum(value for value in pre_size.values())
    total_post=sum(value for value in post_size.values())

    delta_unk=post_size["UNKNOWN"] - pre_size["UNKNOWN"]
    delta_someunsafe=post_size["SOME_UNSAFE"]-pre_size["SOME_UNSAFE"]

    total_delta=total_post-total_pre

    if total_delta == 1 and delta_someunsafe in [0,1] and delta_unk in [0,1] and delta_someunsafe != delta_unk:
        return True
    else:
        return False


def my_mutator(data, max_size, seed):

    random.seed(seed)
    for partition in partitions:
        high=partition[0]
        low=partition[1]
        ceil=1
        floor=0
        random_mod=np.random.uniform(floor, ceil, size=high.shape)
        sign=np.random.choice([-1,1],size=high.shape)
        new_high=high+(sign*random_mod)
        new_low=low+(sign*random_mod)
        mutated_region=[new_high, new_low, partition[2:]]
        break
    encoded_partition=pickle.dumps(mutated_region)
    print(len(encoded_partition))
    if len(encoded_partition) <= max_size:
        return encoded_partition[:max_size]
    else:
        raise NotImplementedError("returned data exceed max_len")


def TestOneInput(data):
    global counter
    counter+=1
    try:
        partition=pickle.loads(data)
        #for strategy in config["strategy"].values():
        #    strategy.set_config(config)
        print(partition)
        falsify(config, partition, sets['reporter'].get_area(partition), sets, from_=UNKNOWN)

        #for strategy in config["strategy"].values():
        #    strategy.shutdown()
        post_set={
                "UNKNOWN": sets[UNKNOWN].set.size(),
                "SAFE": sets[ALL_SAFE].set.size(),
                "UNSAFE": sets[ALL_UNSAFE].set.size(),
                "SOME_UNSAFE": sets[SOME_UNSAFE].queue.qsize()        
        }
        
        if falsify_predicate(pre_set, post_set):
            print("success")
        else:
            print("failure")
        pre_set=post_set
        
    except Exception:
        pass

    if counter > 10:
        cov.stop()
        cov.save()
        cov.report()
        cov.html_report()
        sys.exit(0)

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True, custom_mutator=my_mutator)
    atheris.Fuzz()

if __name__ == "__main__":
    main()

