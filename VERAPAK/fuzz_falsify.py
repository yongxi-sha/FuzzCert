import sys
import atheris
import tempfile
import os
import traceback
import time
import numpy as np

with atheris.instrument_imports():
    from config import Config
    from verapak.parse_args.tools import parse_args
    from verapak.verification.ve import UNKNOWN
    from verapak.abstraction.ae import AbstractionEngine
    from algorithm import main, verify, falsify
    from verapak.utilities.sets import make_sets, Reporter
    import fuzz_falsify

corpus_dir="corpus"
for filename in os.listdir(corpus_dir):
    path=os.path.join(corpus_dir,filename)
    fuzz_args=[
        f"--config_file={path}",
        "--output_dir=/src/out",
        "--halt_on_first=loose",
    ]
    break

def get_config(args):
    config = parse_args(fuzz_args, prog="fuzz_target.py")
    config = Config(config)
    return config


def get_init_region(config):
    initial_region=config["initial_region"]
    return initial_region


def get_init_area(reporter, region):
    area=reporter.get_area(region)
    return area


config=get_config(fuzz_args)
region=get_init_region(config)
reporter=Reporter()
start_time=time.time()
reporter.setup(config,start_time)
sets=make_sets(reporter)
area=get_init_area(reporter,region)
from_=UNKNOWN

def deserialize_input(data):
    try:
        region_data, area = pickle.loads(data)
        low, high = region_data
        low = np.array(low, dtype=input_dtype)
        high = np.array(high, dtype=input_dtype)
        return (low, high, ()), area
    except Exception:
        region = random_region()
        area = 1.0
        return region, area


def my_mutator(data, max_size, seed):
    
    '''
    random.seed(seed)
    np.random.seed(seed)
    try:
        region_data, area = pickle.loads(data)
        low, high = region_data
        low = np.array(low, dtype=input_dtype)
        high = np.array(high, dtype=input_dtype)
        region = (low, high, ())
    except Exception:
        region = random_region()
        area = 1.0

    region = mutate_region(region)
    area += random.uniform(-0.05, 0.05)
    area = max(area, 0.0)

    # serialize as (list, list), area
    serialized = pickle.dumps(((region[0].tolist(), region[1].tolist()), area))
    return serialized[:max_size]
    '''
    
    pass

def TestOneInput(data):

    #region, area = deserialize_input(data)

    print("++++++++++++++++config++++++++++++++++++++++")
    print(config)
    print("++++++++++++++++config++++++++++++++++++++++")
    print("----------------sets----------------------")
    print(sets)
    print("----------------sets----------------------")
    print("****************from_**********************")
    print(from_)
    print("****************from_**********************")
    print("^^^^^^^^^^^^^^^^region^^^^^^^^^^^^^^^^^^^^^^")
    print(region)
    print("^^^^^^^^^^^^^^^^region^^^^^^^^^^^^^^^^^^^^^^")
    print("%%%%%%%%%%%%%%%%%area%%%%%%%%%%%%%%%%%%%%%")
    print(area)
    print("%%%%%%%%%%%%%%%%%area%%%%%%%%%%%%%%%%%%%%%")
    for strategy in config["strategy"].values():
        strategy.set_config(config)

    falsify(config,region,area,sets,from_)

    for strategy in config["strategy"].values():
        strategy.shutdown()



atheris.Setup(sys.argv, TestOneInput, custom_mutator=my_mutator)
atheris.Fuzz()


