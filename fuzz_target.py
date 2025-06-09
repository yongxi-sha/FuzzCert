import sys
import atheris
import numpy as np
import config_loader
import region_utils
import mutator

with atheris.instrument_imports():
    from verapak.verification.ve import UNKNOWN
    from algorithm import falsify


# Load config/sets only once at startup
config, reporter, sets = config_loader.load_config_from_corpus()
region = config["initial_region"]
area = reporter.get_area(region)
from_ = UNKNOWN
input_dtype = config['graph'].input_dtype

def TestOneInput(data):
    try:
        region_mutated, area_mutated = region_utils.deserialize_input(data, input_dtype)

        for strategy in config["strategy"].values():
            strategy.set_config(config)

        falsify(config, region_mutated, area_mutated, sets, from_)

        for strategy in config["strategy"].values():
            strategy.shutdown()
    except Exception:
        pass

atheris.Setup(sys.argv, TestOneInput, custom_mutator=mutator.my_mutator)
atheris.Fuzz()
