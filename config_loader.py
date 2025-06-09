import os
import time
from VERAPAK.config import Config
from VERAPAK.verapak.parse_args.tools import parse_args
from VERAPAK.verapak.utilities.sets import make_sets, Reporter

def load_config_from_corpus(corpus_dir="corpus"):
    for filename in os.listdir(corpus_dir):
        path = os.path.join(corpus_dir, filename)
        fuzz_args = [
            f"--config_file={path}",
            "--output_dir=/src/out",
            "--halt_on_first=loose",
        ]
        break  # only load one for now

    config_dict = parse_args(fuzz_args, prog="fuzz_target.py")
    config = Config(config_dict)
    reporter = Reporter()
    start_time = time.time()
    reporter.setup(config, start_time)
    sets = make_sets(reporter)
    return config, reporter, sets
