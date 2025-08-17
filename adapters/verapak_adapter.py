import pickle
import random
import numpy as np
import atheris
from fuzzcert.bench_adapter import BenchAdapter
import config_loader
from Falsify_Interface import *


class VerapakAdapter(BenchAdapter):
    def __init__(self, config):
        super().__init__(config)
        self.config = None
        self.region = None
        self.from_ = None
        self.sets = None

    def initialize(self, input_dir=None):
        """
        Initialize model configuration, region, and area info.
        """
        # Atheris import instrumentation
        with atheris.instrument_imports():
            from algorithm import falsify
            from config import Config
            from verapak.parse_args.tools import parse_args
            from verapak.verification.ve import UNKNOWN
            from verapak.abstraction.ae import AbstractionEngine
            from algorithm import main, verify

        # Load VERAPAK config
        fuzz_args = config_loader.load_config_from_corpus(input_dir)
        config, region, sets = get_fal_paras(fuzz_args)
        self.config = config
        self.region = region
        self.sets = sets
        self.from_ = UNKNOWN

    def my_mutator(data, max_size, seed):

        random.seed(seed)

        mutated_region = region
        high = region.high
        low = region.low
        ceil = 1
        floor = 0
        random_mod = np.random.uniform(floor, ceil, size=high.shape)
        sign = np.random.choice([-1, 1], size=high.shape)

        new_high = high + (sign * random_mod)
        new_low = low + (sign * random_mod)

        mutated_region.high = new_high
        mutated_region.low = new_low

        encoded_region = VerapakAdapter.serialize(mutated_region)

        if len(encoded_region) <= max_size:
            return encoded_region[:max_size]
        else:
            raise NotImplementedError(f"returned encoded_region exceed max_len: {max_size}")
    
    @staticmethod
    def serialize(self, data) -> bytes:
        """
        Serialize a region and area into bytes (for corpus writing).

        Args:
            data: A tuple of (region, area), where region is (low, high, ()) and area is float.
            input_dtype: Data type of the region tensors (e.g., np.float32).

        Returns:
            bytes: Pickled representation of region+area.
        """
        return pickle.dumps(data)
    
    @staticmethod
    def deserialize(self, data):
        """
        Deserialize bytes into a region and area.

        Args:
            data (bytes): Serialized region/area data.
            input_dtype (type): Expected dtype (e.g., np.float32).

        Returns:
            Tuple: (region, area), where region = (low, high, ()), area is float.
        """
        return pickle.loads(data)