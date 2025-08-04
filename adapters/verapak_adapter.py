import pickle
import random
import numpy as np
import atheris
from fuzzcert.bench_adapter import BenchAdapter
import config_loader
from falsify_interface2 import *


class VerapakAdapter(BenchAdapter):
    def __init__(self, config):
        super().__init__(config)
        self.config_obj = None
        self.partitions = None
        self.from_ = None
        self.input_dtype = None
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

        self.from_ = UNKNOWN

        # Load VERAPAK config
        fuzz_args = config_loader.load_config_from_corpus(input_dir)
        params=get_fal_paras(fuzz_args)
        config, partitions, sets=params
        self.config_obj=config
        self.partitions=partitions
        self.sets=sets
        self.input_dtype = self.config_obj['graph'].input_dtype


    def mutate(self, data, max_size, seed):
        
        random.seed(seed)
        partitions=self.partitions
        new_partitions=[]
        for partiton in partitions:
            high=partiton[0]
            low=partiton[1]
            ceil = 1
            floor = 0

            # creates a random float between floor and ceil for each region position
            random_mod = np.random.uniform(floor, ceil, size=high.shape)

            # randomize sign for each region position (either add or subtract random_mod)
            sign = np.random.choice([-1, 1], size=high.shape)

            new_high = high + (sign * random_mod)
            new_low = low + (sign * random_mod)

            mutated_region = [new_high, new_low, partiton[2:]]
            new_partitions.append(mutated_region)

        encoded_partitions=pickle.dumps(new_partitions)
        print(len(encoded_partitions))

        if len(encoded_partitions) <= max_size:
            return encoded_partitions[:max_size]
        else:
            raise NotImplementedError("returned data exceed max_len")

    def serialize(self, data, input_dtype) -> bytes:
        """
        Serialize a region and area into bytes (for corpus writing).
        
        Args:
            data: A tuple of (region, area), where region is (low, high, ()) and area is float.
            input_dtype: Data type of the region tensors (e.g., np.float32).
        
        Returns:
            bytes: Pickled representation of region+area.
        """
        region, area = data
        low, high, _ = region
        low_list = np.array(low, dtype=input_dtype).tolist()
        high_list = np.array(high, dtype=input_dtype).tolist()
        return pickle.dumps(((low_list, high_list), area))

    def deserialize(self, data, input_dtype):
        """
        Deserialize bytes into a region and area.
        
        Args:
            data (bytes): Serialized region/area data.
            input_dtype (type): Expected dtype (e.g., np.float32).
        
        Returns:
            Tuple: (region, area), where region = (low, high, ()), area is float.
        """
        try:
            region_data, area = pickle.loads(data)
            low, high = region_data
            low = np.array(low, dtype=input_dtype)
            high = np.array(high, dtype=input_dtype)
            return (low, high, ()), area
        except Exception as e:
            raise ValueError(f"Failed to deserialize input: {e}")
