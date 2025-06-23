import os
import pickle
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
        """
        Placeholder for region mutation logic.
        Currently not implemented.
        """
        raise NotImplementedError("VerapakAdapter.mutate is not implemented yet.")

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
