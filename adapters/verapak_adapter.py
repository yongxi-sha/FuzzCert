import os
import pickle
import numpy as np
import atheris
from VERAPAK.config import Config
from VERAPAK.verapak.parse_args.tools import parse_args
from VERAPAK.verapak.utilities.sets import make_sets, Reporter
from fuzzcert.bench_adapter import BenchAdapter
import config_loader


class VerapakAdapter(BenchAdapter):
    def __init__(self, config):
        super().__init__(config)
        self.region = None
        self.area = None
        self.from_ = None
        self.input_dtype = None
        self.config_obj = None
        self.reporter = None
        self.sets = None

    def initialize(self, input_dir=None):
        """
        Initialize model configuration, region, and area info.
        """
        # Atheris import instrumentation
        with atheris.instrument_imports():
            from VERAPAK.verapak.verification.ve import UNKNOWN
            from VERAPAK.algorithm import falsify

        self.from_ = UNKNOWN

        # Load VERAPAK config
        self.config_obj, self.reporter, self.sets = config_loader.load_config_from_corpus()
        self.region = self.config_obj["initial_region"]
        self.area = self.reporter.get_area(self.region)
        self.input_dtype = self.config_obj['graph'].input_dtype

    def mutate(self, base_input: np.ndarray) -> np.ndarray:
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
