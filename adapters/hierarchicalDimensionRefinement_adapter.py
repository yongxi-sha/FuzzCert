import pickle
import random
import sys
import copy
import numpy as np
import atheris
from pathlib import Path
import coverage
from Falsify_Interface import *
from verapak.verification.ve import UNKNOWN, ALL_SAFE, ALL_UNSAFE, SOME_UNSAFE
from fuzzcert.bench_adapter import FunctionAdapter
from config import Config
from verapak.parse_args.tools import parse_args
from verapak.abstraction.ae import AbstractionEngine
from algorithm import main, verify

class InvalidStateTransitionError(Exception):
    """Raised when validate_state_transition() returns False."""
    pass

class FalsifyAdapter(FunctionAdapter):

    def __init__(self, config, function_name, benchmark_name="verapak"):
        super().__init__(config, function_name=function_name)
        self.function_name = function_name
        self.OUT = Path(f"experiments/{self.function_name}-results")
        self.OUT.mkdir(parents=True, exist_ok=True)
        self.cov=coverage.Coverage()
        self.cov.start()


    def initialize(self, input_dir=None):
        """
        Initialize model configuration, region, and area info.
        """
        # Atheris import instrumentation
        with atheris.instrument_imports():
            from algorithm import falsify as _falsify
        self._falsify=_falsify
        self.counter=1

        # Load VERAPAK config

        fuzz_args = load_config_from_corpus(input_dir)
        config, region, sets = get_fal_paras(fuzz_args)
        self.config = config
        self.region = region
        self.sets = sets
        self.from_ = UNKNOWN
        self.pre_set = {
            "UNKNOWN": len(sets[UNKNOWN]),
            "SAFE": len(sets[ALL_SAFE]),
            "UNSAFE": len(sets[ALL_UNSAFE]),
            "SOME_UNSAFE": len(sets[SOME_UNSAFE]),
        }

        # initialize multi-inputs num_dims and divisor
        initial_input = {
            "region": copy.deepcopy(self.region),
            "num_dims": self.region.low.shape[0],
            "divisor": 2,
        }

        # Create a dedicated corpus directory for Atheris.
        self.atheris_corpus_dir = self.OUT / "atheris_region_corpus"
        self.atheris_corpus_dir.mkdir(parents=True, exist_ok=True)

        # Write the initial serialized region seed.
        seed_path = self.atheris_corpus_dir / "seed_input.pkl"
        with seed_path.open("wb") as f:
            pickle.dump(initial_input, f)

        # File used to store the decoded region that triggers an invalid transition.
        self.failure_region_path = self.OUT / "invalid_transition_decoded_region.pkl"

    def get_atheris_corpus_dir(self):
        """Return the normalized corpus directory used by Atheris."""
        return str(self.atheris_corpus_dir)

    def save_failing_decoded_region(self, decoded_region):
        """Save the decoded failing region object to a fixed file."""
        self.failure_region_path.parent.mkdir(parents=True, exist_ok=True)
        with self.failure_region_path.open("wb") as f:
            pickle.dump(decoded_region, f)

    def my_mutator(self, data, max_size, seed):
        try:
            fuzz_input = FalsifyAdapter.deserialize(data)
        except Exception:
            fuzz_input = {
                "region": copy.deepcopy(self.region),
                "num_dims": self.region.low.shape[0],
                "divisor": 2,
            }

        mutated = copy.deepcopy(fuzz_input)

        # ---- mutate region ----
        region = mutated["region"]
        high = region.high
        low = region.low

        random_mod = np.random.uniform(0, 1, size=high.shape)
        sign = np.random.choice([-1, 1], size=high.shape)
        delta = sign * random_mod

        new_high = high + delta
        new_low = low + delta

        region.low = np.minimum(new_low, new_high)
        region.high = np.maximum(new_low, new_high)

        # ---- mutate num_dims ----
        # between 0 and the total number of dimensions of the input region.
        total_dims = region.low.shape[0]
        if random.random() < 0.3:
            mutated["num_dims"] = random.randint(0, total_dims) 

        # ---- mutate divisor ----
        # non-negative nonzero integer
        if random.random() < 0.3:
            mutated["divisor"] = random.randint(1, 16)  

        encoded = FalsifyAdapter.serialize(mutated)
        if len(encoded) <= max_size:
            return encoded
        return encoded[:max_size]

    @staticmethod
    def serialize(data) -> bytes:
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
    def deserialize(data):
        """
        Deserialize bytes into a region and area.

        Args:
            data (bytes): Serialized region/area data.
            input_dtype (type): Expected dtype (e.g., np.float32).

        Returns:
            Tuple: (region, area), where region = (low, high, ()), area is float.
        """
        return pickle.loads(data)

    @staticmethod
    def strip_fuzzcert_args(argv):
        """Remove fuzzcert-specific args that Atheris doesn't understand"""
        cleaned = []
        skip_next = False
        for i, arg in enumerate(argv):
            if skip_next:
                skip_next = False
                continue
            if arg in ("--bench", "--input", "--config", "--function"):
                skip_next = True  # Skip next argument (e.g., value after --bench)
                continue
            if arg.startswith("--bench=") or arg.startswith("--input=") or arg.startswith("--config=") or arg.startswith("--function="):
                continue
            cleaned.append(arg)

        return cleaned

    @staticmethod
    def validate_state_transition(pre_size: dict, post_size: dict) -> bool:
        """
        check if the transition is valid for hierarchicaldimensionrefinement
        return True if the transition is valid, False otherwise
        """


    def testoneinput(self, data):
        try:
            decoded = pickle.loads(data)
        except (EOFError, pickle.UnpicklingError, ValueError, TypeError, AttributeError):
            return

        try:
            region = decoded["region"]
            num_dims = decoded["num_dims"]
            divisor = decoded["divisor"]

            total_dims = region.low.shape[0]
            if not (0 <= num_dims <= total_dims):
                return
            if not (isinstance(divisor, int) and divisor > 0):
                return

            original_region = copy.deepcopy(region)

            result = hierarchicalDimensionRefinement(
                region,
                num_dims,
                divisor,
            )

            # roperty / invariant check
            ...

        except Exception:
            pass
