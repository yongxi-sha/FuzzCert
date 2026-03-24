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

        # Create a dedicated corpus directory for Atheris.
        self.atheris_corpus_dir = self.OUT / "atheris_region_corpus"
        self.atheris_corpus_dir.mkdir(parents=True, exist_ok=True)

        # Write the initial serialized region seed.
        seed_path = self.atheris_corpus_dir / "seed_region.pkl"
        with seed_path.open("wb") as f:
            pickle.dump(copy.deepcopy(self.region), f)

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
            base_region=FalsifyAdapter.deserialize(data)
        except Exception:
            base_region = copy.deepcopy(self.region)
            

        mutated_region = copy.deepcopy(base_region)

        high=mutated_region.high
        low=mutated_region.low

        ceil = 1
        floor = 0
        random_mod = np.random.uniform(floor, ceil, size=high.shape)
        sign = np.random.choice([-1, 1], size=high.shape)
        delta = sign * random_mod

        new_high = high + delta
        new_low = low + delta

        if new_high.shape != new_low.shape:
            print("Shape mismatch between new low and new high")
            sys.exit(0)

        # ensure the low is the low and high is the high - never get flipped/invalid regions
        low = np.minimum(new_low, new_high)
        high = np.maximum(new_low, new_high)

        # mutated_region.high = new_high
        # mutated_region.low = new_low
        mutated_region.low=low
        mutated_region.high=high

        encoded_region = FalsifyAdapter.serialize(mutated_region)

        if len(encoded_region) <= max_size:
            return encoded_region[:max_size]
        else:
            raise NotImplementedError(f"returned encoded_region exceed max_len: {max_size}")

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
        :param pre_size: The size of each set prior to falsify call
        :param post_size: The size of each set after call to falsify
        :return: bool: Checks correctness and returns True/False
        """
        total_pre = sum(value for value in pre_size.values())
        total_post = sum(value for value in post_size.values())

        delta_unk = post_size["UNKNOWN"] - pre_size["UNKNOWN"]
        delta_someunsafe = post_size["SOME_UNSAFE"] - pre_size["SOME_UNSAFE"]

        total_delta = total_post - total_pre
        print(f"total delta {total_delta}, total_pre {total_pre}, total_post {total_post}, delta_unk {delta_unk}, delta_someunsafe {delta_someunsafe}")
        # total change should be 1 -> we either increase unknown by 1 or some_unsafe by 1 - never both - but always 1
        if total_delta == 1 and ((delta_someunsafe == 1 and delta_unk == 0) or (delta_someunsafe == 0 and delta_unk == 1)):
            return True
        else:
            return False


    def testoneinput(self, region):
        pre_set = self.pre_set
        try:
            decoded_region=pickle.loads(region)
        except (EOFError, pickle.UnpicklingError, ValueError, TypeError, AttributeError):
            # Ignore malformed serialized inputs.
            return
            # Keep an immutable copy of the decoded input before _falsify mutates it.
        try:
            original_decoded_region = copy.deepcopy(decoded_region)
            self._falsify(
                self.config,
                decoded_region,
                self.sets["reporter"].get_area(self.region),
                self.sets,
                from_=self.from_,
            )

            post_set = {
                "UNKNOWN": len(self.sets[UNKNOWN]),
                "SAFE": len(self.sets[ALL_SAFE]),
                "UNSAFE": len(self.sets[ALL_UNSAFE]),
                "SOME_UNSAFE": len(self.sets[SOME_UNSAFE]),
            }
            self.pre_set = post_set

            if FalsifyAdapter.validate_state_transition(pre_set, post_set):
                print("success")
            else:
                self.save_failing_decoded_region(original_decoded_region)
                raise InvalidStateTransitionError(
                            f"Invalid transition detected: pre={pre_set}, post={post_set}"
                        )
                print("failure")

            self.counter += 1
        
        except Exception:
            pass

        if self.counter > 10000:
            self.cov.stop()
            self.cov.save()
            with (self.OUT / "coverage.txt").open("w") as f:
                self.cov.report(file=f, show_missing=True)
            self.cov.html_report(directory=str(self.OUT / "html"))
            sys.exit(0)
