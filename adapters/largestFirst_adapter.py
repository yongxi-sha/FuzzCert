import pickle
import random
import sys
import numpy as np
import atheris
import coverage
from pathlib import Path
from Falsify_Interface import *
from verapak.verification.ve import UNKNOWN, ALL_SAFE, ALL_UNSAFE, SOME_UNSAFE
from fuzzcert.bench_adapter import FunctionAdapter
from config import Config
from verapak.parse_args.tools import parse_args
from verapak.abstraction.ae import AbstractionEngine
from algorithm import main, verify
from math import isclose

from itertools import combinations

import traceback
import json
import time
import copy

class InvalidStateTransitionError(Exception):
    """Raised when validate_state_transition() returns False."""
    pass

class PartitioningAdapter(FunctionAdapter):

    def __init__(self, config, function_name, benchmark_name="verapak"):
        super().__init__(config, function_name=function_name)
        self.function_name = function_name
        self.OUT = Path(f"experiments/{self.function_name}-results")
        self.OUT.mkdir(parents=True, exist_ok=True)
        self.cov = coverage.Coverage()
        self.cov.start()

    def initialize(self, input_dir=None):
        """
        Initialize model configuration, region, and area info.
        """
        with atheris.instrument_imports():
            from verapak.partitioning.tools import hierarchicalDimensionRefinement as _hierarchicalDimensionRefinement
            from verapak.dimension_ranking.largest_first import LargestFirstDimSelection as _LargestFirstDimSelection
        self._hierarchicalDimensionRefinement = _hierarchicalDimensionRefinement
        self._LargestFirstDimSelection = _LargestFirstDimSelection()
        self.counter = 1

        self.fail_pool = []
        self.max_pool = 512

        # Load VERAPAK config

        fuzz_args = load_config_from_corpus(input_dir)
        config, region, sets = get_fal_paras(fuzz_args)
        self.config = config
        self.region = region
        self.sets = sets
        self.num_dims = 3
        self.divisor = 2

        # self.from_ = UNKNOWN
        # self.pre_set = {
        #     "UNKNOWN": len(sets[UNKNOWN]),
        #     "SAFE": len(sets[ALL_SAFE]),
        #     "UNSAFE": len(sets[ALL_UNSAFE]),
        #     "SOME_UNSAFE": len(sets[SOME_UNSAFE]),
        # }

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


        # Return to previous iteration without copy
        # do operations on the seed
        # use starting regions - do operations based on seed
        try:
            base_region = FalsifyAdapter.deserialize(data)
        except Exception:
            base_region = copy.deepcopy(self.region)

        rnd = random.Random(seed)

        seed_region = copy.deepcopy(base_region)
        new_low = seed_region.low.copy()
        new_high = seed_region.high.copy()

        # both high and low should have same shape
        if new_low.shape != new_high.shape:
            raise Exception("Low and High in Region do not match, invalid region")
        else:
            shape = new_low.shape
            num_elements = new_low.size

        flat_index = random.randrange(num_elements)
        idx_to_mutate = np.unravel_index(flat_index, shape)

        current_low = new_low[idx_to_mutate]
        current_high = new_high[idx_to_mutate]
        current_width = current_high - current_low

        strategy = random.choice(["jiggle_low", "jiggle_high", "slide", "shrink", "expand"])
        mutation_scale = 5.0

        if strategy == "jiggle_low":
            delta = rnd.uniform(-mutation_scale, mutation_scale)
            new_val = current_low + delta
            new_low[idx_to_mutate] = new_val

        elif strategy == "jiggle_high":
            delta = random.uniform(-mutation_scale, mutation_scale)
            new_val = current_high + delta
            new_high[idx_to_mutate] = new_val

        elif strategy == "slide":
            delta = random.uniform(-mutation_scale, mutation_scale)
            new_l = current_low + delta
            new_h = new_l + current_width  # Preserve width
            new_low[idx_to_mutate] = new_l
            new_high[idx_to_mutate] = new_h

        elif strategy == "shrink":
            if current_width > 1e-6:  # Avoid shrinking zero-width regions
                shrink_low = random.uniform(0, current_width / 2)
                shrink_high = random.uniform(0, current_width / 2)
                new_low[idx_to_mutate] = current_low + shrink_low
                new_high[idx_to_mutate] = current_high - shrink_high

        elif strategy == "expand":
            expand_low = random.uniform(0, mutation_scale)
            expand_high = random.uniform(0, mutation_scale)
            new_l = current_low - expand_low
            new_h = current_high + expand_high

            new_low[idx_to_mutate] = new_l
            new_high[idx_to_mutate] = new_h

        # enforce low < high on all dim
        final_low = np.minimum(new_low, new_high)
        final_high = np.maximum(new_low, new_high)

        seed_region.low = final_low
        seed_region.high = final_high
        encoded_region = PartitioningAdapter.serialize(seed_region)

        #print(seed_region.low)
        #print(seed_region.high)
        if len(encoded_region) <= max_size:
            return encoded_region[:max_size]
        else:
            raise NotImplementedError(f"returned encoded_region exceed max_len: {max_size}")

    @staticmethod
    def serialize(data) -> bytes:
        """
        Serialize a region and area into bytes (for corpus writing).
        """
        return pickle.dumps(data)

    @staticmethod
    def deserialize(data):
        """
        Deserialize bytes into a region and area.
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
            if arg.startswith("--bench=") or arg.startswith("--input=") or arg.startswith(
                    "--config=") or arg.startswith("--function="):
                continue
            cleaned.append(arg)

        return cleaned


    def validate_state_transition(self, input_region, partitions, num_dims, divisor):
        #print(f"power of divisor {divisor} and num_dims {num_dims} is {divisor ** num_dims}")
        #print(f"len of partitions {len(partitions)}")

        RTOL = 1e-5
        ATOL = 1e-15

        results = {
            "return_count" : True,
            "is_contained" : True,
            "is_disjoint" : True,
            "volume_conserved" : True
            }
        stats = {
            "total_children" : len(partitions),
            "parent_vol" : float(self.sets["reporter"].get_area(input_region)),
            "child_vol:" : float(sum(self.sets["reporter"].get_area(r) for r in partitions))
            }

        # -- Count Check --
        if not (len(partitions) == (divisor ** num_dims)):
                results["return_count"] = False

        # -- is_contained check --
        for child in partitions:
            # childs lower bound must be >= parents lower
            # childs upper bound must be <= parents upper

            low_check = (child.low > input_region.low) | np.isclose(child.low, input_region.low, rtol=RTOL, atol=ATOL)
            contained_low = np.all(low_check)
            high_check = (child.high < input_region.high) | np.isclose(child.high, input_region.high, rtol=RTOL, atol=ATOL)
            contained_high = np.all(high_check)

            if not (contained_low and contained_high):
                results["is_contained"] = False

        # -- is_disjoint check --
        for p1, p2 in combinations(partitions, 2):
            inter_low = np.maximum(p1.low, p2.low)
            inter_high = np.minimum(p1.high, p2.high)

            is_less = inter_low < inter_high

            is_not_touching = ~np.isclose(inter_low, inter_high, rtol=RTOL, atol=ATOL)

            if np.all(is_less & is_not_touching):
                results["is_disjoint"] = False

        total_partition_area = 0
        for r in partitions:
            total_partition_area += self.sets["reporter"].get_area(r)

        if not (isclose(total_partition_area, self.sets["reporter"].get_area(input_region), rel_tol=RTOL, abs_tol=ATOL)):
            results["volume_conserved"] = False

        return results, stats

    def testoneinput(self, region):
        try:
            decoded_region = pickle.loads(region)
        except (EOFError, pickle.UnpicklingError, ValueError, TypeError, AttributeError):
            # Ignore malformed serialized inputs.
            return
            # Keep an immutable copy of the decoded input before _falsify mutates it.
        try:
            original_decoded_region = copy.deepcopy(decoded_region)
            #print(f"region: {decoded_region.low}, {decoded_region.high}")
            partitions = self._hierarchicalDimensionRefinement(
                decoded_region,
                self._LargestFirstDimSelection.rank,
                self.num_dims,
                self.divisor,
            )
            checks, stats = self.validate_state_transition(decoded_region, partitions, self.num_dims, self.divisor)

            if not all(checks.values()):
                # ensure all checks pass

                # extract only failed checks
                failures = {k: v for k, v in checks.items() if not v}

                crash_report = {
                    "error": "partition_verification_failure",
                    "failed_checks": list(failures.keys()),
                    "stats": stats,
                    "parent_bounds": {
                        "low": decoded_region.low.tolist(),
                        "high": decoded_region.high.tolist()
                    },
                    "child_bounds":[
                        {"low": c.low.tolist(), "high": c.high.tolist()} for c in partitions]
                }

                self.save_crash_report(crash_report)
                self.save_failing_decoded_region(original_decoded_region)
                raise InvalidStateTransitionError(
                    f"Invalid transition detected"
                )
                print("Failure")
            else:
                print("Success")
            self.counter += 1


        except Exception:
            pass

        if self.counter > 1000:
            self.cov.stop()
            self.cov.save()
            with (self.OUT / "coverage.txt").open("w") as f:
                self.cov.report(file=f, show_missing=True)
            self.cov.html_report(directory=str(self.OUT / "html"))
            sys.exit(0)

    def save_crash_report(self, report):
        crash_dir = self.OUT / "crash_reports"

        crash_dir.mkdir(parents=True, exist_ok=True)
        filename = f"crash_partition_{int(time.time_ns())}.json"
        full_path = crash_dir / filename

        with open(full_path, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"Validation failed: {report['failed_checks']}. Report saved to {filename}")