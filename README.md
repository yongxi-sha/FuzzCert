# FuzzCert

FuzzCert is a lightweight, function-level fuzzing framework for **certifiable robustness of neural networks**.  
It uses a two-layer adapter architecture:

- **Benchmark-level adapter (Bench)** — e.g., `VerapakAdapter`: registers/chooses function adapters and delegates lifecycle.
- **Function-level adapter (Function)** — e.g., `FalsifyAdapter`: owns the actual fuzz target (init, custom mutator, (de)serialization, invariants, evaluation).

The fuzzer integrates with **Atheris**.

```
FuzzCert/
├─ adapters/
│  ├─ adapters.py                # ADAPTERS registry: {"verapak": VerapakAdapter}
│  ├─ verapak_adapter.py         # Bench-level adapter (thin manager)
│  └─ falsify_adapter.py         # Function-level adapter for "falsify"
├─ fuzzcert/
│  ├─ main.py                    # CLI entry (console_script: fuzzcert)
│  ├─ fuzzer.py                  # Atheris integration (Setup/TestOneInput)
│  └─ bench_adapter.py           # Abstract base class of benchmark-level and function-level adapter
├─ experiments/
│  └─ VERAPAK/                   # Experiment code & corpus (your project-specific code)
├─ setup.py                      # Packaging config
└─ README.md


```

## Installation
```
pip install atheris
pip install .
```

## Quick start
Compile and copy the VERAPAK to ``experiments/VERAPAK``, then run:
```
fuzzcert --bench verapak --function falsify --input experiments/VERAPAK/corpus --max_len 60000
```
### Arguments
--bench — which benchmark to fuzz (provided by adapters/adapters.py via the ADAPTERS registry).

--function — which function-level adapter to use (registered inside verapak_adapter.py via register_fadapter()).

--input — corpus/config directory consumed by FalsifyAdapter.initialize().

--max_len — the maximum size for inputs produced by the custom mutator (Atheris will enforce this).

## How it works
### (1) Registry & delegation
```
from adapters.verapak_adapter import VerapakAdapter
ADAPTERS = {"verapak": VerapakAdapter}
```
adapters/verapak_adapter.py (Bench layer, thin)

Registers function-level adapters with delayed import (to avoid circular imports):
```
def register_fadapter(self):
    
    from falsify_adapter import FalsifyAdapter
    self.add_fadapter("falsify",FalsifyAdapter)
```
Delegates initialize, my_mutator, testoneinput to self.function_adapter.

Optionally mirrors shared state (e.g., config/region/sets/from_/pre_set) for convenience.

adapters/falsify_adapter.py (Function layer, owns logic)

initialize(input_dir) — loads VERAPAK config, sets up region/sets/pre_set.

my_mutator(data, max_size, seed) — creates a mutated object and serializes it to bytes for Atheris.

serialize/deserialize(bytes) — the wire protocol for fuzzing (make these @staticmethod and robust to empty/invalid inputs).

strip_fuzzcert_args(argv) — removes CLI flags unknown to Atheris.

validate_state_transition(pre, post) — (formerly falsify_predicate) checks post-state of sets.

testoneinput(obj) — evaluates one input (object), updates sets, checks invariants.

### (2) Fuzzer (Atheris)
fuzzcert/fuzzer.py

start_fuzzing(adapter, corpus_dir):

adapter.initialize(corpus_dir)

argv = adapter.strip_fuzzcert_args(sys.argv)

atheris.Setup(argv, TestOneInput, custom_mutator=adapter.my_mutator, enable_python_coverage=True)

atheris.Fuzz()

TestOneInput(data: bytes):

Current path: region = g_benchAdapter.deserialize(data) → g_benchAdapter.testoneinput(region)


## Coverage output to a specific directory
The default output file is ``experiments/function_name-results``
You can also modify the output path in ``adapters/falsify_adapter.py``:
```
from pathlib import Path
import coverage

OUT = Path("/path/to/save/coverage")
OUT.mkdir(parents=True, exist_ok=True)

cov = coverage.Coverage(data_file=str(OUT / ".coverage"))
cov.start()

# ... fuzzing ...

cov.stop()
cov.save()  # writes OUT/.coverage

# Text report
with (OUT / "coverage.txt").open("w") as f:
    cov.report(file=f, show_missing=True)

# HTML report
cov.html_report(directory=str(OUT / "html"))
```

## A practical guide to writing a new function-level adapter
This guide explains how to add a new function-level adapter (the component that implements the actual fuzz target logic) and wire it into the existing bench-level manager (e.g., VerapakAdapter). It assumes your repo already builds/installs and the fuzzcert CLI works.

### (1) Create a function-level adapter
Create ``adapters/<yourfunc>_adapter.py`` and implement a class that inherits FunctionAdapter (or BenchAdapter if you kept a single abstract base):

The template is ``adapters/falsify_adapter.py``:
```

class FalsifyAdapter(FunctionAdapter):

    def __init__(self, config, function_name, benchmark_name="verapak"):
  

    def initialize(self, input_dir=None):
        """
        Initialize model configuration, region, and area info.
        """



    def my_mutator(self, data, max_size, seed):
        
        # funtion-level mutator

    
    @staticmethod
    def serialize(data) -> bytes:
        """
        Serialize a region and area into bytes (for corpus writing).

        return pickle.dumps(data)
    
    @staticmethod
    def deserialize(data):
        """
        Deserialize bytes into a region and area.

        return pickle.loads(data)
    
    @staticmethod
    def strip_fuzzcert_args(argv):

    @staticmethod
    def falsify_predicate(pre_size: dict, post_size: dict) -> bool:

     
    def testoneinput(self, region):
```
Please **DO NOT** change the method signatures defined in the template. 

You need to customize the ``initialization``, ``custom_mutator`` and ``testoneinput``. If you do not need to use ``falsify_predicate`` when fuzzing other functions, use ``pass`` to skip this method. 

### (2) Register the adapter in the bench manager

Open the bench manager (``adapters/verapak_adapter.py``) and add your mapping inside its delayed registration method:

```
def register_fadapter(self):
    
    from falsify_adapter import FalsifyAdapter
    self.add_fadapter("falsify",FalsifyAdapter)
```
Keep it a local import inside the method to prevent circular imports with other modules.

If you’re introducing a new benchmark manager, add it to ``adapters/adapters.py``:
```
from adapters.verapak_adapter import VerapakAdapter
# from adapters.mybench_adapter import MyBenchAdapter

ADAPTERS = {
  "verapak": VerapakAdapter,
  # "mybench": MyBenchAdapter,
}
```
### (3) Reinstall & Run

Reinstall and run:
```
pip install .
fuzzcert --bench verapak --function myfunc --input experiments/VERAPAK/corpus --max_len 60000
```
If the input generated by custom mutator is over the default **length (60000)**, you can modify the input paramter **--max_len** to adjust the maximum length.