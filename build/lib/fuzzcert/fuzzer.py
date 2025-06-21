import sys
import atheris

g_benchAdapter = None


def TestOneInput(data: bytes) -> None:
    """
    Atheris fuzzing entry point. Deserializes and runs verifier on input.
    """
    global g_benchAdapter
    adapter = g_benchAdapter

    try:
        # deserialize
        region, area = adapter.deserialize(data, adapter.input_dtype)
        
        # falsify(region, area, ....)

        # serialize
        data = adapter.serialize(data, adapter.input_dtype)

    except Exception:
        pass


def start_fuzzing(benchAdapter, corpus_dir: str) -> None:
    """
    Initializes benchmark adapter and starts fuzzing with Atheris.

    Args:
        benchAdapter: A subclass instance of BenchAdapter (e.g., VerapakAdapter).
        corpus_dir: Path to fuzzing corpus directory.
    """
    global g_benchAdapter

    benchAdapter.initialize(corpus_dir)
    g_benchAdapter = benchAdapter

    # Use adapter’s own custom_mutator
    atheris.Setup(
        sys.argv,
        TestOneInput,
        custom_mutator=benchAdapter.mutate,
        enable_python_coverage=True,
    )
    atheris.Fuzz()
