import sys
import atheris
import pickle

g_benchAdapter = None
counter=0

def strip_fuzzcert_args(argv):
    """Remove fuzzcert-specific args that Atheris doesn't understand"""
    cleaned = []
    skip_next = False
    for i, arg in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if arg in ("--bench", "--input", "--config"):
            skip_next = True  # Skip next argument (e.g., value after --bench)
            continue
        if arg.startswith("--bench=") or arg.startswith("--input=") or arg.startswith("--config="):
            continue
        cleaned.append(arg)
    return cleaned



def TestOneInput(data: bytes) -> None:
    """
    Atheris fuzzing entry point. Deserializes and runs verifier on input.
    """

    global counter
    counter+=1

    try:

        # deserialize
        partitions=pickle.loads(data)

        config=g_benchAdapter.config_obj

        from_=g_benchAdapter.from_

        sets=g_benchAdapter.sets

        for strategy in config["strategy"].values():
            strategy.set_config(config)

        for partition in partitions:
            falsify(config,partition,sets['reporter'].get_area(partition),sets,from_=from_)

        for strategy in config["strategy"].values():
            strategy.shutdown()

    except Exception:
        pass

    if counter > 10:
        sys.exit(0)



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
    cleaned_argv=strip_fuzzcert_args(sys.argv)
    print(cleaned_argv)
    # Use adapter’s own custom_mutator
    atheris.Setup(
        cleaned_argv,
        TestOneInput,
        custom_mutator=benchAdapter.mutate,
        enable_python_coverage=True,
    )
    atheris.Fuzz()
