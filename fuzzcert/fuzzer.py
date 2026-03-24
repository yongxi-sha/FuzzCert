import sys
import atheris

g_benchAdapter = None

def TestOneInput(data: bytes) -> None:
    """
    Atheris fuzzing entry point. Deserializes and runs verifier on input.
    """

    global g_benchAdapter
    g_benchAdapter.testoneinput(data)


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
    cleaned_argv=benchAdapter.strip_fuzzcert_args(sys.argv)
    atheris_corpus_dir = benchAdapter.get_atheris_corpus_dir()
    setup_argv = [cleaned_argv[0], atheris_corpus_dir] + cleaned_argv[1:]
    # Use adapter’s own custom_mutator
    atheris.Setup(
        setup_argv,
        TestOneInput,
        custom_mutator=benchAdapter.my_mutator,
        enable_python_coverage=True,
    )
    atheris.Fuzz()
