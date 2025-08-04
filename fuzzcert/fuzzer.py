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

def falsify_predicate(pre_size: dict, post_size: dict) -> bool:
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

    # total change should be 1 -> we pulled out a region then place it back after falsify
    # unknown or some unsafe can grow by 1 but not both at the same time
    if total_delta == 1 and delta_someunsafe in [0,1] and delta_unk in [0,1] and delta_someunsafe != delta_unk:
        return True
    else:
        return False

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

        pre_set = {
            "UNKNOWN": sets[UNKNOWN].set.size(),
            "SAFE": sets[ALL_SAFE].set.size(),
            "UNSAFE": sets[ALL_UNSAFE].set.size(),
            "SOME_UNSAFE": sets[SOME_UNSAFE].queue.qsize()
        }

        for strategy in config["strategy"].values():
            strategy.set_config(config)

        for partition in partitions:
            falsify(config,partition,sets['reporter'].get_area(partition),sets,from_=from_)

            post_set = {
                "UNKNOWN": sets[UNKNOWN].set.size(),
                "SAFE": sets[ALL_SAFE].set.size(),
                "UNSAFE": sets[ALL_UNSAFE].set.size(),
                "SOME_UNSAFE": sets[SOME_UNSAFE].queue.qsize()
            }
            if falsify_predicate(pre_set, post_set):
                print("success")
            else:
                print("failure")

        for strategy in config["strategy"].values():
            strategy.shutdown()

    except Exception:
        pass

    if counter > 20:
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
