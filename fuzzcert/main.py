import argparse
from fuzzer import start_fuzzing
from adapters.adapters import ADAPTERS

def parse_args():
    parser = argparse.ArgumentParser(description="FuzzCert: A Lightweight Function-level Fuzzer")

    parser.add_argument("--bench", required=True, choices=ADAPTERS.keys(),
                        help="Benchmark to fuzz (e.g., verapak)")
    parser.add_argument("--function", required=True,
                        help="Function to fuzz (e.g., falsify)")
    parser.add_argument("--input", required=True,
                        help="Path to input directory or corpus directory (function-specific)")
    parser.add_argument("-max_len",required=True,
                        help="Maximum input length of custom_mutator")
    return parser.parse_args()


def main():
    args = parse_args()
    print(args)
    AdapterClass = ADAPTERS[args.bench]
    adapter = AdapterClass(config=args, function_name=args.function)
    start_fuzzing(adapter, args.input)


if __name__ == "__main__":
    main()
