import argparse
from adapters.verapak_adapter import VerapakAdapter
from fuzzcert.fuzz_main import start_fuzzing

# Registry of supported benchmarks and their adapter classes
ADAPTERS = {
    "verapak": VerapakAdapter,
}

def parse_args():
    parser = argparse.ArgumentParser(description="FuzzCert: A Lightweight Neural Verifier Fuzzer")

    parser.add_argument("--bench", required=True, choices=ADAPTERS.keys(),
                        help="Benchmark to fuzz (e.g., verapak)")
    parser.add_argument("--input", required=True,
                        help="Path to input directory or corpus root (adapter-specific)")

    return parser.parse_args()


def main():
    args = parse_args()

    AdapterClass = ADAPTERS[args.bench]
    adapter = AdapterClass(args)

    start_fuzzing(adapter, args.input)


if __name__ == "__main__":
    main()
