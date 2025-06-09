import atheris
import sys
import os
import random
with atheris.instrument_imports():
    import hello

def TestOneInput(data):
    try:
        data=data.decode("utf-8",errors="ignore").splitlines()
        print(data[0])
        hello.greet(data[0])
    except Exception:
        print("************")
        pass  

def my_mutator(data: bytes, max_size: int, seed: int) -> bytes:
    random.seed(seed)

    if len(data) == 0:
        return b"initial"

    data = bytearray(data)

    # Example: flip a random byte
    idx = random.randint(0, len(data) - 1)
    data[idx] ^= 0xFF

    # Maybe insert a byte
    if len(data) < max_size and random.random() < 0.5:
        insert_idx = random.randint(0, len(data))
        data.insert(insert_idx, random.randint(0, 255))

    return bytes(data)


def main():
    atheris.Setup(sys.argv,TestOneInput, enable_python_coverage=True,custom_mutator=my_mutator)
    atheris.Fuzz()

if __name__ == "__main__":
    main()

