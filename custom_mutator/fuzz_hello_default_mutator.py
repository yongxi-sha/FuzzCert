import atheris
import sys
import os
import random
with atheris.instrument_imports():
    import hello

def TestOneInput(data):
    try:
        data=data.decode("utf-8",errors="ignore").splitlines()
        hello.greet(data[0])
    except Exception:
        pass  

def main():
    atheris.Setup(sys.argv,TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()

