import atheris
import sys
import os
import random
import coverage

cov=coverage.Coverage()
cov.start()

with atheris.instrument_imports():
    import hello

counter=0

def TestOneInput(data):
    global counter
    counter += 1
    try:
        data=data.decode("utf-8",errors="ignore")
        hello.greet(data)
    except Exception:
        pass  
    if counter > 50:
        cov.stop()
        cov.save()
        cov.report()
        cov.html_report()
        sys.exit(0)

def my_mutator(data: bytes, max_size: int, seed: int) -> bytes:
    random.seed(seed)
    try:
        s=data.decode("utf-8",errors="ignore")
        if len(s)<5:
            s=s+'abc'
        else:
            s=s+'def'
        return s.encode("utf-8")[:max_size]
    except Exception:
        return b'default'


def main():
    atheris.Setup(sys.argv,TestOneInput, enable_python_coverage=True,custom_mutator=my_mutator)
    atheris.Fuzz()

if __name__ == "__main__":
    main()

