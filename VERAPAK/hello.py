# hello.py

def greet(name: str) -> str:
    if name == "fuzzer":
        raise ValueError("Crash triggered!")
    return f"Hello, {name}!"

