# hello.py

def greet(name: str) -> str:
    print(name)
    if name == "fuzzer":
        raise ValueError("Crash triggered!")
    return f"Hello, {name}!"

