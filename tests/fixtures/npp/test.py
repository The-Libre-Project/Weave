#!/usr/bin/env python3
"""Sample Python file used by Weave's Notepad++ integration test."""

def greet(name: str) -> str:
    """Return a greeting string."""
    return f"Hello, {name}!"


def main():
    message = greet("Weave")
    print(message)


if __name__ == "__main__":
    main()
