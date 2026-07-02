#!/usr/bin/env python3
"""Write a random string of a given length to test.txt.

Usage: python3 gen_test.py <length> [outfile]
"""
import random
import string
import sys


def main():
    if len(sys.argv) < 2:
        print("usage: gen_test.py <length> [outfile]", file=sys.stderr)
        sys.exit(1)
    try:
        length = int(sys.argv[1])
        if length < 0:
            raise ValueError
    except ValueError:
        print("error: length must be a non-negative integer", file=sys.stderr)
        sys.exit(1)
    outfile = sys.argv[2] if len(sys.argv) > 2 else "test.txt"
    alphabet = string.ascii_letters + string.digits
    data = "".join(random.choice(alphabet) for _ in range(length))
    with open(outfile, "w") as f:
        f.write(data)
    print(f"wrote {length} bytes to {outfile}")


if __name__ == "__main__":
    main()
