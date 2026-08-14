import array
import sys

from typing import Mapping, Container

def deep_getsizeof(obj):
    """Find the memory footprint of a Python object.

    Based on code from code.tutsplus.com: http://goo.gl/fZ0DXK

    This is a recursive function that drills down a Python object graph
    like a dictionary holding nested dictionaries with lists of lists
    and tuples and sets.

    The sys.getsizeof function does a shallow size of only. It counts each
    object inside a container as pointer only regardless of how big it
    really is.
    """

    ids = set()

    def size(o):
        if id(o) in ids:
            return 0

        r = sys.getsizeof(o)
        ids.add(id(o))

        if isinstance(o, (str, bytes, bytearray, array.array)):
            return r

        if isinstance(o, Mapping):
            return r + sum(size(k) + size(v) for k, v in o.items())

        if isinstance(o, Container):
            return r + sum(size(x) for x in o)

        return r

    return size(obj)

def main():
    key_bytes = 1 + 4 + 4 + 4 + 4 + 5
    value_bytes = 1

    max_ratio = None

    x = dict()
    for i in range(1000):
        x[i.to_bytes(key_bytes, 'big')] = b'0' * value_bytes
    ratio = deep_getsizeof(x) / 1000
    if max_ratio is None or max_ratio < ratio:
        max_ratio = ratio

    print(max_ratio * 1.3)

if __name__ == '__main__':
    main()