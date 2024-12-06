def rotate_left(value: int, shift: int, size: int = 32):
    return ((value << shift) | (value >> (size - shift))) & ((1 << size) - 1)