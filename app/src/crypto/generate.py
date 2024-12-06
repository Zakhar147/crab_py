import random
import hashlib

def generate_permutation():
    P = list(range(256))
    random.shuffle(P)
    return P

def generate_s_array(key: bytes, size: int = 256):
    S = []
    hashed_data = key
    while len(S) < size:
        hashed_data = hashlib.md5(hashed_data).digest()
        S.extend([int.from_bytes(hashed_data[i:i+4], 'little') for i in range(0, len(hashed_data), 4)])
    return S[:size]

def generate_key(): 
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890', k=16))