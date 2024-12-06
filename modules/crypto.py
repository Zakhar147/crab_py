# crypto.py
import random
import hashlib

def rotate_left(value: int, shift: int, size: int = 32):
    return ((value << shift) | (value >> (size - shift))) & ((1 << size) - 1)

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

def encrypt_block_simple(block: bytes, P: list, S: list):
    X = [int.from_bytes(block[i:i+4], 'little') for i in range(0, len(block), 4)]
    for i in range(len(X)):
        X[i] = rotate_left(X[i] ^ S[i % len(S)], 5)
    X = [X[P[i]] for i in range(len(P))]
    return b''.join(x.to_bytes(4, 'little') for x in X)

def decrypt_block_simple(encrypted_block: bytes, P: list, S: list):
    X = [int.from_bytes(encrypted_block[i:i+4], 'little') for i in range(0, len(encrypted_block), 4)]
    P_inv = [0] * len(P)
    for i, p in enumerate(P):
        P_inv[p] = i
    X = [X[P_inv[i]] for i in range(len(P))]
    for i in range(len(X)):
        X[i] = rotate_left(X[i], 27) ^ S[i % len(S)]
    return b''.join(x.to_bytes(4, 'little') for x in X)