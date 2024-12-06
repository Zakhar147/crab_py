from utils import rotate_left

def decrypt_block_simple(encrypted_block: bytes, P: list, S: list):
    X = [int.from_bytes(encrypted_block[i:i+4], 'little') for i in range(0, len(encrypted_block), 4)]
    P_inv = [0] * len(P)
    for i, p in enumerate(P):
        P_inv[p] = i
    X = [X[P_inv[i]] for i in range(len(P))]
    for i in range(len(X)):
        X[i] = rotate_left(X[i], 27) ^ S[i % len(S)]
    return b''.join(x.to_bytes(4, 'little') for x in X)