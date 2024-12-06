from utils import rotate_left
from generate import generate_permutation, generate_s_array

def encrypt_block_simple(block: bytes, P: list, S: list):
    X = [int.from_bytes(block[i:i+4], 'little') for i in range(0, len(block), 4)]
    for i in range(len(X)):
        X[i] = rotate_left(X[i] ^ S[i % len(S)], 5)
    X = [X[P[i]] for i in range(len(P))]
    return b''.join(x.to_bytes(4, 'little') for x in X)

def encrypt_message(key, message):
    if not key or not message:
        raise ValueError("Please provide both key and message.")

    padded_message = message.encode('utf-8').ljust(1024, b'\0')
    P = generate_permutation()
    S = generate_s_array(key)

    #global encrypted_message, P_global, S_global

    return encrypt_block_simple(padded_message, P, S)
    # P_global, S_global = P, S
    # res_input.config(text=f"{encrypted_message.hex()[:64]}")