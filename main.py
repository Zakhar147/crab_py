import tkinter as tk
from tkinter import messagebox
import random
import hashlib

# Utility functions for encryption and decryption
def rotate_left(value: int, shift: int, size: int = 32):
    """Performs a cyclic left shift."""
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

# GUI Application
def generate_key():
    generated_key = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890', k=16))
    key_entry.delete(0, tk.END)
    key_entry.insert(0, generated_key)

def encrypt_message():
    key = key_entry.get().encode('utf-8')
    message = message_entry.get()
    if not key or not message:
        messagebox.showwarning("Warning", "Please provide both key and message.")
        return
    padded_message = message.encode('utf-8').ljust(1024, b'\0')
    P = generate_permutation()
    S = generate_s_array(key)
    global encrypted_message, P_global, S_global
    encrypted_message = encrypt_block_simple(padded_message, P, S)
    P_global, S_global = P, S
    encrypted_label.config(text=f"Encrypted: {encrypted_message.hex()[:64]}")

def decrypt_message():
    global encrypted_message, P_global, S_global
    key = key_entry.get().encode('utf-8')
    if not encrypted_message or not key:
        messagebox.showwarning("Warning", "Please encrypt a message first.")
        return
    decrypted_message = decrypt_block_simple(encrypted_message, P_global, S_global).rstrip(b'\0')
    decrypted_label.config(text=f"Decrypted: {decrypted_message.decode('utf-8', errors='ignore')}")

# Create GUI
root = tk.Tk()
root.title("Simple Encryption Interface")
root.geometry("600x400")
root.configure(bg="#E0F7FA")
root.resizable(False, False)

# Static Key Input
tk.Label(root, text="Enter Key:", bg="#E0F7FA", font=("Arial", 12)).place(x=20, y=20)
key_entry = tk.Entry(root, width=40, font=("Arial", 12))
key_entry.place(x=120, y=20)
tk.Button(root, text="Generate Key", bg="#0288D1", fg="white", font=("Arial", 10),
          command=generate_key).place(x=460, y=18)

# Message Input
tk.Label(root, text="Enter Message:", bg="#E0F7FA", font=("Arial", 12)).place(x=20, y=80)
message_entry = tk.Entry(root, width=60, font=("Arial", 12))
message_entry.place(x=20, y=110)

# Encrypt Button
tk.Button(root, text="Encrypt", bg="#0288D1", fg="white", font=("Arial", 12),
          command=encrypt_message).place(x=150, y=160)

# Decrypt Button
tk.Button(root, text="Decrypt", bg="#0288D1", fg="white", font=("Arial", 12),
          command=decrypt_message).place(x=300, y=160)

# Encrypted Message Display
encrypted_label = tk.Label(root, text="Encrypted:", bg="#E0F7FA", font=("Arial", 12))
encrypted_label.place(x=20, y=220)

# Decrypted Message Display
decrypted_label = tk.Label(root, text="Decrypted:", bg="#E0F7FA", font=("Arial", 12))
decrypted_label.place(x=20, y=270)

# Run GUI
root.mainloop()
