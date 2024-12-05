import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import random
import hashlib

# Utility functions for encryption and decryption
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
root.title("Enhanced Encryption Interface")
root.geometry("1000x600")
root.configure(bg="#F0F8FF")
root.resizable(False, False)

# Header
header = tk.Label(root, text="Simple Encryption Tool", bg="#4682B4", fg="white", font=("Arial", 16), pady=10)
header.pack(fill="x")

# Key Input
frame = tk.Frame(root, bg="#000000", padн=120)
frame.pack(fill="both", expand=True)

tk.Label(frame, text="Enter Key:", bg="#F0F8FF", font=("Arial", 12)).grid(row=0, column=0, sticky="w", padx=10, pady=5)
key_entry = tk.Entry(frame, width=40, font=("Arial", 12), relief="solid")
key_entry.grid(row=0, column=1, padx=10, pady=5)
tk.Button(frame, text="Generate Key", bg="#4682B4", fg="white", font=("Arial", 10), command=generate_key).grid(row=0, column=2, padx=10, pady=5)

# Message Input
tk.Label(frame, text="Enter Message:", bg="#F0F8FF", font=("Arial", 12)).grid(row=1, column=0, sticky="w", padx=10, pady=5)
message_entry = tk.Entry(frame, width=60, font=("Arial", 12), relief="solid")
message_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=5)

# Encrypt and Decrypt Buttons
tk.Button(frame, text="Encrypt", bg="#008080", fg="white", font=("Arial", 12), command=encrypt_message).grid(row=2, column=0, padx=10, pady=20)
tk.Button(frame, text="Decrypt", bg="#008080", fg="white", font=("Arial", 12), command=decrypt_message).grid(row=2, column=1, padx=10, pady=20)

# Result Display
encrypted_label = tk.Label(frame, text="Encrypted: ", bg="#F0F8FF", font=("Arial", 12), anchor="w")
encrypted_label.grid(row=3, column=0, columnspan=3, sticky="w", padx=10, pady=5)

decrypted_label = tk.Label(frame, text="Decrypted: ", bg="#F0F8FF", font=("Arial", 12), anchor="w")
decrypted_label.grid(row=4, column=0, columnspan=3, sticky="w", padx=10, pady=5)

# Run GUI
root.mainloop()
