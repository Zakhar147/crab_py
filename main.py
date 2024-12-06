import tkinter as tk
from tkinter import messagebox
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
    res_input.config(text=f"{encrypted_message.hex()[:64]}")

def decrypt_message():
    global encrypted_message, P_global, S_global
    key = key_entry.get().encode('utf-8')
    if not encrypted_message or not key:
        messagebox.showwarning("Warning", "Please encrypt a message first.")
        return
    decrypted_message = decrypt_block_simple(encrypted_message, P_global, S_global).rstrip(b'\0')
    res_input.config(text=f"{decrypted_message.decode('utf-8', errors='ignore')}")

def main():
    global key_entry, message_entry, res_input

    root = tk.Tk()
    root.title("Encryption Tool")
    root.geometry("600x500")
    root.configure(bg="#F0F8FF")
    root.resizable(False, False)

    header = tk.Label(root, text="Encryption Tool", bg="#F0F8FF", fg="#4682B4", font=("Arial", 24, "bold"))
    header.place(relx=0.5, rely=0.1, anchor="center")

    key_label = tk.Label(root, text="Enter Key:", bg="#F0F8FF", fg="#000000", font=("Arial", 12))
    key_label.place(relx=0.1, rely=0.3)

    key_entry = tk.Entry(root, font=("Arial", 12), relief="solid", bd=1, bg="#F0F8FF")
    key_entry.place(relx=0.3, rely=0.3, relwidth=0.4, height=30)

    generate_key_btn = tk.Button(
        root,
        text="Generate Key",
        bg="#F0F8FF",
        fg="#000000",
        font=("Arial", 12),
        relief="solid",
        bd=1,
        command=generate_key
    )
    generate_key_btn.place(relx=0.75, rely=0.3, relwidth=0.2, height=30)

    message_label = tk.Label(root, text="Enter Message:", bg="#F0F8FF", fg="#000000", font=("Arial", 12))
    message_label.place(relx=0.1, rely=0.4)

    message_entry = tk.Entry(root, font=("Arial", 12), relief="solid", bd=1, bg="#F0F8FF")
    message_entry.place(relx=0.3, rely=0.4, relwidth=0.65, height=30)

    encrypt_btn = tk.Button(
        root,
        text="Encrypt",
        bg="#F0F8FF",
        fg="#000000",
        font=("Arial", 12),
        relief="solid",
        bd=1,
        command=encrypt_message
    )
    encrypt_btn.place(relx=0.1, rely=0.53, relwidth=0.2, height=30)

    decrypt_btn = tk.Button(
        root,
        text="Decrypt",
        bg="#F0F8FF",
        fg="#000000",
        font=("Arial", 12),
        relief="solid",
        bd=1,
        command=decrypt_message
    )
    decrypt_btn.place(relx=0.75, rely=0.53, relwidth=0.2, height=30)

    result_label = tk.Label(root, text="Result:", bg="#F0F8FF", fg="#000000", font=("Arial", 14))
    result_label.place(relx=0.1, rely=0.7)

    res_input = tk.Label(root, bg="#F0F8FF", fg="#000000", font=("Arial", 12), anchor="w")
    res_input.place(relx=0.24, rely=0.7, relwidth=0.7, height=30)

    root.mainloop()

if __name__ == "__main__":
    main()