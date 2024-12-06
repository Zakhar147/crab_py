# interface.py
import tkinter as tk
from tkinter import messagebox
from modules.crypto import encrypt_block_simple, generate_permutation, generate_s_array
from modules.utils import generate_key
from config.settings import WINDOW_TITLE, WINDOW_SIZE, BACKGROUND_COLOR, HEADER_FONT, TEXT_FONT, BUTTON_FONT


def create_interface():
    global key_entry, message_entry, res_input

    root = tk.Tk()
    root.title(WINDOW_TITLE)
    root.geometry(WINDOW_SIZE)
    root.configure(bg=BACKGROUND_COLOR)
    root.resizable(False, False)

    header = tk.Label(root, text=WINDOW_TITLE, bg=BACKGROUND_COLOR, fg="#4682B4", font=HEADER_FONT)
    header.place(relx=0.5, rely=0.1, anchor="center")

    key_label = tk.Label(root, text="Enter Key:", bg=BACKGROUND_COLOR, fg="#000000", font=TEXT_FONT)
    key_label.place(relx=0.1, rely=0.3)

    key_entry = tk.Entry(root, font=TEXT_FONT, relief="solid", bd=1, bg=BACKGROUND_COLOR)
    key_entry.place(relx=0.3, rely=0.3, relwidth=0.4, height=30)

    generate_key_btn = tk.Button(
        root,
        text="Generate Key",
        bg=BACKGROUND_COLOR,
        fg="#000000",
        font=BUTTON_FONT,
        relief="solid",
        bd=1,
        command=lambda: key_entry.insert(0, generate_key())
    )
    generate_key_btn.place(relx=0.75, rely=0.3, relwidth=0.2, height=30)

    message_label = tk.Label(root, text="Enter Message:", bg=BACKGROUND_COLOR, fg="#000000", font=TEXT_FONT)
    message_label.place(relx=0.1, rely=0.4)

    message_entry = tk.Entry(root, font=TEXT_FONT, relief="solid", bd=1, bg=BACKGROUND_COLOR)
    message_entry.place(relx=0.3, rely=0.4, relwidth=0.65, height=30)

    encrypt_btn = tk.Button(
        root,
        text="Encrypt",
        bg=BACKGROUND_COLOR,
        fg="#000000",
        font=BUTTON_FONT,
        relief="solid",
        bd=1,
        command=encrypt_message
    )
    encrypt_btn.place(relx=0.1, rely=0.53, relwidth=0.2, height=30)

    decrypt_btn = tk.Button(
        root,
        text="Decrypt",
        bg=BACKGROUND_COLOR,
        fg="#000000",
        font=BUTTON_FONT,
        relief="solid",
        bd=1,
        command=decrypt_message
    )
    decrypt_btn.place(relx=0.75, rely=0.53, relwidth=0.2, height=30)

    result_label = tk.Label(root, text="Result:", bg=BACKGROUND_COLOR, fg="#000000", font=("Arial", 14))
    result_label.place(relx=0.1, rely=0.7)

    res_input = tk.Label(root, bg=BACKGROUND_COLOR, fg="#000000", font=TEXT_FONT, anchor="w")
    res_input.place(relx=0.24, rely=0.7, relwidth=0.7, height=30)

    root.mainloop()

def encrypt_message():
    key = key_entry.get().encode('utf-8')
    message = message_entry.get()
    if not key or not message:
        messagebox.showwarning("Warning", "Please provide both key and message.")
        return
    padded_message = message.encode('utf-8').ljust(1024, b'\0')
    P = generate_permutation()
    S = generate_s_array(key)
    encrypted_message = encrypt_block_simple(padded_message, P, S)
    res_input.config(text=f"{encrypted_message.hex()[:64]}")

def decrypt_message():
    key = key_entry.get().encode('utf-8')
    if not key:
        messagebox.showwarning("Warning", "Please encrypt a message first.")
        return
    res_input.config(text="Decryption logic not fully integrated.")
