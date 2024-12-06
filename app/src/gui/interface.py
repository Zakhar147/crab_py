# interface.py
import tkinter as tk
from tkinter import messagebox

from crypto.generate import generate_key, generate_permutation, generate_s_array
from crypto.encrypt import encrypt_message
from crypto.decrypt import decrypt_message
from settings import *


class Interface: 
    
    def _handle_generate_key(self):
        key = generate_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)
        
    def _handle_encrypt(self, key, message):
        try:
            self.P = generate_permutation()
            self.S = generate_s_array(key)
            self.encrypted_message = encrypt_message(key, message, self.P, self.S)
            self.res_input.config(text=f"{self.encrypted_message.hex()[:64]}")
        except ValueError as e:
            messagebox.showwarning("Warning", str(e))
        
    def _handle_decrypt(self, key, encrypted_message):
        try:
            result = decrypt_message(key, encrypted_message, self.P, self.S)
            self.res_input.config(text=f"{result.decode('utf-8', errors='ignore')}")
            
        except ValueError as e:
            messagebox.showwarning("Warning", str(e))        
        
    def _setup(self):
        
        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)
        self.root.geometry(WINDOW_SIZE)
        self.root.configure(bg=BACKGROUND_COLOR)
        self.root.resizable(False, False)

        self.header = tk.Label(self.root, text=WINDOW_TITLE, bg=BACKGROUND_COLOR, fg="#4682B4", font=HEADER_FONT)
        self.header.place(relx=0.5, rely=0.1, anchor="center")

        self.key_label = tk.Label(self.root, text="Enter Key:", bg=BACKGROUND_COLOR, fg="#000000", font=TEXT_FONT)
        self.key_label.place(relx=0.1, rely=0.3)

        self.key_entry = tk.Entry(self.root, font=TEXT_FONT, relief="solid", bd=1, bg=BACKGROUND_COLOR)
        self.key_entry.place(relx=0.3, rely=0.3, relwidth=0.4, height=30)

        self.generate_key_btn = tk.Button(
            self.root,
            text="Generate Key",
            bg=BACKGROUND_COLOR,
            fg="#000000",
            font=BUTTON_FONT,
            relief="solid",
            bd=1,
            command=self._handle_generate_key
        )
        self.generate_key_btn.place(relx=0.75, rely=0.3, relwidth=0.2, height=30)

        self.message_label = tk.Label(self.root, text="Enter Message:", bg=BACKGROUND_COLOR, fg="#000000", font=TEXT_FONT)
        self.message_label.place(relx=0.1, rely=0.4)

        self.message_entry = tk.Entry(self.root, font=TEXT_FONT, relief="solid", bd=1, bg=BACKGROUND_COLOR)
        self.message_entry.place(relx=0.3, rely=0.4, relwidth=0.65, height=30)

        encrypt_btn = tk.Button(
            self.root,
            text="Encrypt",
            bg=BACKGROUND_COLOR,
            fg="#000000",
            font=BUTTON_FONT,
            relief="solid",
            bd=1,
            command=lambda: self._handle_encrypt(self.key_entry.get().encode('utf-8'), self.message_entry.get())
        )

        encrypt_btn.place(relx=0.1, rely=0.53, relwidth=0.2, height=30)

        self.decrypt_btn = tk.Button(
            self.root,
            text="Decrypt",
            bg=BACKGROUND_COLOR,
            fg="#000000",
            font=BUTTON_FONT,
            relief="solid",
            bd=1,
            command =lambda: self._handle_decrypt(self.key_entry.get().encode('utf-8'), self.encrypted_message)
        )
        self.decrypt_btn.place(relx=0.75, rely=0.53, relwidth=0.2, height=30)

        self.result_label = tk.Label(self.root, text="Result:", bg=BACKGROUND_COLOR, fg="#000000", font=("Arial", 14))
        self.result_label.place(relx=0.1, rely=0.7)

        self.res_input = tk.Label(self.root, bg=BACKGROUND_COLOR, fg="#000000", font=TEXT_FONT, anchor="w")
        self.res_input.place(relx=0.24, rely=0.7, relwidth=0.7, height=30)
        
    def __init__(self):
        self.P = None
        self.S = None
        self.encrypted_message = None
        self._setup()
    
    def start(self):
        self.root.mainloop()