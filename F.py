import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import filedialog
import datetime
import torch

class ImageEncryptor:
    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        return private_key, public_key

    def encrypt_image(self, image_path, public_key, out_img_path):
        with open(image_path, 'rb') as image_file:
            image_data = image_file.read()

        encrypted_data = public_key.encrypt(
            image_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(out_img_path, 'wb') as out_image_file:
            out_image_file.write(encrypted_data)

    def decrypt_image(self, encrypted_img_path, private_key, out_img_path):
        with open(encrypted_img_path, 'rb') as encrypted_image_file:
            encrypted_data = encrypted_image_file.read()

        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(out_img_path, 'wb') as out_image_file:
            out_image_file.write(decrypted_data)

class Main:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption App")

        self.original_image_path = tk.StringVar()
        self.encrypted_image_path = tk.StringVar()
        self.keys_path = tk.StringVar()
        self.decrypted_image_path = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Original Image:").grid(row=0, column=0)
        tk.Entry(self.root, textvariable=self.original_image_path, state="readonly", width=50).grid(row=0, column=1)
        tk.Button(self.root, text="Select", command=self.select_original_image).grid(row=0, column=2)

        tk.Label(self.root, text="Encrypted Image:").grid(row=1, column=0)
        tk.Entry(self.root, textvariable=self.encrypted_image_path, state="readonly", width=50).grid(row=1, column=1)
        tk.Button(self.root, text="Encrypt", command=self.encrypt_image).grid(row=1, column=2)

        tk.Label(self.root, text="Keys:").grid(row=2, column=0)
        tk.Entry(self.root, textvariable=self.keys_path, state="readonly", width=50).grid(row=2, column=1)
        tk.Button(self.root, text="Hide", command=self.hide_image).grid(row=2, column=2)

        tk.Label(self.root, text="Decrypted Image:").grid(row=3, column=0)
        tk.Entry(self.root, textvariable=self.decrypted_image_path, state="readonly", width=50).grid(row=3, column=1)
        tk.Button(self.root, text="Decrypt", command=self.decrypt_image).grid(row=3, column=2)

    def select_original_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        self.original_image_path.set(file_path)

    def encrypt_image(self):
        encryptor = ImageEncryptor()
        private_key, public_key = encryptor.generate_key_pair()

        keys_path = self.original_image_path.get().rsplit('.', 1)[0] + '_keys.txt'
        self.keys_path.set(keys_path)

        encryptor.encrypt_image(self.original_image_path.get(), public_key, self.encrypted_image_path.get())
        with open(keys_path, 'wb') as keys_file:
            keys_file.write(
                serialization.serialize_ssh_public_key(
                    public_key,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    

    def decrypt_image(self):
        encryptor = ImageEncryptor()

        with open(self.keys_path.get(), 'rb') as keys_file:
            public_key = serialization.load_ssh_public_key(
                keys_file.read(),
                backend=default_backend()
            )

        encryptor.decrypt_image(self.encrypted_image_path.get(), public_key, self.decrypted_image_path.get())

if __name__ == "__main__":
    root = tk.Tk()
    app = Main(root)
    root.mainloop()
