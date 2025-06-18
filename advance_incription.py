import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64
import secrets

class AES256Encryptor:
    def __init__(self, password: str):
        self.password = password.encode()
        self.backend = default_backend()

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=self.backend
        )
        return kdf.derive(self.password)

    def encrypt(self, data: bytes) -> bytes:
        salt = secrets.token_bytes(16)
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return salt + nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 File Encryptor")
        self.root.geometry("400x200")
        self.file_path = None

        self.label = tk.Label(root, text="AES-256 File Encryptor", font=("Arial", 16))
        self.label.pack(pady=10)

        self.file_btn = tk.Button(root, text="Choose File", command=self.choose_file)
        self.file_btn.pack()

        self.password_label = tk.Label(root, text="Enter Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(root, show="*", width=30)
        self.password_entry.pack()

        self.encrypt_btn = tk.Button(root, text="Encrypt", command=self.encrypt_file)
        self.encrypt_btn.pack(pady=5)

        self.decrypt_btn = tk.Button(root, text="Decrypt", command=self.decrypt_file)
        self.decrypt_btn.pack()

    def choose_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            messagebox.showinfo("File Selected", f"File: {self.file_path}")

    def encrypt_file(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please choose a file to encrypt.")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter a password.")
            return
        with open(self.file_path, "rb") as f:
            data = f.read()
        encryptor = AES256Encryptor(password)
        encrypted = encryptor.encrypt(data)
        out_file = self.file_path + ".enc"
        with open(out_file, "wb") as f:
            f.write(encrypted)
        messagebox.showinfo("Success", f"File encrypted and saved as:\n{out_file}")

    def decrypt_file(self):
        if not self.file_path or not self.file_path.endswith(".enc"):
            messagebox.showwarning("Invalid File", "Please choose a .enc file to decrypt.")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter a password.")
            return
        with open(self.file_path, "rb") as f:
            data = f.read()
        try:
            decryptor = AES256Encryptor(password)
            decrypted = decryptor.decrypt(data)
        except Exception as e:
            messagebox.showerror("Decryption Failed", str(e))
            return
        out_file = self.file_path.replace(".enc", ".dec")
        with open(out_file, "wb") as f:
            f.write(decrypted)
        messagebox.showinfo("Success", f"File decrypted and saved as:\n{out_file}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
