import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    messagebox.showinfo("Key", "✅ Key generated and saved as 'secret.key'.")

def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        messagebox.showerror("Error", "❌ Key not found! Generate key first.")
        return None

def encrypt_file():
    filepath = filedialog.askopenfilename(title="Select file to encrypt")
    if not filepath:
        return
    key = load_key()
    if key is None:
        return
    fernet = Fernet(key)
    with open(filepath, "rb") as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    filename = os.path.basename(filepath)
    out_path = os.path.join("encrypted_files", filename + ".enc")
    with open(out_path, "wb") as enc_file:
        enc_file.write(encrypted)
    messagebox.showinfo("Success", f"🔐 File encrypted and saved to:\n{out_path}")

def decrypt_file():
    filepath = filedialog.askopenfilename(title="Select encrypted file", initialdir="encrypted_files")
    if not filepath:
        return
    output_name = os.path.splitext(os.path.basename(filepath))[0]
    output_path = os.path.join("decrypted_files", output_name)
    key = load_key()
    if key is None:
        return
    fernet = Fernet(key)
    try:
        with open(filepath, "rb") as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted)
        with open(output_path, "wb") as dec_file:
            dec_file.write(decrypted)
        messagebox.showinfo("Success", f"🔓 File decrypted and saved to:\n{output_path}")
    except Exception as e:
        messagebox.showerror("Error", f"❌ Decryption failed: {str(e)}")

root = tk.Tk()
root.title("🔐 AES File Encrypt/Decrypt Tool")
root.geometry("420x250")
root.resizable(False, False)

tk.Label(root, text="AES File Tool", font=("Helvetica", 16, "bold")).pack(pady=10)
tk.Button(root, text="🔑 Generate Key", width=40, command=generate_key).pack(pady=5)
tk.Button(root, text="🔐 Encrypt File", width=40, command=encrypt_file).pack(pady=5)
tk.Button(root, text="🔓 Decrypt File", width=40, command=decrypt_file).pack(pady=5)
tk.Label(root, text="Encrypted in: encrypted_files/\nDecrypted in: decrypted_files/", font=("Arial", 9)).pack(pady=15)

root.mainloop()
