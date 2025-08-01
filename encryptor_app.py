import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
import base64
import hashlib

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def encrypt(text, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text).encode())
    return base64.b64encode(encrypted).decode()

def decrypt(text, password):
    key = hashlib.sha256(password.encode()).digest()
    text = text.strip()  # Removes spaces/newlines that break Base64
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(text))
    return decrypted.decode().rstrip()

def do_encrypt():
    try:
        result = encrypt(entry_text.get(), entry_password.get())
        output_text.delete(0, tk.END)
        output_text.insert(0, result)
    except Exception as e:
        messagebox.showerror("Encryption Error", f"Encryption failed!\n\n{str(e)}")

def do_decrypt():
    try:
        result = decrypt(entry_text.get(), entry_password.get())
        output_text.delete(0, tk.END)
        output_text.insert(0, result)
    except Exception as e:
        messagebox.showerror("Decryption Error", f"Decryption failed!\n\n{str(e)}")

# GUI setup
window = tk.Tk()
window.title("Secure Encryptor App")
window.geometry("400x300")

tk.Label(window, text="Enter Text:").pack()
entry_text = tk.Entry(window, width=50)
entry_text.pack()

tk.Label(window, text="Enter Password:").pack()
