import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def aes_encrypt_gui():
    global key, iv
    key = get_random_bytes(16)  # AES-128 key
    plaintext = text_input.get("1.0", "end-1c")
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    encrypted_output.delete("1.0", "end")
    encrypted_output.insert("1.0", ciphertext.hex())
    iv_output.delete("1.0", "end")
    iv_output.insert("1.0", iv.hex())
    key_output.delete("1.0", "end")
    key_output.insert("1.0", key.hex())

def aes_decrypt_gui():
    try:
        ciphertext = bytes.fromhex(encrypted_output.get("1.0", "end-1c"))
        iv = bytes.fromhex(iv_input.get("1.0", "end-1c"))
        key = bytes.fromhex(key_input.get("1.0", "end-1c"))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        decrypted_output.delete("1.0", "end")
        decrypted_output.insert("1.0", plaintext.decode())
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

root = tk.Tk()
root.title("AES Encryption/Decryption")

tk.Label(root, text="Enter text to encrypt:").pack()
text_input = tk.Text(root, height=5)
text_input.pack()

tk.Button(root, text="Encrypt", command=aes_encrypt_gui).pack()

tk.Label(root, text="Encrypted text:").pack()
encrypted_output = tk.Text(root, height=5)
encrypted_output.pack()

tk.Label(root, text="Generated IV:").pack()
iv_output = tk.Text(root, height=1)
iv_output.pack()

tk.Label(root, text="Generated Key:").pack()
key_output = tk.Text(root, height=1)
key_output.pack()

tk.Label(root, text="Enter IV for decryption:").pack()
iv_input = tk.Text(root, height=1)
iv_input.pack()

tk.Label(root, text="Enter Key for decryption:").pack()
key_input = tk.Text(root, height=1)
key_input.pack()

tk.Button(root, text="Decrypt", command=aes_decrypt_gui).pack()

tk.Label(root, text="Decrypted text:").pack()
decrypted_output = tk.Text(root, height=5)
decrypted_output.pack()

root.mainloop()
