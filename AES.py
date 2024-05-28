from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv, ciphertext

def aes_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# Example usage
key = get_random_bytes(16)  # AES-128 key
plaintext = "This is a secret message."

iv, ciphertext = aes_encrypt(plaintext, key)
print("Ciphertext:", ciphertext)

decrypted_text = aes_decrypt(iv, ciphertext, key)
print("Decrypted text:", decrypted_text)
