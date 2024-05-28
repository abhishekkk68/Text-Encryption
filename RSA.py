from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def rsa_encrypt(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

# Generate RSA keys
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

# Example usage
plaintext = "This is a secret message."

ciphertext = rsa_encrypt(plaintext, public_key)
print("Ciphertext:", ciphertext)

decrypted_text = rsa_decrypt(ciphertext, private_key)
print("Decrypted text:", decrypted_text)
