Text Encryption Using Cryptographic Algorithms

This project demonstrates text encryption and decryption using the AES (Advanced Encryption Standard) cryptographic algorithm. The project includes a graphical user interface (GUI) built with 'tkinter' to allow users to encrypt and decrypt text easily.

Introduction

Encryption is a process of converting plaintext into ciphertext to protect the confidentiality of data. This project showcases how to use the AES algorithm for symmetric key encryption, where the same key is used for both encryption and decryption. The GUI built with tkinter provides an easy-to-use interface for users to perform encryption and decryption.

Features

*Encrypt plaintext using AES-128.
*Decrypt ciphertext using AES-128.
*Generate and display the encryption key and initialization vector (IV).
*Simple and intuitive GUI for user interaction.

How It Works

*AES Encryption:

The AES algorithm is used in CBC (Cipher Block Chaining) mode for encryption. A random 128-bit key and IV are generated for each encryption operation.

*Key and IV:

The generated key and IV are displayed after encryption to be used for decryption. These values must be provided correctly to decrypt the ciphertext successfully.

*tkinter GUI:

The GUI is built using the tkinter library, providing a simple interface for users to input text, view encrypted text, and decrypt ciphertext.