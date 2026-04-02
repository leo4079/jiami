# File Encryption Tool (AES-GCM)
# pip install cryptography

import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ===== CONFIG =====
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 100000


# ===== KEY DERIVATION =====
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# ===== ENCRYPT =====
def encrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        data = f.read()

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)

    encrypted = aesgcm.encrypt(nonce, data, None)

    with open(output_file, 'wb') as f:
        f.write(salt + nonce + encrypted)

    print(f"[+] Encrypted -> {output_file}")


# ===== DECRYPT =====
def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        raw = f.read()

    salt = raw[:SALT_SIZE]
    nonce = raw[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    encrypted = raw[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        decrypted = aesgcm.decrypt(nonce, encrypted, None)
    except Exception:
        print("[!] Decryption failed: wrong password or corrupted file")
        return

    with open(output_file, 'wb') as f:
        f.write(decrypted)

    print(f"[+] Decrypted -> {output_file}")


# ===== CLI =====
def main():
    if len(sys.argv) < 5:
        print("Usage:")
        print("  python tool.py encrypt input.txt output.enc password")
        print("  python tool.py decrypt input.enc output.txt password")
        return

    mode = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]
    password = sys.argv[4]

    if mode == 'encrypt':
        encrypt_file(input_file, output_file, password)
    elif mode == 'decrypt':
        decrypt_file(input_file, output_file, password)
    else:
        print("Invalid mode. Use encrypt/decrypt")


if __name__ == '__main__':
    main()