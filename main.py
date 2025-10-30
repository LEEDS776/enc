import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

def generate_key(password, salt):
    password = password.encode()
    salt = salt.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_file(filename, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    f = Fernet(key)

    with open(filename, "rb") as file:
        file_data = file.read()

    encrypted_data = f.encrypt(file_data)

    with open(filename + ".enc", "wb") as file:
        file.write(salt + encrypted_data)

    os.remove(filename)
    print(f"[+] File {filename} berhasil dienkripsi jadi {filename}.enc")

def decrypt_file(filename, password):
    try:
        with open(filename, "rb") as file:
            file_data = file.read()

        salt = file_data[:16]
        encrypted_data = file_data[16:]
        key = generate_key(password, salt)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)

        new_filename = filename.replace(".enc", "")
        with open(new_filename, "wb") as file:
            file.write(decrypted_data)

        os.remove(filename)
        print(f"[+] File {filename} berhasil didekripsi jadi {new_filename}")

    except Exception as e:
        print(f"[-] Error: {e}")

# Contoh penggunaan
if __name__ == "__main__":
    filename = input("Masukkan nama file: ")
    password = input("Masukkan password: ")

    action = input("Enkripsi (E) atau Dekripsi (D)? ").upper()

    if action == "E":
        encrypt_file(filename, password)
    elif action == "D":
        decrypt_file(filename, password)
    else:
        print("Pilihan tidak valid.")
