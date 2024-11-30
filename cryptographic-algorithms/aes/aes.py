from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def generate_key(password: str, salt: bytes) -> bytes:
    """Generates a key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file: str, output_file: str, password: str):
    """Encrypts a file using AES."""
    # Generate a random salt and initialization vector (IV)
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = generate_key(password, salt)
    
    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Read and pad the file
    with open(input_file, 'rb') as f:
        data = f.read()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Write the encrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(salt + iv + encrypted_data)

def decrypt_file(input_file: str, output_file: str, password: str):
    """Decrypts a file encrypted with AES."""
    with open(input_file, 'rb') as f:
        # Read salt, IV, and encrypted data
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()
    
    key = generate_key(password, salt)
    
    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt and unpad the data
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    # Write the decrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    print("File Encryption and Decryption using AES")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Choose an option (1/2): ").strip()
    
    if choice == "1":
        input_file = input("Enter the file to encrypt: ").strip()
        output_file = input("Enter the output encrypted file name: ").strip()
        password = input("Enter a password for encryption: ").strip()
        encrypt_file(input_file, output_file, password)
        print(f"File '{input_file}' has been encrypted and saved as '{output_file}'.")
    
    elif choice == "2":
        input_file = input("Enter the file to decrypt: ").strip()
        output_file = input("Enter the output decrypted file name: ").strip()
        password = input("Enter the password for decryption: ").strip()
        try:
            decrypt_file(input_file, output_file, password)
            print(f"File '{input_file}' has been decrypted and saved as '{output_file}'.")
        except Exception as e:
            print(f"Decryption failed: {e}")
    
    else:
        print("Invalid choice. Please run the program again.")
