from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend
import os

# === RSA Key Generation ===
def generate_rsa_keys(private_key_file, public_key_file):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Save private key
    with open(private_key_file, "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Save public key
    public_key = private_key.public_key()
    with open(public_key_file, "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Keys generated and saved: {private_key_file}, {public_key_file}")

# === RSA Encryption ===
def encrypt_file(input_file, output_file, public_key_file):
    # Load public key
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    
    # Generate a random AES key and IV
    aes_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(16)  # 128-bit IV
    
    # Encrypt the AES key with the RSA public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Encrypt the file with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(input_file, "rb") as infile, open(output_file, "wb") as outfile:
        # Write the encrypted AES key and IV to the output file
        outfile.write(len(encrypted_aes_key).to_bytes(4, byteorder="big"))
        outfile.write(encrypted_aes_key)
        outfile.write(iv)
        
        # Encrypt the file data and write it
        while chunk := infile.read(4096):
            outfile.write(encryptor.update(chunk))
        outfile.write(encryptor.finalize())
    print(f"File encrypted and saved to: {output_file}")

# === RSA Decryption ===
def decrypt_file(input_file, output_file, private_key_file):
    # Load private key
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    with open(input_file, "rb") as infile, open(output_file, "wb") as outfile:
        # Read the encrypted AES key and IV
        key_len = int.from_bytes(infile.read(4), byteorder="big")
        encrypted_aes_key = infile.read(key_len)
        iv = infile.read(16)
        
        # Decrypt the AES key with the RSA private key
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt the file with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        while chunk := infile.read(4096):
            outfile.write(decryptor.update(chunk))
        outfile.write(decryptor.finalize())
    print(f"File decrypted and saved to: {output_file}")

# === Main Menu ===
def main():
    while True:
        print("\nRSA File Encryption and Decryption")
        print("1. Generate RSA keys")
        print("2. Encrypt a file")
        print("3. Decrypt a file")
        print("4. Exit")
        choice = input("Choose an option (1/2/3/4): ")
        
        if choice == "1":
            private_key_file = input("Enter the private key file name: ")
            public_key_file = input("Enter the public key file name: ")
            generate_rsa_keys(private_key_file, public_key_file)
        elif choice == "2":
            input_file = input("Enter the file to encrypt: ")
            output_file = input("Enter the output encrypted file name: ")
            public_key_file = input("Enter the public key file: ")
            encrypt_file(input_file, output_file, public_key_file)
        elif choice == "3":
            input_file = input("Enter the file to decrypt: ")
            output_file = input("Enter the output decrypted file name: ")
            private_key_file = input("Enter the private key file: ")
            decrypt_file(input_file, output_file, private_key_file)
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
