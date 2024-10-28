import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Load the sender's private key
def load_private_key():
    with open('../keys/private_key.pem', 'rb') as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# Load the recipient's public key
def load_public_key():
    with open('../keys/public_key.pem', 'rb') as key_file:
        return serialization.load_pem_public_key(key_file.read())

# Encrypt the message using ECC and AES-GCM
def encrypt_message(message):
    private_key = load_private_key()
    public_key = load_public_key()

    # ECDH Key exchange
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    # Derive a symmetric key from the shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    # AES-GCM encryption
    iv = os.urandom(12)  # Generate a random IV
    encryptor = Cipher(algorithms.AES(derived_key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    return iv + ciphertext, encryptor.tag

# Sign the message using the sender's private key
def sign_message(message):
    private_key = load_private_key()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

# Main sender logic
if __name__ == "__main__":
    message = input("Enter your message: ").encode()

    # Encrypt the message
    encrypted_message, tag = encrypt_message(message)
    print(f"Encrypted Message: {encrypted_message.hex()}")
    print(f"Tag: {tag.hex()}")

    # Sign the encrypted message
    signature = sign_message(encrypted_message)
    print(f"Signature: {signature.hex()}")
