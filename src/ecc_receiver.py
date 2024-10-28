from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

# Load the recipient's private key
def load_private_key():
    with open('../keys/private_key.pem', 'rb') as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# Load the sender's public key
def load_public_key():
    with open('../keys/public_key.pem', 'rb') as key_file:
        return serialization.load_pem_public_key(key_file.read())

# Decrypt the message using ECC and AES-GCM
def decrypt_message(ciphertext, tag):
    private_key = load_private_key()
    public_key = load_public_key()

    # ECDH Key exchange
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    # Derive the symmetric key from the shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    # Extract the IV from the beginning of the ciphertext
    iv = ciphertext[:12]
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext[12:]) + decryptor.finalize()

    return plaintext

# Verify the message signature using the sender's public key
def verify_message(encrypted_message, signature):
    public_key = load_public_key()
    try:
        public_key.verify(signature, encrypted_message, ec.ECDSA(hashes.SHA256()))
        print("Signature is valid.")
    except InvalidSignature:
        print("Invalid signature.")

# Main receiver logic
if __name__ == "__main__":
    encrypted_message = bytes.fromhex(input("Enter the received encrypted message (hex): "))
    tag = bytes.fromhex(input("Enter the GCM tag (hex): "))
    signature = bytes.fromhex(input("Enter the signature (hex): "))

    # Verify the signature
    verify_message(encrypted_message, signature)

    # Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, tag)
    print(f"Decrypted Message: {decrypted_message.decode()}")
