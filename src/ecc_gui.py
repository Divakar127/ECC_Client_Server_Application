import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QMessageBox
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature, InvalidTag
import os

# Load ECC private and public keys
def load_private_key():
    with open('../keys/private_key.pem', 'rb') as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key():
    with open('../keys/public_key.pem', 'rb') as key_file:
        return serialization.load_pem_public_key(key_file.read())

# Encrypt the message using ECC and AES-GCM
def encrypt_message(message):
    public_key = load_public_key()
    private_key = load_private_key()

    shared_key = private_key.exchange(ec.ECDH(), public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)

    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    return iv + ciphertext, encryptor.tag

# Decrypt the message using ECC and AES-GCM
def decrypt_message(ciphertext, tag):
    private_key = load_private_key()
    public_key = load_public_key()

    shared_key = private_key.exchange(ec.ECDH(), public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)

    iv = ciphertext[:12]
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[12:]) + decryptor.finalize()

# Sign a message using the sender's private key
def sign_message(message):
    private_key = load_private_key()
    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return signature

# Verify the message signature using the sender's public key
def verify_message(message, signature):
    public_key = load_public_key()
    public_key.verify(
        signature,
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )

# GUI Application for ECC Encryption, Decryption, and Signature Verification
class ECCApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ECC Encryption, Decryption & Signature')

        layout = QVBoxLayout()

        # Encryption Section
        self.label_encrypt = QLabel('Enter the message to encrypt:')
        layout.addWidget(self.label_encrypt)

        self.textbox_encrypt = QTextEdit(self)
        layout.addWidget(self.textbox_encrypt)

        self.button_encrypt = QPushButton('Encrypt', self)
        self.button_encrypt.clicked.connect(self.encrypt_message)
        layout.addWidget(self.button_encrypt)

        self.label_encrypted = QLabel('Encrypted message (hex):')
        layout.addWidget(self.label_encrypted)

        self.encrypted_message = QTextEdit(self)
        self.encrypted_message.setReadOnly(True)
        layout.addWidget(self.encrypted_message)

        self.label_tag = QLabel('Encryption tag (hex):')
        layout.addWidget(self.label_tag)

        self.tag = QTextEdit(self)
        self.tag.setReadOnly(True)
        layout.addWidget(self.tag)

        self.label_signature = QLabel('Signature (hex):')
        layout.addWidget(self.label_signature)

        self.signature = QTextEdit(self)
        self.signature.setReadOnly(True)
        layout.addWidget(self.signature)

        # Decryption Section
        self.label_decrypt = QLabel('Enter the received encrypted message (in hex):')
        layout.addWidget(self.label_decrypt)

        self.textbox_decrypt = QTextEdit(self)
        layout.addWidget(self.textbox_decrypt)

        self.label_tag_input = QLabel('Enter the GCM tag (in hex):')
        layout.addWidget(self.label_tag_input)

        self.textbox_tag = QTextEdit(self)
        layout.addWidget(self.textbox_tag)

        self.label_signature_input = QLabel('Enter the signature (in hex):')
        layout.addWidget(self.label_signature_input)

        self.textbox_signature = QTextEdit(self)
        layout.addWidget(self.textbox_signature)

        self.button_decrypt = QPushButton('Decrypt & Verify', self)
        self.button_decrypt.clicked.connect(self.decrypt_and_verify_message)
        layout.addWidget(self.button_decrypt)

        self.result_label = QLabel('Decrypted message will appear here:')
        layout.addWidget(self.result_label)

        self.decrypted_message = QTextEdit(self)
        self.decrypted_message.setReadOnly(True)
        layout.addWidget(self.decrypted_message)

        self.setLayout(layout)

    def encrypt_message(self):
        try:
            message = self.textbox_encrypt.toPlainText().strip()
            if not message:
                raise ValueError("Message cannot be empty.")

            encrypted_message, tag = encrypt_message(message)
            signature = sign_message(message)

            self.encrypted_message.setText(encrypted_message.hex())
            self.tag.setText(tag.hex())
            self.signature.setText(signature.hex())

        except Exception as e:
            QMessageBox.critical(self, 'Encryption Error', f"An error occurred during encryption: {str(e)}")

    def decrypt_and_verify_message(self):
        try:
            # Validate hex input for encrypted message
            encrypted_message_hex = self.textbox_decrypt.toPlainText().strip()
            if not all(c in '0123456789abcdefABCDEF' for c in encrypted_message_hex):
                raise ValueError("Invalid hex input for encrypted message.")

            # Validate hex input for tag
            tag_hex = self.textbox_tag.toPlainText().strip()
            if not all(c in '0123456789abcdefABCDEF' for c in tag_hex):
                raise ValueError("Invalid hex input for tag.")

            # Validate hex input for signature
            signature_hex = self.textbox_signature.toPlainText().strip()
            if not all(c in '0123456789abcdefABCDEF' for c in signature_hex):
                raise ValueError("Invalid hex input for signature.")

            # Convert hex strings to bytes
            encrypted_message = bytes.fromhex(encrypted_message_hex)
            tag = bytes.fromhex(tag_hex)
            signature = bytes.fromhex(signature_hex)

            # Decrypt the message
            decrypted_message = decrypt_message(encrypted_message, tag)

            # Verify the signature
            verify_message(decrypted_message.decode(), signature)

            # If verification is successful, display the decrypted message and a success message
            self.decrypted_message.setText(decrypted_message.decode())
            QMessageBox.information(self, 'Verification Success', 'Signature is valid.')

        except ValueError as e:
            QMessageBox.critical(self, 'Input Error', str(e))
        except InvalidSignature:
            # If verification fails, notify the user
            QMessageBox.critical(self, 'Verification Failed', 'Invalid signature.')
        except InvalidTag:
            QMessageBox.critical(self, 'Decryption Failed', 'Decryption failed. Invalid tag or corrupted message.')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"An error occurred: {str(e)}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ECCApp()
    ex.show()
    sys.exit(app.exec_())
