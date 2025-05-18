import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class AES:
    @staticmethod
    def Generate_key(length=32):
        return os.urandom(length)

    @staticmethod
    def Encrypt(key, plaintext):
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def Decrypt(key, b64_ciphertext):
        data = base64.b64decode(b64_ciphertext)
        iv = data[:16]
        ciphertext = data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode()

if __name__ == "__main__":

    text = "mensagem muito secreta"

    key = AES.generate_key()
    # Criptografar
    c = AES.encrypt(key, text)
    print("cifra:", c)

    # Descriptografar
    m = AES.decrypt(key, c)
    print("mensagem:", m)
