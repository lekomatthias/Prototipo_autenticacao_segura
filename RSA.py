from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import os

class RSA:
    @staticmethod
    def KeyGen():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def Encrypt(key, message):
        cipher = key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return cipher
    
    @staticmethod
    def Decrypt(key, cipher):
        message = key.decrypt(
            cipher,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        return message

    @staticmethod
    def SaveKey(key, filename):
        if os.path.exists(filename):
            os.remove(filename)

        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filename, "wb") as f:
            f.write(pem)

    @staticmethod
    def LoadKey(filename):
        with open(filename, "rb") as f:
            return serialization.load_pem_public_key(f.read())

if __name__ == "__main__":
    mensagem = "Mensagem secreta com RSA!"

    Pr, Pu = RSA.KeyGen()
    c = RSA.Encrypt(Pu, mensagem)
    print(f"mensagem: {RSA.Decrypt(Pr, c)}")

    nome = "teste_chave_publica.pem"
    RSA.SaveKey(Pu, nome)
    if Pu == RSA.LoadKey(nome):
        print("senha salva e carregada corretamente!")
