from cryptography.hazmat.primitives import serialization
from base64 import b64decode
from time import time, sleep

from Server import Server
from DataBase import DataBase
from RSA import RSA
from JWT import JWT

class API_protect(Server):

    def client_command(self, user):
        # Enviar chave pública ao cliente
        public_pem = self.public_client_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        user.send(public_pem.decode())  # Envia como string PEM
        sleep(0.2)

        while self.running:
            try:
                user.send("Digite o usuário:")
                encrypted_username_b64 = user.recv()
                if not encrypted_username_b64:
                    raise ConnectionResetError
                username = RSA.Decrypt(self.private_client_key, b64decode(encrypted_username_b64))

                user.send("Digite a senha:")
                encrypted_password_b64 = user.recv()
                if not encrypted_password_b64:
                    raise ConnectionResetError
                password = RSA.Decrypt(self.private_client_key, b64decode(encrypted_password_b64))

                if not self.data_base.check(username, password):
                    user.send("Usuário ou senha inválido.")
                    continue

                user.send("Autenticação válida.")
                print(f"{user.IP} foi autenticado.")
                payload = {
                    "user_id": str(user.IP),
                    "exp": int(time()) + 300
                }
                token = JWT.create_jwt(payload, self.private_server_key)
                user.send(token)

                self.del_user(user)
                break

            except Exception as e:
                print(f"{user.IP} foi desconectado.\nErro: {e}")
                self.del_user(user)
                break

if __name__ == "__main__":

    server = API_protect(port=7778)
    server.run()
