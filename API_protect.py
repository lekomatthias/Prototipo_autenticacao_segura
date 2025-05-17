from cryptography.hazmat.primitives import serialization
from base64 import b64decode
from time import sleep

from Server import Server
from RSA import RSA
from JWT import JWT

class API_protect(Server):

    def __init__(self, port, buffer_size=4096, data_base_name="dados_seguros.db"):
        super().__init__(port=port, 
                       buffer_size=buffer_size, 
                       data_base_name=data_base_name)
        self.secure_data = "__dados_seguros_do_servidos__"
        self.public_server_key = None

    def client_command(self, user):
        # Enviar chave pública ao cliente
        public_pem = self.public_client_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        user.send(public_pem.decode())
        sleep(0.1)

        while self.running:
            try:
                user.send("Validando o token...")
                sleep(0.05)
                user.send("Envie seu token.")
                token = user.recv().strip()
                self.public_server_key = RSA.LoadKey(self.server_key_name)
                if not JWT.verify_jwt(token, self.public_server_key):
                    user.send("Token inválido ou expirado.")
                    user.send("Tente acessar o servidor de autenticação entes deste.")
                    self.del_user(user)
                    break
                user.send("Token validado com sucesso!")

                user.send("Deseja obter umas infos diferenciadas? [s/n]")
                encrypted_msg_b64 = user.recv()
                msg = RSA.Decrypt(self.private_client_key, b64decode(encrypted_msg_b64))

                if msg == "s":
                    user.send(self.secure_data)
                elif msg == "n":
                    user.send("Então tchau!")

                self.del_user(user)
                break

            except Exception as e:
                print(f"{user.IP} foi desconectado.\nErro: {e}")
                self.del_user(user)
                break

if __name__ == "__main__":

    server = API_protect(port=7778)
    server.run()
