
from time import time, sleep

from Server import Server
from RSA import RSA
from JWT import JWT

class API_autentication(Server):
    def __init__(self, port, buffer_size=4096, data_base_name="dados.db"):
        super().__init__(port=port, 
                         buffer_size=buffer_size, 
                         data_base_name=data_base_name)
        self.private_server_key, self.public_server_key = RSA.KeyGen()
        RSA.SaveKey(self.public_server_key, self.server_key_name)

    def client_command(self, user):
        sleep(0.1)

        while self.running:
            try:
                user.aes_send("Digite o usuário:")
                username = user.aes_recv()

                user.aes_send("Digite a senha:")
                password = user.aes_recv()

                if not self.data_base.check(username, password):
                    user.aes_send("Usuário ou senha inválido.")
                    continue

                user.aes_send("Autenticação válida.")
                print(f"{user.IP} foi autenticado.")
                payload = {
                    "user_id": str(user.IP),
                    "exp": int(time()) + 300
                }
                token = JWT.create_jwt(payload, self.private_server_key)
                user.aes_send(token)

                self.del_user(user)
                break

            except Exception as e:
                print(f"{user.IP} foi desconectado.\nErro: {e}")
                self.del_user(user)
                break

if __name__ == "__main__":

    server = API_autentication(port=6668)
    server.run()
