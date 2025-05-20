
from time import sleep

from Server import Server
from RSA import RSA
from JWT import JWT
from HMAC import JWT_HS256 as JWTH

class API_protect(Server):

    def __init__(self, port, buffer_size=4096, data_base_name="dados_seguros.db", hmac=False):
        super().__init__(port=port, 
                       buffer_size=buffer_size, 
                       data_base_name=data_base_name)
        self.secure_data = "__dados_seguros_do_servidos__"
        self.public_server_key = None
        self.hmac=hmac

    def Token_validation(self, user):
        user.aes_send("Validando o token...")
        user.aes_send("Envie seu token.")
        token = user.aes_recv()

        if not self.hmac:
            self.public_server_key = RSA.LoadKey(self.server_key_name)
            verifyed = JWT.verify_jwt(token, self.public_server_key)
        else:
            secret = b"Troque-por-32-bytes-aleatorios-&-secretos"
            verifyed = JWTH.verify_jwt(token, secret)
        if not verifyed:
            user.aes_send("Token inválido ou expirado.")
            user.aes_send("Tente acessar o servidor de autenticação entes deste.")
            self.del_user(user)
            return
        user.aes_send("Token validado com sucesso!")

    def client_command(self, user):
        self.Token_validation(user)
        sleep(0.1)

        while self.running:
            try:
                user.aes_send("Deseja obter umas infos diferenciadas? [s/n]")
                msg = user.aes_recv()

                if msg == "s":
                    user.aes_send(self.secure_data)
                elif msg == "n":
                    user.aes_send("Então tchau!")
                else:
                    user.aes_send("Opção inválida!")
                    continue

                sleep(0.2)
                self.del_user(user)
                break

            except Exception as e:
                print(f"{user.IP} foi desconectado.\nErro: {e}")
                self.del_user(user)
                break

if __name__ == "__main__":

    print("O servidor será usado com hmac ou assinarura RSA?")
    print("1 - HMAC")
    print("2 - Assinatura RSA")
    hmac = True if input() == "1" else False
    server = API_protect(port=7778, hmac=hmac)
    server.run()
