from socket import AF_INET, socket, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, gethostbyname, gethostname
from threading import Thread
from cryptography.hazmat.primitives import serialization
from base64 import b64decode
from time import time, sleep

from Server_user import User
from DataBase import DataBase
from RSA import RSA
from JWT import JWT

class Server:
    def __init__(self):
        self.socket = None
        self.thread = None
        self.IP = None
        self.users = []
        self.port = 6668
        self.buffer_size = 4096
        self.running = False

        self.data_base = DataBase("dados.db")
        self.private_client_key, self.public_client_key = RSA.KeyGen()
        self.private_server_key, self.public_server_key = RSA.KeyGen()

    def listen_conect(self):
        while self.running:
            try:
                client, client_IP = self.socket.accept()
                user = User(client, client_IP, self)
                self.users.append(user)
                print(f"{user.IP} se conectou. Total de usuários: {len(self.users)}")
                Thread(target=self.client_command, args=(user,)).start()
            except Exception as e:
                print("Erro ao aceitar conexão:", e)
                break

    def del_user(self, user):
        if user in self.users:
            self.users.remove(user)
        try:
            user.sock.close()
        except:
            pass
        print(f"{user.IP} foi removido. Total de usuários: {len(self.users)}")

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

    def shutdown(self):
        print("Encerrando servidor...")
        self.running = False
        for user in self.users:
            try:
                user.sock.close()
            except:
                pass
        try:
            self.socket.close()
        except:
            pass
        print("Servidor encerrado.")

    def run(self):
        try:
            self.IP = gethostbyname(gethostname())
            print("O IP que hospedará o servidor é:", self.IP)

            self.socket = socket(AF_INET, SOCK_STREAM)
            self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self.socket.bind((self.IP, self.port))
            self.socket.listen(10)

            self.running = True
            print("Servidor iniciado e aguardando conexões...")

            self.thread = Thread(target=self.listen_conect)
            self.thread.start()

            while self.running:
                cmd = input()
                if cmd.strip().lower() == "exit":
                    self.shutdown()
                    break

        except Exception as e:
            print("Erro na hospedagem do servidor:", e)

if __name__ == "__main__":

    server = Server()
    server.run()
