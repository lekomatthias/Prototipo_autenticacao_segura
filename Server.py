from socket import AF_INET, socket, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, gethostbyname, gethostname
from cryptography.hazmat.primitives import serialization
from threading import Thread
from base64 import b64decode

from User import User
from DataBase import DataBase
from RSA import RSA

class Server:

    def __init__(self, port, buffer_size=4096, data_base_name="dados.db"):
        self.socket = None
        self.thread = None
        self.IP = None
        self.users = []
        self.port = port
        self.buffer_size = buffer_size
        self.running = False

        self.data_base = DataBase(data_base_name)
        self.private_client_key, self.public_client_key = RSA.KeyGen()
        self.server_key_name = "Chave_publica_servidores.pem"

    def client_command(self, user):
        while self.running:
            try:
                user.aes_send("Servidor base rodando, esperando 'exit' para sair...")
                msg = user.aes_recv()
                if msg.lower() == "exit": break
            except Exception as e:
                print(f"{user.IP} foi desconectado.\nErro: {e}")
                self.del_user(user)
                break

    def Switch_key(self, user):
        public_pem = self.public_client_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        user.send(public_pem.decode())

        encrypted_aes_key = b64decode(user.recv())
        aes_key_hex_str = RSA.Decrypt(self.private_client_key, encrypted_aes_key)

        user.aes_key = bytes.fromhex(aes_key_hex_str)
        print(f"Chave AES configurada para o usuário {user.IP}")

    def listen_conect(self):
        while self.running:
            try:
                client, client_IP = self.socket.accept()
                user = User(client, client_IP, self)
                self.users.append(user)
                print(f"{user.IP} se conectou. Total de usuários: {len(self.users)}")
                
                self.Switch_key(user)
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

    server = Server(port=6668)
    server.run()