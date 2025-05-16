from socket import AF_INET, socket, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, gethostbyname, gethostname
from threading import Thread
from Server_user import User

class Server:
    def __init__(self):
        self.socket = None
        self.thread = None
        self.IP = None
        self.users = []
        self.port = 7778
        self.buffer_size = 500
        self.running = False

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
        while self.running:
            try:
                msg = user.recv()
                if not msg:
                    raise ConnectionResetError
                user.send(f"mensagem do servidor protegido: {msg}")

            except Exception:
                print(f"{user.IP} foi desconectado.")
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


if __name__ == "__main__":

    server = Server()
    server.run()
