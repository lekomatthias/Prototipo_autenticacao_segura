
import sys
import os
from socket import AF_INET, socket, SOCK_STREAM, gethostbyname, gethostname
from threading import Thread
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from base64 import b64encode

from RSA import RSA

class Client:
    def __init__(self):
        self.server = None
        self.thread = None
        self.port = 6668
        self.buffer_size = 4096
        self.running = False
        self.server_key = None
        self.token = None

    def show_IP_client(self):
        ip_local = gethostbyname(gethostname())
        print(f'O seu IP local é: {ip_local}')

    def recv(self):
        while self.running:
            data = self.server.recv(self.buffer_size)
            if not data:
                print("Conexão encerrada pelo servidor.")
                self.running = False

            try:
                msg = data.decode('utf-8').strip()
                print(msg)
                if msg == "Autenticação válida.":
                    self.server.settimeout(2)
                    try:
                        token_b64 = self.server.recv(self.buffer_size).decode().strip()
                        self.token = token_b64
                        print(f"Token recebido com sucesso!")
                    except socket.timeout:
                        print("Token não recebido a tempo!")
                    finally:
                        self.server.settimeout(None)
                    self.running = False

            except:
                self.running = False

    def connect(self, ip_host):
        try:
            self.server = socket(AF_INET, SOCK_STREAM)
            self.server.connect((ip_host, self.port))
            self.running = True

            # Receber chave pública do servidor
            key_data = self.server.recv(self.buffer_size).decode()
            self.server_key = serialization.load_pem_public_key(
                key_data.encode(),
                backend=default_backend()
            )
            print("Chave pública recebida.")

            self.thread = Thread(target=self.recv)
            self.thread.start()
            print("Conectado ao servidor.")
            return True

        except Exception as e:
            print(f"Não foi possível conectar ao servidor. Erro: {e}")
            return False

    def disconnect(self):
        self.running = False
        if self.server:
            self.server.close()
        if self.thread and self.thread.is_alive():
            self.thread.join()
        print("Desconectado do servidor.")

    def messenger(self):
        while self.running:
            try:
                data = input()
                # ajuste das linhas do terminal
                sys.stdout.write("\033[A")
                sys.stdout.write("\033[K")

                if data.lower() == 'exit':
                    self.disconnect()
                    break

                # Criptografar e enviar com base64
                encrypted = RSA.Encrypt(self.server_key, data)
                encrypted_b64 = b64encode(encrypted)
                self.server.send(encrypted_b64)

            except Exception as e:
                print(f"Erro no envio: {e}")
                self.disconnect()
                break

    def run(self):
        '''Ao rodar quero que a parte do cliente decida qual servidor conectar'''
        
        while True:
            self.show_IP_client()
            server = input("Digite o serviço (ou 'exit' para encerrar):\n1 - Autenticação\n2 - Informação (protegida)\n")
            if server == "1":
                print("Autenticação selecionada.")
                self.port = 6668
                print("Informação selecionada.")
            elif server == "2":
                self.port = 7778
            elif server == "exit":
                break
            else:
                if os.name == 'nt': os.system('cls')
                else: os.system('clear')
                continue

            ip_host = input("Digite o IP do servidor para se conectar (ou 'exit' para encerrar): ")

            if ip_host.lower() == 'exit':
                print("Encerrando o cliente.")
                break

            if self.connect(ip_host):
                self.messenger()

if __name__ == "__main__":

    cliente = Client()
    cliente.run()
