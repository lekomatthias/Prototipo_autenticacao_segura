
import sys
from socket import AF_INET, socket, SOCK_STREAM, gethostbyname, gethostname
from threading import Thread
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from base64 import b64encode

from RSA import RSA
from AES import AES

class Client:
    def __init__(self):
        self.server = None
        self.thread = None
        self.port = 6668
        self.buffer_size = 4096
        self.running = False
        self.server_key = None
        self.token = "token"
        self.simetric_key = AES.Generate_key()

    def show_IP_client(self):
        ip_local = gethostbyname(gethostname())
        print(f'O seu IP local é: {ip_local}')

    def Verify_response(self, msg):
            print(msg)

    def Switch_key(self):
        key_data = self.server.recv(self.buffer_size)
        self.server_key = serialization.load_pem_public_key(
            key_data,
            backend=default_backend())

        simetric_key_str = self.simetric_key.hex()
        encrypted_key = RSA.Encrypt(self.server_key, simetric_key_str)

        encrypted_key_b64 = b64encode(encrypted_key)
        self.server.send(encrypted_key_b64)

    def recv(self):
        while self.running:
            data = self.server.recv(self.buffer_size)
            if not data:
                print("Conexão encerrada pelo servidor.")
                self.running = False
                break

            try:
                encrypted = data.decode('utf-8').strip()
                decrypted = AES.Decrypt(self.simetric_key, encrypted)
                self.Verify_response(decrypted)

            except Exception as e:
                print(f"Erro em recv: {e}")
                self.running = False

    def connect(self, ip_host):
        try:
            self.server = socket(AF_INET, SOCK_STREAM)
            self.server.connect((ip_host, self.port))
            self.running = True

            self.Switch_key()
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
                # ajuste de linhas no terminal
                sys.stdout.write("\033[A")
                sys.stdout.write("\033[K")

                if data.lower() == 'exit':
                    self.disconnect()
                    break

                encrypted = AES.Encrypt(self.simetric_key, data)
                self.server.send(encrypted.encode('utf-8'))

            except Exception as e:
                print(f"Erro no envio: {e}")
                self.disconnect()
                break

    def run(self):
        '''Ao rodar quero que a parte do cliente decida qual servidor conectar'''
        
        while True:
            msg = input("Client básico rodando, envie 'exit' para sair.")
            if msg == "exit": break

if __name__ == "__main__":

    client = Client()
    client.run()
