
import os
from socket import socket

from Client import Client
from AES import AES

class Client_API(Client):
    def Verify_response(self, msg):
        if msg == "Autenticação válida.":
            self.server.settimeout(2)
            try:
                data = self.server.recv(self.buffer_size)
                encrypted_token_str = data.decode('utf-8')
                self.token = AES.Decrypt(self.simetric_key, encrypted_token_str)
                print(f"Token recebido com sucesso!")
            except socket.timeout:
                print("Token não recebido a tempo!")
            finally:
                self.server.settimeout(None)
            self.running = False
        if msg == "Envie seu token.":
            try:
                self.server.send(AES.Encrypt(self.simetric_key, self.token).encode('utf-8'))
                print("Token enviado ao servidor.")
            except Exception as e:
                print(f"Erro ao criptografar/enviar o token: {e}")
        else:
            print(msg)

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

    cliente = Client_API()
    cliente.run()
