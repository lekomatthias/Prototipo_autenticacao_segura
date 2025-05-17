
import os
from socket import socket
from base64 import b64encode
from time import sleep

from Client import Client
from RSA import RSA

class Client_server(Client):
    def Verify_response(self, msg):
        if msg == "Autenticação válida.":
            self.server.settimeout(2)
            try:
                token_b64 = self.server.recv(self.buffer_size).decode().strip()
                self.token = token_b64
                print("Token recebido com sucesso!")
            except socket.timeout:
                print("Token não recebido a tempo!")
            finally:
                self.server.settimeout(None)
            self.running = False
        if msg == "Envie seu token.":
            try:
                self.server.send(self.token.encode())
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

    cliente = Client_server()
    cliente.run()
