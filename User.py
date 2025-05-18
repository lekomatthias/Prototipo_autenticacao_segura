from AES import AES

class User:
    def __init__(self, sock, IP, server):
        self.sock = sock
        self.IP = IP[0]
        self.host = server
        self.aes_key = None

    def recv(self):
        return self.sock.recv(self.host.buffer_size).decode('utf8')

    def send(self, msg):
        self.sock.send(msg.encode('utf8'))

    def recv_bytes(self):
        return self.sock.recv(self.host.buffer_size)

    def send_bytes(self, data):
        self.sock.sendall(data)

    def aes_send(self, msg):
        encrypted = AES.Encrypt(self.aes_key, msg)
        self.send_bytes(encrypted.encode('utf-8'))

    def aes_recv(self):
        encrypted = self.recv_bytes()
        encrypted_str = encrypted.decode('utf-8')
        decrypted = AES.Decrypt(self.aes_key, encrypted_str)
        return decrypted.strip()
