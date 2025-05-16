

class User:
    def __init__(self, sock, IP, server):
        self.sock = sock
        self.IP = IP[0]
        self.host = server

    def recv(self):
        return self.sock.recv(self.host.buffer_size).decode('utf8')

    def send(self, msg):
        self.sock.send(msg.encode('utf8'))
