import argparse
import socket
import select
import sys

class Server():
    def __init__(self, host='', port=9999):
        self.PORT = port
        self.HOST = host
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
    def run(self):
        self.s.bind((self.HOST, self.PORT))
        self.s.listen(10)
        new_conn, addr = self.s.accept()
        InstantMessenger.message(new_conn)
        
class Client():
    def __init__(self, host='', port=9999):
        self.PORT = port
        self.HOST = host
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        self.s.connect((self.HOST, self.PORT))
        InstantMessenger.message(self.s)
        
class InstantMessenger():
    def message(s):
        try:
            while True:
                read_list = [s] + [sys.stdin]
                (ready_read, _, _) = select.select(read_list, [], [])
                
                for sock in ready_read:
                    if sock is s:
                        data = sock.recv(1024)
                        if data:
                            sys.stdout.write(data.decode('utf-8'))
                            sys.stdout.flush()
                    else:
                        m = sys.stdin.readline()
                        s.send(m.encode('utf-8'))
        except KeyboardInterrupt:
            s.close()      

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--s', dest='server', action='store_true')
    parser.add_argument('--c', dest='hostname')
    args = parser.parse_args()

    if args.server:
        server = Server()
        server.run()
    else:
        client = Client()
        client.run()
