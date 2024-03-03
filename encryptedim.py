import argparse, socket, select, sys
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

class Server():
    def __init__(self, k1, k2, host='', port=9999):
        self.PORT = port
        self.HOST = host
        self.K1 = k1
        self.K2 = k2
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
    def run(self):
        self.s.bind((self.HOST, self.PORT))
        self.s.listen(10)
        new_conn, addr = self.s.accept()
        InstantMessenger.message(new_conn, self.K1, self.K2)
        
class Client():
    def __init__(self, k1, k2, host='', port=9999):
        self.PORT = port
        self.HOST = host
        self.K1 = k1
        self.K2 = k2
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        self.s.connect((self.HOST, self.PORT))
        InstantMessenger.message(self.s, self.K1, self.K2)
        
class InstantMessenger():
    def message(s, k1, k2):
        try:
            while True:
                read_list = [s] + [sys.stdin]
                (ready_read, _, _) = select.select(read_list, [], [])
                
                for sock in ready_read:
                    if sock is s:
                        data = sock.recv(1024)
                        if data:
                            sys.stdout.write(InstantMessenger.decrypt(data, k1, k2))
                            sys.stdout.flush()
                    else:
                        m = sys.stdin.readline()
                        s.send(InstantMessenger.encrypt(m, k1, k2))
        except KeyboardInterrupt:
            s.close()

    def sha256Key(k):
        return SHA256.new(k.encode('utf-8')).hexdigest()[:16]

    def pad(s):
        return s + (16 - len(s)%16) * chr(16 - len(s)%16)

    def unpad(s):
        return s[:-ord(s[-1])]

    def encrypt(data, k1, k2):
        # create aes and hmac keys
        aes_key = InstantMessenger.sha256Key(k1).encode('utf-8')

        # pad data to 16 bytes
        paddedData = (InstantMessenger.pad(data)).encode('utf-8')

        # create random initialization vector
        iv = get_random_bytes(16)

        # create aes cipher
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # Ek1(m)
        ciphertext = cipher.encrypt(paddedData)
        
        return iv + ciphertext

    def decrypt(data, k1, k2):       
        # create aes key
        aes_key = InstantMessenger.sha256Key(k1).encode('utf-8')

        # get IV and ciphertext from data
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        
        return InstantMessenger.unpad(plaintext.decode('utf-8'))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--s', dest='server', action='store_true')
    parser.add_argument('--c', dest='hostname')
    parser.add_argument('--confkey', dest = 'k1') # confidentiality key
    parser.add_argument('--authkey', dest = 'k2') # authentication key

    args = parser.parse_args()

    if args.server:
        server = Server(args.k1, args.k2)
        server.run()
    else:
        client = Client(args.k1, args.k2)
        client.run()
