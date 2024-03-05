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
        return (SHA256.new(k.encode('utf-8')).hexdigest()[:16]).encode('utf-8')

    def pad(s):
        return (s + (16 - len(s)%16) * chr(16 - len(s)%16)).encode('utf-8')

    def unpad(s):
        s = s.decode('utf-8')
        return s[:-ord(s[-1])]

    def getBlockSize(n):
        blockSize = 16
        while (n > blockSize):
            blockSize += 16
        return blockSize

    def encrypt(data, k1, k2):
        # create aes and hmac keys
        aes_key = InstantMessenger.sha256Key(k1)
        hmac_key = InstantMessenger.sha256Key(k2)

        # pad data to 16 bytes
        paddedData = (InstantMessenger.pad(data))
        paddedLength = (InstantMessenger.pad(str(len(data))))
        
        # create random initialization vector
        iv = get_random_bytes(16)

        # create AES cipher
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # Ek1(len(m))
        ciphertextlength = cipher.encrypt(paddedLength)

        # Ek1(m)
        ciphertext = cipher.encrypt(paddedData)

        # HMACk2(iv + Ek1(len(m)))
        hmacIvLen = HMAC.new(hmac_key, msg=(iv + ciphertextlength), digestmod=SHA256).digest()

        # HMACk2(Ek1(m))
        hmacM = HMAC.new(hmac_key, msg=ciphertext, digestmod=SHA256).digest()

        '''
        print(b'iv: ' + iv)
        print('iv length: ' + str(len(iv)))
        
        print(b'length encrypted: ' + ciphertextlength)
        print('length encrypted length: ' + str(len(ciphertextlength)))
        
        print(b'hmacIvLen: ' + hmacIvLen)
        print('hmacIvLen length: ' + str(len(hmacIvLen)))

        print(b'ciphertext: ' + ciphertext)
        print("ciphertext length: " + str(len(ciphertext)))

        print(b'hmacM: ' + hmacM)
        print('hmacM length: ' + str(len(hmacM)))
        '''
        
        # iv + Ek1(len(m)) + HMACk2(iv + Ek1(len(m))) + Ek1(m) + HMACk2(Ek1(m))
        return iv + ciphertextlength + hmacIvLen + ciphertext + hmacM

    def decrypt(data, k1, k2):       
        # create aes and hmac keys
        aes_key = InstantMessenger.sha256Key(k1)
        hmac_key = InstantMessenger.sha256Key(k2)

        # get IV, Ek1(len(m)), and HMACk2(iv + Ek1(len(m))) from data
        iv = data[:16]
        ciphertextlength = data[16:32]
        hmacIvLen = data[32:64]

        '''
        print(b'iv: ' + iv)
        print('iv length: ' + str(len(iv)))
        
        print(b'length encrypted: ' + ciphertextlength)
        print('length encrypted length: ' + str(len(ciphertextlength)))
        
        print(b'hmacIvLen: ' + hmacIvLen)
        print('hmacIvLen length: ' + str(len(hmacIvLen)))
        '''
        
        try:
            # verify HMACk2(iv + Ek1(len(m)))
            hmac = HMAC.new(hmac_key, digestmod=SHA256)
            hmac.update(iv + ciphertextlength).verify(hmacIvLen)
        except ValueError:
            sys.stdout.write("ERROR: HMAC verification failed")
            sys.exit(1)

        # create AES cipher
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # decrypt Ek1(len(m))
        length = InstantMessenger.unpad(cipher.decrypt(ciphertextlength))
        ciphertextlength = InstantMessenger.getBlockSize(int(length))
        cEndIndex = 64 + ciphertextlength

        # get Ek1(m) and HMACk2(Ek1(m)) from data
        ciphertext = data[64:cEndIndex]
        hmacM = data[cEndIndex:cEndIndex+32]

        '''
        print(b'ciphertext: ' + ciphertext)
        print("ciphertext length: " + str(len(ciphertext)))

        print(b'hmacM: ' + hmacM)
        print('hmacM length: ' + str(len(hmacM)))
        '''
        
        try:
            # verify HMACk2(Ek1(m))
            hmac = HMAC.new(hmac_key, digestmod=SHA256)
            hmac.update(ciphertext).verify(hmacM)
        except ValueError:
            sys.stdout.write("ERROR: HMAC verification failed")
            sys.exit(1)

        # decrypt Ek1(m)
        plaintext = InstantMessenger.unpad(cipher.decrypt(ciphertext))
        
        return plaintext

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
