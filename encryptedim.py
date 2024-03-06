import argparse, socket, select, sys
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# HOST = '127.0.0.1'
PORT = 9999

def run_server(k1, k2):
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind(('', PORT))
    listen_socket.listen()
    client_sockets = []

    while True:
        read_list = [listen_socket] + client_sockets + [sys.stdin]
        (ready_read, _, _) = select.select(read_list, [], [])

        for sock in ready_read:
            if sock is listen_socket:
                new_conn, addr = sock.accept()
                client_sockets.append(new_conn)
            elif sock is sys.stdin:
                input = sys.stdin.readline()
                if not input:
                    listen_socket.close()
                    for c in client_sockets :
                        c.close()
                    return
                for c in client_sockets:
                    c.sendall(encrypt(input, k1, k2))
            else:
                data = sock.recv(4096)
                if data != b'':
                    sys.stdout.write(decrypt(data, k1, k2))
                    sys.stdout.flush()
                else:
                    client_sockets.remove(sock)
                    sock.close()

def run_client(hostname, k1, k2):
    conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn_sock.connect((hostname, PORT))

    while True:
        input_list = [conn_sock, sys.stdin]
        try:
            (ready_read, _, _) = select.select(input_list, [], [])
        except ValueError:
            break

        for sock in ready_read:
            if sock is conn_sock:
                data = sock.recv(4096)
                if data:
                    sys.stdout.write(decrypt(data, k1, k2))
                    sys.stdout.flush()
                else:
                    sock.close()
            elif sock is sys.stdin:
                input = sys.stdin.readline()
                if not input:
                    conn_sock.close()
                    return
                conn_sock.sendall(encrypt(input, k1, k2))

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
    aes_key = sha256Key(k1)
    hmac_key = sha256Key(k2)

    # pad data to 16 bytes
    paddedData = pad(data)
    paddedLength = pad(str(len(data)))
    
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
    aes_key = sha256Key(k1)
    hmac_key = sha256Key(k2)
    
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
    length = unpad(cipher.decrypt(ciphertextlength))
    ciphertextlength = getBlockSize(int(length))
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
    plaintext = unpad(cipher.decrypt(ciphertext))
    
    return plaintext

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', '--s', action='store_true')
    parser.add_argument('--client', '--c') # Requires str
    parser.add_argument('--confkey', dest = 'k1') # confidentiality key
    parser.add_argument('--authkey', dest = 'k2') # authentication key

    args = parser.parse_args()

    if args.server:
        run_server(args.k1, args.k2)
    elif args.client:
        if args.client == "":
            raise Exception("--c flag requires a hostname argument")
        else:
            run_client(args.client, args.k1, args.k2)

if __name__ == '__main__':
    main()
