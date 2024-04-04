import argparse
import binascii
import select
import socket
import sys
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# HOST = '127.0.0.1'
PORT = 9998

def gen_key():
    # generate 4096 bit RSA key pair
    key = RSA.generate(4096)

    # save public key
    with open("mypubkey.pem", "wb") as public_f:
        pubkey_pem = key.publickey().export_key()
        public_f.write(pubkey_pem)

    # save private key
    with open("myprivatekey.pem", "wb") as private_f:
        privatekey_pem = key.export_key()
        private_f.write(privatekey_pem)

def pad(num):
    return '0' * (4-len(str(num))) + str(num)

def run_client(hostname, message): 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, PORT))

    # compute message signature
    key = RSA.import_key(open('myprivatekey.pem').read())
    h = SHA256.new(message.encode('utf8'))
    signature = pkcs1_15.new(key).sign(h)
    signature_hex = binascii.hexlify(signature)

    # send message to server
    s.send(pad(len(message)).encode('utf8') + message.encode('utf8') + pad(len(signature_hex)).encode('utf8') + signature_hex)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--genkey', action='store_true')
    parser.add_argument('--client', '--c') # Requires str
    parser.add_argument('--message', '--m') # Requires str

    args = parser.parse_args()

    if args.genkey:
        gen_key()
    elif args.client:
        if args.client == "":
            raise Exception("--c flag requires a hostname argument")
        else:
            run_client(args.client, args.message)

if __name__ == '__main__':
    main()
