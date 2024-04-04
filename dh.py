import argparse, socket, select, sys, secrets
from Crypto.Random import random

# HOST = '127.0.0.1'
PORT = 9999
g = 2
p = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b


def run_server():
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind(('', PORT))
    listen_socket.listen()
    client_sockets = []

    # choose a number b uniformly at random from the range [1, p)
    b = random.randint(0, p)
    
    # compute B
    B = pow(g, b, p)
    
    read_list = [listen_socket] + client_sockets
    (ready_read, _, _) = select.select(read_list, [], [])

    for sock in ready_read:
        if sock is listen_socket:
            conn, addr = sock.accept()
            client_sockets.append(conn)
            conn.send(bytes(str(B) + '\n','utf8'))

            data = conn.recv(1024)
            if data:
                # get A from client
                A = int(data)

    # compute K
    K = pow(A, b, p)
    sys.stdout.write(str(K))

    for sock in ready_read:
        if sock is not listen_socket:
            client_sockets.remove(sock)
            sock.close()

def run_client(hostname):
    conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn_sock.connect((hostname, PORT))

    # choose a number a uniformly at random from the range [1, p)
    a = random.randint(0, p)
    
    # compute A
    A = pow(g, a, p)

    # send A to server
    conn_sock.send(bytes(str(A) + '\n','utf8'))

    # get B from server
    data = conn_sock.recv(1024)
    B = int(data)
    
    # compute K
    K = pow(B, a, p)
    sys.stdout.write(str(K))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', '--s', action='store_true')
    parser.add_argument('--client', '--c') # Requires str

    args = parser.parse_args()

    if args.server:
        run_server()
    elif args.client:
        if args.client == "":
            raise Exception("--c flag requires a hostname argument")
        else:
            run_client(args.client)

if __name__ == '__main__':
    main()
