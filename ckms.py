#!/usr/bin/env python3

import socket
from cryptography.fernet import Fernet

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 40008  # Port to listen on (non-privileged ports are > 1023)
fernet: Fernet = Fernet(Fernet.generate_key())

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    while True:
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break

                conn.sendall(fernet._signing_key + b"|" + fernet._encryption_key)
