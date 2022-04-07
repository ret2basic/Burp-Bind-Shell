from burp import IBurpExtender, ITab
from javax import swing
from java.awt import BorderLayout
from exceptions_fix import FixBurpExceptions

import time
import socket
import threading
import sys

from aes import AES

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.aes = AES()
        self.clicked = False
        self.response_data = None
        self.kill_threads = False

        sys.stdout = callbacks.getStdout()
        self.callbacks = callbacks
        self.callbacks.setExtensionName('Bind Shell')
        self.tab = swing.JPanel(BorderLayout())

        text_panel = swing.JPanel()
        vertical_box = swing.Box.createVerticalBox()

        # Add a horizontal box that accepts an IP address
        horizontal_box = swing.Box.createHorizontalBox()
        self.ip_address = swing.JTextArea('', 2, 100)
        self.ip_address.setLineWrap(True)
        self.ip_address.border = swing.BorderFactory.createTitledBorder('IP Address:')
        horizontal_box.add(self.ip_address)
        vertical_box.add(horizontal_box)
        # Add a horizontal box that accepts an user command
        horizontal_box = swing.Box.createHorizontalBox()
        self.user_command = swing.JTextArea('', 2, 100)
        self.user_command.setLineWrap(True)
        self.user_command.border = swing.BorderFactory.createTitledBorder('Command:')
        horizontal_box.add(self.user_command)
        vertical_box.add(horizontal_box)

        # Add a "connect" button
        horizontal_box = swing.Box.createHorizontalBox()
        button_panel = swing.JPanel()

        self.connect_button = swing.JButton('Connect', actionPerformed=self.connect)
        self.send_button = swing.JButton('Send', actionPerformed=self.send)
        self.disconnect_button = swing.JButton('Disconnect', actionPerformed=self.disconnect)

        self.disconnect_button.enabled = False
        self.send_button.enabled = False

        button_panel.add(self.connect_button)
        button_panel.add(self.send_button)
        button_panel.add(self.disconnect_button)

        horizontal_box.add(button_panel)
        vertical_box.add(horizontal_box)

        horizontal_box = swing.Box.createHorizontalBox()
        self.output = swing.JTextArea('', 25, 100)
        self.output.setLineWrap(True)
        self.output.setEditable(False)

        scroll = swing.JScrollPane(self.output)

        horizontal_box.add(scroll)
        vertical_box.add(horizontal_box)

        text_panel.add(vertical_box)
        self.tab.add(text_panel)

        callbacks.addSuiteTab(self)

        return

    def getTabCaption(self):
        return 'Bind Shell'

    def getUiComponent(self):
        return self.tab

    def encrypted_send(self, s, message):
        """Send an AES-encrypted message."""
        encrypted = self.aes.encrypt(message)
        s.send(encrypted)
    
    def send(self, event):
        """"""
        self.clicked = True
        # Hack race condition
        time.sleep(0.5)
        self.output.text = self.response_data

    def send_thread(self):
        while True:
            if self.kill_threads:
                sys.exit()

            if self.clicked:
                self.clicked = False
                self.encrypted_send(self.s, self.user_command.text)

    def recv_thread(self):
        while True:
            if self.kill_threads:
                sys.exit()

            data = self.s.recv(4096)

            if data:
                decrypted = self.aes.decrypt(data.strip()).replace('Enter command>', '')
                self.response_data = decrypted

    def connect(self, event):
        """"""
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect((self.ip_address.text, 443))
            self.kill_threads = False

            threading.Thread(target=self.send_thread).start()
            threading.Thread(target=self.recv_thread).start()

            # Once connected, the user is allowed to:
            # [ ] Press the "Connect" button
            # [x] Press the "Send" button
            # [x] Press the "Disconnect" button
            # [ ] Modify the IP address
            self.connect_button.enabled = False
            self.send_button.enabled = True
            self.disconnect_button.enabled = True
            self.ip_address.enabled = False

            self.output.text = 'Connected to the bind shell.'
        
        except:
            self.output.text = 'Failed to connect to the bind shell.'

    def disconnect(self, event):
        """"""
        self.encrypted_send(self.s, 'exit')
        self.s.close()
        self.kill_threads = True

        # Once disconnected, the user is allowed to:
        # [x] Press the "Connect" button
        # [ ] Press the "Send" button
        # [ ] Press the "Disconnect" button
        # [x] Modify the IP address
        self.connect_button.enabled = True
        self.send_button.enabled = False
        self.disconnect_button.enabled = False
        self.ip_address.enabled = True

        self.output.text = 'Disconnected from the bind shell.'

# https://github.com/securityMB/burp-exceptions
FixBurpExceptions()
