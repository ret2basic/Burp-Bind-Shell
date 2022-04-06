# Burp Bind Shell

This project is made of two major parts:

- `bind_shell.py`
  - An encrypted bind shell implementation that works in Linux/Windows command line.
- `burp_bind_shell.py`
  - A Burp extension that adds GUI to the encrypted bind shell implementation.

### `bind_shell.py`

This bind shell is **encrypted** using AES. If the bind shell is unencrypted, the commands sent over the network can be easily intercepted using a sniffer tool such as Wireshark. For example, when executing the command `id`, Wireshark can only intercept the encrypted data:

![Encrypted Bind Shell](Encrypted_Bind_Shell.png)

### `burp_bind_shell.py`



## Dependencies

### PyCryptodome

Install PyCryptodome:

```shell
pip3 install pycryptodome
```

This is only needed if you wish to run the bind shell from terminal. If you just need the Burp extension, skip this part.

### Jython

Jython is an implementation of the Python programming language designed to run on the Java platform. In Burp, go to "Extender -> Options -> Python Environment -> Select file" and select the `jython-standalone-2.7.2.jar` file in this repo.

The sad thing is PyCryptodome has C code that Jython is not able to translate. For the Burp extension, I had to implement AES on my own.

## Usage

### `bind_shell.py`

In a terminal, start the listener:

```shell
sudo python3 bind_shell.py -l
```

In another terminal, connect to the listener:

```shell
python3 bind_shell.py -c 127.0.0.1
```

### `burp_bind_shell.py`

Open Burp, go to "Extender -> Extensions -> Add", Choose "Extension type: Python" and select `burp_bind_shell.py`. Click "Next".


