from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class AESCipher:
    def __init__(self):
        # CHANGEME: Generate your own AES-128 key (32 random bytes)
        # For example, you can use:
        # https://www.allkeysgenerator.com/Random/Security-Encryption-Key-Generator.aspx
        self.key = bytes.fromhex('423F4528472B4B6250655368566D5971')
        self.cipher = AES.new(self.key, AES.MODE_ECB)
    
    def encrypt(self, plaintext):
        return self.cipher.encrypt(pad(plaintext, AES.block_size)).hex()

    def decrypt(self, encrypted):
        return unpad(self.cipher.decrypt(bytearray.fromhex(encrypted)), AES.block_size)

    def __str__(self):
        return "Key: {}".format(self.key.hex())

    def test(self):
        plaintext = b'1337'
        print(self.encrypt(plaintext))

if __name__ == '__main__':
    aes = AESCipher()
    aes.test()
