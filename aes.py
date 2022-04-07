def _string_to_bytes(text):
    return list(ord(c) for c in text)

def _bytes_to_string(binary):
    return "".join(chr(b) for b in binary)

class AES:
    def __init__(self):
        self.key = '423F4528472B4B6250655368566D5971'.decode('hex')
        self.N_ROUNDS = 10
        # Learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
        self.xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

        # Customized padding scheme
        self.lookup_table = {
            1 : '1',
            2 : '2',
            3 : '3',
            4 : '4',
            5 : '5',
            6 : '6',
            7 : '7',
            8 : '8',
            9 : '9',
            10 : 'a',
            11 : 'b',
            12 : 'c',
            13 : 'd',
            14 : 'e',
            15 : 'f',
            16 : 'x',
        }

        # Customized unpadding scheme
        self.reverse_lookup_table = {
            '1' : 1,
            '2' : 2,
            '3' : 3,
            '4' : 4,
            '5' : 5,
            '6' : 6,
            '7' : 7,
            '8' : 8,
            '9' : 9,
            'a' : 10,
            'b' : 11,
            'c' : 12,
            'd' : 13,
            'e' : 14,
            'f' : 15,
            'x' : 16,
        }

        self.s_box = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )
        self.inv_s_box = (
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
        )

    #--------Structure of AES--------#

    def bytes2matrix(self, text):
        # Converts a 16-byte array into a 4x4 matrix.
        text = _string_to_bytes(text)
        return [text[i:i+4] for i in range(0, len(text), 4)]


    def matrix2bytes(self, matrix):
        # Converts a 4x4 matrix into a 16-byte array.
        return _bytes_to_string(sum(matrix, []))


    #--------Round Keys--------#


    def add_round_key(self, s, k):
        return [[sss ^ kkk for sss, kkk in zip(ss, kk)] for ss, kk in zip(s, k)]


    #--------Confusion through Substitution--------#


    def sub_bytes(self, s):
        return [[self.s_box[entry] for entry in row] for row in s]


    def inv_sub_bytes(self, s):
        return [[self.inv_s_box[entry] for entry in row] for row in s]


    #--------Diffusion through Permutation--------#


    def shift_rows(self, s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


    def inv_shift_rows(self, s):
        s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
        s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
        s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]


    # Learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
    xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


    def mix_single_column(self, a):
        # See Sec 4.1.2 in The Design of Rijndael
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ self.xtime(a[0] ^ a[1])
        a[1] ^= t ^ self.xtime(a[1] ^ a[2])
        a[2] ^= t ^ self.xtime(a[2] ^ a[3])
        a[3] ^= t ^ self.xtime(a[3] ^ u)

    def mix_columns(self, s):
        for i in range(4):
            self.mix_single_column(s[i])

    def inv_mix_columns(self, s):
        # see Sec 4.1.3 in The Design of Rijndael
        for i in range(4):
            u = self.xtime(self.xtime(s[i][0] ^ s[i][2]))
            v = self.xtime(self.xtime(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v

        self.mix_columns(s)


    #--------Bringing It All Together--------#


    def expand_key(self, master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        """

        # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
        r_con = (
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
            0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
            0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
        )

        # Initialize round keys with raw key material.
        key_columns = self.bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        # Each iteration has exactly as many columns as the key material.
        counter = 1
        while len(key_columns) < (self.N_ROUNDS + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [self.s_box[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[counter]
                counter += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [self.s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = [i^j for i, j in zip(word, key_columns[-iteration_size])]
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def pad(self, text):
        """Customized padding scheme."""

        padding_length = 16 - (len(text) % 16)
        padding = self.lookup_table[padding_length]
        result = text + padding * padding_length

        return result

    def unpad(self, text):
        """Customized unpadding scheme."""

        padding = text[-1]
        padding_length = self.reverse_lookup_table[padding]
        result = text[:-padding_length]

        return result

    def encrypt_one_block(self, plaintext):
        """AES encryption with customized padding scheme."""

        state = self.bytes2matrix(plaintext)
        
        round_keys = self.expand_key(self.key)
        state = self.add_round_key(state, round_keys[0])

        # Only loops for self.N_ROUNDS - 1 times.
        for i in range(1, self.N_ROUNDS):
            state = self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            state = self.add_round_key(state, round_keys[i])

        # The last round does not include the MixColumns step.
        state = self.sub_bytes(state)
        self.shift_rows(state)
        state = self.add_round_key(state, round_keys[-1])

        ciphertext = self.matrix2bytes(state)

        return ciphertext

    def decrypt_one_block(self, ciphertext):
        """AES decryption with customized unpadding scheme."""

        # Convert ciphertext to state matrix
        state = self.bytes2matrix(ciphertext)

        round_keys = self.expand_key(self.key)
        # Remember to start from the last round key and work backwards through them when decrypting
        state = self.add_round_key(state, round_keys[self.N_ROUNDS])

        for i in range(self.N_ROUNDS - 1, 0, -1):
            self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, round_keys[i])
            self.inv_mix_columns(state)
    
        # The final round does not include the InvMixColumns step.
        self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, round_keys[0])

        # Convert state matrix to plaintext
        plaintext = self.matrix2bytes(state)

        return plaintext

    def encrypt(self, plaintext):
        """Encrypt blocks one after another."""

        plaintext = self.pad(plaintext)
        num_of_blocks = len(plaintext) // 16

        ciphertext = ""
        for i in range(num_of_blocks):
            plaintext_block = plaintext[i*16:(i+1)*16]
            ciphertext += self.encrypt_one_block(plaintext_block)

        ciphertext = ciphertext.encode('hex')
        
        return ciphertext


    def decrypt(self, ciphertext):
        """Decrypt blocks one after another."""

        ciphertext = ciphertext.decode('hex')
        num_of_blocks = len(ciphertext) // 16

        plaintext = ""
        for i in range(num_of_blocks):
            ciphertext_block = ciphertext[i*16:(i+1)*16]
            plaintext += self.decrypt_one_block(ciphertext_block)

        plaintext = self.unpad(plaintext)
        
        return plaintext

    def test(self):
        # plaintext = 'ctf{this_is_a_flag}'
        plaintext = 'whoami'
        encrypted = self.encrypt(plaintext)
        print "encrypted: {}".format(encrypted)
        decrypted = self.decrypt(encrypted)
        print "decrypted: {}".format(decrypted)

if __name__ == '__main__':
    aes = AES()
    aes.test()
