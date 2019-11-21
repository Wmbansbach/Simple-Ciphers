# An attempt to recreate rudimentary ciphers in python
# Source - Guide to Network Security

class TPSMC:
    def __init__(self):
        pass
    ## Three Position Shift Monoalphabetic Cipher
    def process(self, mode, pt):
        # Input: plaintext-pt, encrypt/decrypt-mode 
        # Output: ciphertext-data
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        data = ""
        for n in pt:
            for i, l in enumerate(alphabet):
                if n == l:
                    if mode == 1:
                        data += alphabet[i + 3]
                    else:
                        data += alphabet[i - 3]
        return data


class TPSPC:
    ## Three Position Shift Polyalphabetic Cipher
    def __init__(self):
        self.alpha = { 0 : "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                       1 : "DEFGHIJKLMNOPQRSTUVWXYZABC",
                       2 : "GHIJKLMNOPQRSTUVWXYZABCDEF",
                       3 : "JKLMNOPQRSTUVWXYZABCDEFGHI",
                       4 : "MNOPQRSTUVWXYZABCDEFGHIJKL" }
    
    def process(self, mode, msg):
        if mode == 1:
            return self.encrypt(msg)
        else:
            return self.decrypt(msg)

            
    def encrypt(self, pt):
        # Input: plaintext-pt
        # Output: ciphertext-data
        data = ""        
        pos = 1
        for p in pt:
            if pos > 4: pos = 1
            for i, l in enumerate(self.alpha[0]):
                if p == l:
                    data += self.alpha[pos][i]
                    pos += 1
        return data

    def decrypt(self, ct):
        # Input: ciphertext
        # Output: plaintext-data
        data = ""
        pos = 1
        for c in ct:
            if pos > 4: pos = 1
            for i, l in enumerate(self.alpha[pos]):
                if c == l:
                    data += self.alpha[0][i]
                    pos += 1
        return data


class PVSC:
    # Polyalphabetic Vigenere Square Cipher #

    def __init__(self):
        self.square = { 0 : "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                       "A": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                       "B": "BCDEFGHIJKLMNOPQRSTUVWXYZA",
                       "C": "CDEFGHIJKLMNOPQRSTUVWXYZAB",
                       "D": "DEFGHIJKLMNOPQRSTUVWXYZABC",
                       "E": "EFGHIJKLMNOPQRSTUVWXYZABCD",
                       "F": "FGHIJKLMNOPQRSTUVWXYZABCDE",
                       "G": "GHIJKLMNOPQRSTUVWXYZABCDEF",
                       "H": "HIJKLMNOPQRSTUVWXYZABCDEFG",
                       "I": "IJKLMNOPQRSTUVWXYZABCDEFGH",
                       "J": "JKLMNOPQRSTUVWXYZABCDEFGHI",
                       "K": "KLMNOPQRSTUVWXYZABCDEFGHIJ",
                       "L": "LMNOPQRSTUVWXYZABCDEFGHIJK",
                       "M": "MNOPQRSTUVWXYZABCDEFGHIJKL",
                       "N": "NOPQRSTUVWXYZABCDEFGHIJKLM",
                       "O": "OPQRSTUVWXYZABCDEFGHIJKLMN",
                       "P": "PQRSTUVWXYZABCDEFGHIJKLMNO",
                       "Q": "QRSTUVWXYZABCDEFGHIJKLMNOP",
                       "R": "RSTUVWXYZABCDEFGHIJKLMNOPQ",
                       "S": "STUVWXYZABCDEFGHIJKLMNOPQR",
                       "T": "TUVWXYZABCDEFGHIJKLMNOPQRS",
                       "U": "UVWXYZABCDEFGHIJKLMNOPQRST",
                       "V": "VWXYZABCDEFGHIJKLMNOPQRSTU",
                       "W": "WXYZABCDEFGHIJKLMNOPQRSTUV",
                       "X": "XYZABCDEFGHIJKLMNOPQRSTUVW",
                       "Y": "YZABCDEFGHIJKLMNOPQRSTUVWX",
                       "Z": "ZABCDEFGHIJKLMNOPQRSTUVWXY"}

    def process(self, mode, msg, k):
        if mode == 1:
            return self.encrypt(msg, k)
        else:
            return self.decrypt(msg, k)

    def encrypt(self, pt, key):
        # Input: Plaintext-pt, Cipher Key-key
        # Ouput: Ciphertext-data
        data = ""
        pos = 0
        for c in pt:
            if pos >= len(key): pos = 0
            for i, v in enumerate(self.square[0]):
                if c == v:
                    data += self.square[key[pos]][i]
                    pos += 1
        return data

    def decrypt(self, ct, key):
        # Input: ciphertext-ct, Cipher Key-key
        # Ouput: plaintext-data
        data = ""
        pos = 0
        
        for c in ct:
            if pos >= len(key): pos = 0
            for i, v in enumerate(self.square[key[pos]]):
                if c == v:
                    data += self.square[0][i]
                    pos += 1
        return data

