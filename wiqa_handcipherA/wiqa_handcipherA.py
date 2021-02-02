# WIQA Hand Cipher

class WIQAHCA:
    def keysetup(self, key):
        k = [0] * len(key)
        j = 0
        for c, byte in enumerate(key):
            k[c] = (k[c] + (ord(byte) - 65)) % 26
            j = (j + (ord(byte) - 65)) % 26
        return k, j

    def encrypt(self, chars, key):
        ctxt = []
        c = 0
        k, j = self.keysetup(key)
        for char in chars:
            j = k[j]
            k[j] = (k[j] - k[c]) % 26
            output = (k[j] + k[k[j]]) % 26
            sub = ((ord(char) - 65) + output) % 26
            ctxt.append(chr(sub + 65))
            c = (c + 1) % 26
        return "".join(ctxt)
    
    def decrypt(self, chars, key):
        ctxt = []
        c = 0
        k, j = self.keysetup(key)
        for char in chars:
            j = k[j]
            k[j] = (k[c] - k[j]) % 26
            output = (k[j] + k[k[j]]) % 26
            sub = (output + (ord(char) - 65)) % 26
            ctxt.append(chr(sub + 65))
            c = (c + 1) % 26
        return "".join(ctxt)
