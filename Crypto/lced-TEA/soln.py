from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
import colorama
from colorama import Fore, Back, Style


class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [
            b2l(key[i : i + self.BLOCK_SIZE // 16])
            for i in range(0, len(key), self.BLOCK_SIZE // 16)
        ]
        self.DELTA = 0x9E3779B9
        self.IV = iv

    def _xor(self, a, b):
        return b"".join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def decrypt(self, ct):
        blocks = [
            ct[i : i + self.BLOCK_SIZE // 8]
            for i in range(0, len(ct), self.BLOCK_SIZE // 8)
        ]

        pt = b""
        if self.IV:
            X = self.IV
            for ct_block in blocks:
                dec_block = self._xor(X, self.decrypt_block(ct_block))
                pt += dec_block
                X = ct_block
        else:
            for ct_block in blocks:
                pt += self.decrypt_block(ct_block)

        return unpad(pt, self.BLOCK_SIZE // 8)

    def decrypt_block(self, ct_block):
        m0 = b2l(ct_block[:4])
        m1 = b2l(ct_block[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE // 2)) - 1

        s = (self.DELTA * 32) & msk
        for i in range(32):
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            s -= self.DELTA

        m = ((m0 << (self.BLOCK_SIZE // 2)) + m1) & ((1 << self.BLOCK_SIZE) - 1)
        return l2b(m)


with open("output.txt", "r") as f:
    key_line, ct_line = f.readlines()

key_hex = key_line.split(":")[1].strip()
ct_hex = ct_line.split(":")[1].strip()

KEY = bytes.fromhex(key_hex)
ct = bytes.fromhex(ct_hex)

cipher = Cipher(KEY)
pt = cipher.decrypt(ct)

print(Fore.GREEN, pt.decode())
