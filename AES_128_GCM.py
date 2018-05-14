from Crypto.Cipher import AES
import binascii


# Do not reuse the same IV for a given key
block_size = AES.block_size
iv = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")

key = "andy love simone"

cipher = AES.new(key, AES.MODE_GCM, iv)
encrypted = cipher.encrypt("abcdefghijklmnopqrstuvwxyzabcdef".encode())

print(binascii.hexlify(encrypted))