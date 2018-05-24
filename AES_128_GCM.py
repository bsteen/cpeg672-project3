from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
import binascii
import os

# Keep track of IVs used to encrypt to detect against "stream cipher" attacks
encrypt_ivs = []

# Keep track of IVs used to decrypt to detect against possible replay attacks
decrypt_ivs = []

# Encrypts plaintext using key with AES-128-GCM; Returns new initialization vector, ciphertext, and MAC of ciphertext
# Meeting the 128 key length req. is managed internally by taking the SHA256 hash of whatever key is provided
def encrypt(plaintext, key):
    # Generates a new, unique IV every encryption
    # initialization_vector (bytes) – Must be unique, a nonce. They do not need to
    # be kept secret and they can be included in a transmitted message. NIST
    # recommends a 96-bit IV length for performance critical situations but it can
    # be up to 2**64 - 1 bits. DO NOT REUSE an initialization_vector with a given key.

    iv = os.urandom(16) # 128 bit iv/nonce
    while (iv in encrypt_ivs) or (iv in decrypt_ivs):   # Make sure not to reuse IV already sent or received
        iv = os.urandom(16)
    encrypt_ivs.append(iv)

    # print("Generated unique IV (16 bytes)")

    # key: The secret key to use in the symmetric cipher. It must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes long.
    # From NIST on GCM: the key size shall be AT LEAST 128 bits
    sha256 = SHA256.new()
    sha256.update(key)
    sha256_key = sha256.digest()
    assert(len(sha256_key) == 16 or len(sha256_key) == 24 or len(sha256_key) == 32), "Key is not 16, 24, or 32 bytes long"

    # print("Ensured key is at least 16 bytes")

    # Used AES-128-GCM
    cipher = AES.new(sha256_key, AES.MODE_GCM, iv)

    # Verify block size is 16 bytes
    assert(AES.block_size == 16), "Block size is not 16 bytes (128 bits)"
    # print("AES-128-GCM in use")

    # Encrypt message and generate GCM MAC
    ciphertext, mac = cipher.encrypt_and_digest(plaintext.encode())

    # print("Plaintext encrypted")

    # Make sure MAC is 16 bytes (128 bits)
    assert(len(mac) == 16), "MAC not 16 bytes (128 bits)"

    return ciphertext, iv, mac

def print_decoded(encoded):
    try:
        plain = encoded.decode()
        print(plain)
    except:
        print("Could not decode text:", encoded)

def decrypt(ciphertext, key, iv, mac):
    # Record all IVs used to decrypt to
    if iv in decrypt_ivs:
        print("IV was already used before! Possible replay attack!")
    else:
        decrypt_ivs.append(iv)

    sha256 = SHA256.new()
    sha256.update(key)
    sha256_key = sha256.digest()

    cipher = AES.new(sha256_key, AES.MODE_GCM, iv)

    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(mac)
        print("Message integrity verified!")
    except ValueError:
        print("WARNING! Authentication error when decoding AES-128-GCM cipher text. Do not trust the decrypted text!")
        
    print("Showing decrypted message: ", end="")
    print_decoded(plaintext)
    
    return plaintext

# # Test GCM MAC feature
# k = "my secret key".encode()
# c, i, m = encrypt("Down, down, down. Would the fall NEVER come to an end!".encode(), k)

# print_decoded(decrypt(c, k, i, m))

# fake_c = b'56658486884684'
# print_decoded(decrypt(fake_c, k, i, m))

# edited_c = c[1:]
# print_decoded(decrypt(edited_c, k, i, m))

# fake_k = b'dsf304d'
# print_decoded(decrypt(c, fake_k, i, m))

# fake_i = b'fsdlafksdfkasdfa'
# print_decoded(decrypt(c, k, fake_i, m))

# # Will be able to decode, but can't trust what it says
# fake_m = b'df8asdfa333sdflkajsd'
# print_decoded(decrypt(c, k, i, fake_m))

# # Test vector for GCM
# k = binascii.unhexlify("feffe9928665731c6d6a8f9467308308")
# iv = binascii.unhexlify("cafebabefacedbaddecaf888")
# p = binascii.unhexlify("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")

# cipher = AES.new(k, AES.MODE_GCM, iv)
# c, m = cipher.encrypt_and_digest(p)

# assert(binascii.hexlify(c) == b"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985")
# assert(binascii.hexlify(m) == b"4d5c2af327cd64a62cf35abd2ba6fab4")