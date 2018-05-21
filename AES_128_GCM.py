from Crypto.Cipher import AES
from Crypto.Hash import SHA256
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
    while (iv in encrypt_ivs) or (iv in decrypt_ivs):   # Make sure not to resuse IV already sent or recieved
        iv = os.urandom(16)
    encrypt_ivs.append(iv)

    print("Generated unique IV (16 bytes)")

    # key: The secret key to use in the symmetric cipher. It must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes long.
    # From NIST on GCM: the key size shall be AT LEAST 128 bits
    sha256 = SHA256.new()
    sha256.update(key)      # Caller of encrypt must handle any needed encoding of key before hashing
    sha256_key = sha256.digest()
    assert(len(sha256_key) == 16 or len(sha256_key) == 24 or len(sha256_key) == 32), "Key is not 16, 24, or 32 bytes long"

    print("Ensured key is at least 16 bytes")

    # Used AES-128-GCM
    cipher = AES.new(sha256_key, AES.MODE_GCM, iv)

    # Verify block size is 16 bytes
    assert(AES.block_size == 16), "Block size is not 16 bytes (128 bits)"
    assert(cipher.mode == AES.MODE_GCM), "Not using GCM mode"
    print("AES-128-GCM in use")

    # Encrypt message and generate GCM MAC
    ciphertext, mac = cipher.encrypt_and_digest(plaintext)

    print("Plaintext encrypted")

    # Make sure MAC is 16 bytes (128 bits)
    assert(len(mac) == 16), "MAC not 16 bytes"

    return ciphertext, iv, mac


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
        print("WARNING! Authentication error when decoding AES-128-GCM ciphertext. The key, IV, and/or MAC was invalid.")

    return plaintext


def print_decoded(encoded):
    try:
        plain = encoded.decode()
        print(plain)
    except:
        print("Could not decode text:", encoded)
    print()

# # Test GCM
# k = "my secret key".encode()
# c, i, m = encrypt("Down, down, down. Would the fall NEVER come to an end!", k)

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