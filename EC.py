import os
from Cryptodome.Random import random as crypto_random
from Cryptodome.Hash import SHA256
from fractions import gcd

# Contains all the functions for elliptic curve operations used in *_exchange.py
# Since we are using AES-128, the equivalent security in EC would be at least 256 bits
# Use secp256k1 or secp384r1 (seems to work better) elliptic curve

# ECDHE Steps:
# P is the GENERATOR
# Alice picks a secret key a∈Zq\0
# Alice computes her (ephemeral) public key aP which she sends to Bob.
# Bob picks a secret key b∈Zq\0
# Bob computes his (ephemeral) public key bP which he sends to Alice.
# Bob computes b*aP, Alice computes a*bP, now they both know the shared secret.
# Hash that (Use the x-coordinate only!!! Hash the hex representation of that x-coordinate with SHA-256) and switch to AES

# Used for reading in key files
def h2i(hexLines):
    if (hexLines == ''):
        return 0
    return int(hexLines.replace(' ','').replace(':',''), 16)

# Used for reading in key files
def splitPoint(hexLines):
    gen=hexLines.replace(' ','').replace(':','')[2:]
    gl=len(gen)//2
    return (int(gen[:gl],16), int(gen[gl:], 16))

# Invert a point across the y-axis
def invert_point(P, prime):
    if P[0] == None:
        return (None, None)

    return (P[0], -P[1] % prime)

# Used by point_multiply: Add two points on an elliptic curve
# Q == P: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_doubling
# Else: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
def point_add(Q, P, prime, a):
    if P[0] == None:
        return Q
    if Q[0] == None:
        return P
    if Q == invert_point(P, prime):
        return (None, None)

    if P == Q:
        s = ((3*P[0]**2 + a) * pow(2*P[1], prime - 2 , prime)) % prime
    else:
        s = ((Q[1] - P[1]) * pow(Q[0] - P[0], prime - 2, prime)) % prime

    x_r = (s**2 - P[0] - Q[0]) % prime
    y_r = (s * (P[0] - x_r) - P[1]) % prime
    return (x_r, y_r)

# Point multiplication along an elliptic curve
# Double-and-add method: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
def point_multiply(point, generator, prime, a):
    N = generator
    Q = (None, None)
    binary_point = bin(point)[2:]  # Don't count the "0b" at the start
    m = len(binary_point)

    for i in range(m):
        if(binary_point[i] == "1"):
            Q = point_add(Q, N, prime, a)
        N = point_add(N, N, prime, a)
    return Q

# Read in parameters of EC
def read_paramters(hostname, ec_type):
    file = open("certs/%s_%s_params.txt" % (hostname, ec_type),'r')
    lines = file.readlines()
    file.close()

    params = {}
    currentHex=''
    currentParam=''
    ecpoints=["Gener", "pub"]
    for line in lines:
        if line[0].isalpha():
            if (currentHex != '' and currentParam != ''):
                # print("key:",currentParam)
                if not currentParam in ecpoints:
                    params[currentParam]=h2i(currentHex)
                else:
                    params[currentParam]=splitPoint(currentHex)
            currentParam = line.strip().replace(':','')[:5]
            currentHex=''
        else:
            currentHex+=line.strip()
    # print(params) # Useful printout when exporting to Sage
    return params

# Generate private and public keys for ECDHE
def gen_ECDHE_keys(hostname):
    # I tried using subprocesses, but it didn't work; os.system does work though
    # First, generate EC paramters and convert them in readable format
    
    # Make sure folder for PEM files exists
    if not os.path.exists("certs"):
        os.makedirs("certs")
    
    print("Generating ECDHE parameters...")
    err1 = os.system("openssl ecparam -name secp384r1 -out certs/%s_ECDHE.pem -param_enc explicit" % hostname)
    err2 = os.system("openssl ecparam -in certs/%s_ECDHE.pem -text -noout > certs/%s_ECDHE_params.txt" % (hostname, hostname))

    if(err1 != 0):
        print("ERROR: Could not create PEM file!")
        exit(1)
    if(err2 != 0):
        print("ERROR: Could not read PEM file!")
        exit(1)

    # Read in generated parameters
    params = read_paramters(hostname, "ECDHE")

    generator = params["Gener"]
    order = params["Order"]
    a = params["A"]
    b = params["B"]
    prime = params["Prime"]

    print("Generating private and (ephemeral) public key...")
    private_key = crypto_random.randint(2, order)

    while(gcd(private_key, order) != 1):
        print("GCD of private key and order != 1; Regenerating private key...")
        private_key = crypto_random.randint(2, order)

    public_key = point_multiply(private_key, generator, prime, a)

    # Verify public key is on the curve
    if (public_key[1]**2 - (public_key[0]**3 + a*public_key[0] + b)) % prime != 0:
        print("ERROR: Public key not curve! Failed to create a correct public key")
        exit(1)

    return private_key, public_key, prime, a

# Use own secret key and other host's public key to generate shared secret
# Shared secret is SHA256 sum of the x-coordinate from a*b*Generator
# prime and a are from the parameters of the selected elliptic curve
def gen_shared_secret(private_key, other_host_pub_key, prime_ECDHE, a_ECDHE):
    
    # Only want to use x-coordinate only
    x_coord = point_multiply(private_key, other_host_pub_key, prime_ECDHE, a_ECDHE)[0]

    x_coord_hex = hex(x_coord)[2:]

    sha256 = SHA256.new()
    sha256.update(x_coord_hex.encode())
    shared_secret = sha256.digest()

    return shared_secret

# Generate private and public keys for ECDSA with OpenSSL command
# See ecdsa_test.py for my own attempt at implemeting this
def generate_ECDSA_keys(hostname):
    # Make sure folder for PEM files exists
    if not os.path.exists("certs"):
        os.makedirs("certs")

    err1 = os.system("openssl ecparam -name secp384r1 -genkey -noout -out certs/%s_private_ECDSA.pem -param_enc explicit" % hostname)
    err2 = os.system("openssl ec -in certs/%s_private_ECDSA.pem -pubout -out certs/%s_public_ECDSA.pem" % (hostname, hostname))
    err3 = os.system("openssl ec -in certs/%s_private_ECDSA.pem -noout -out certs/%s_ECDSA_params.txt -text" % (hostname, hostname))

    if(err1 != 0):
        print("ERROR: Could not create private key!")
        exit(1)
    if (err2 != 0):
        print("ERROR: Could not create parameters!")
        exit(1)
    if(err3 != 0):
        print("ERROR: Could not create public key!")
        exit(1)

    # Read in generated parameters
    # params = read_paramters(hostname, "ECDSA")
    # print(params)
    
    # Here I would have my own code to calculate the keys
    # See ecdsa_test.py
    
    return;

# Sign data using ECDSA with OpenSSL command
# Need to pack data as string before signing
def sign_data(signer_hostname, data, seq_num):
    data = str(seq_num) + str(data)

    err = os.system("echo \"%s\" | openssl dgst -sha256 -sign certs/%s_private_ECDSA.pem > certs/sig.bin" % (data, signer_hostname))
    if err != 0:
        print("ERROR: Could not create signature!")
        exit(1)

    # Read in and store the signature
    file = open("certs/sig.bin", "rb")
    signature = file.read()
    file.close()
    os.remove("certs/sig.bin") # Don't need to leave this file lying around

    return signature

# Verify signature of ECDSA signed data and that signed sequence number matches the host expected number
# Data to be verified will usually be a ECDHE public keys (a tuple) => need to pack data as string before verifying
def verify_data(signer_hostname, data, seq_num, signature):
    data = str(seq_num) + str(data)

    # Place the signature in readable place
    file = open("certs/sig.bin", "wb")
    file.write(signature)
    file.close()

    # Since we are assuming each host already knows each other's public key from the start,
    # we are just going to read from the signer host's public key file to get it
    err = os.system("echo \"%s\" | openssl dgst -sha256 -verify certs/%s_public_ECDSA.pem -signature certs/sig.bin" % (data, signer_hostname))
    os.remove("certs/sig.bin")

    if err != 0:
        print("ERROR: Could not verify received public key and/or sequence number!")
        exit(1)

    return 

# Test ECDHE
# alice = gen_ECDHE_keys("hostA")
# print()

# bob = gen_ECDHE_keys("hostB")
# print()

# alice_shared = gen_shared_secret(alice[0], bob[1], alice[2], alice[3])
# bob_shared = gen_shared_secret(bob[0], alice[1], bob[2], bob[3])
# print(alice_shared)
# print(bob_shared)

# assert(alice_shared == bob_shared)

# Test ECDSA
# data = "asdasd"
# generate_ECDSA_keys("hostA")
# sig = sign_data("hostA", data)
# verify_data("hostA", data, sig)