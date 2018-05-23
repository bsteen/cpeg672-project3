import os
from Cryptodome.Random import random
from Cryptodome.Hash import SHA256
from fractions import gcd

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

# Used by gen_priv_pub_keys for reading in key files
def h2i(hexLines):
    if (hexLines == ''):
        return 0
    return int(hexLines.replace(' ','').replace(':',''), 16)

# Used by gen_priv_pub_keys for reading in key files
def splitPoint(hexLines):
    gen=hexLines.replace(' ','').replace(':','')[2:]
    gl=len(gen)//2
    return (int(gen[:gl],16), int(gen[gl:], 16))

# Used by point_multiply: Add two points on an elliptic curve
# Q == P: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_doubling
# Else: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
def point_add(Q, P, prime, a):
    if Q == P:
        lamba = ((3*P[0]**2 + a) * pow(2*P[1], prime - 2 , prime)) % prime
                                            # Inverse modulus, but since modulus is always prime use Fermat's little theorem
    else:
        lamba = ((Q[1] - P[1]) * pow(Q[0] - P[0], prime - 2, prime)) % prime
        
    x_r = (lamba**2 - P[0] - Q[0]) % prime
    y_r = (lamba * (P[0] - x_r) - P[1]) % prime
    return (x_r, y_r)

# Used when generating the public key for ECDHE
# Point multiplication along an elliptic curve
# Double-and-add method: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
def point_multiply(point, generator, prime, a):
    N = generator
    Q = (0, 0)
    binary_point = bin(point)[2:]  # Don't count the "0b" at the start
    m = len(binary_point)
    
    for i in range(0, m):
        if(binary_point[i] == "1"):
            Q = point_add(Q, N, prime, a)
        N = point_add(N, N, prime, a)
    
    return Q
    
# Generate private and public keys for ECDHE
def gen_priv_pub_keys(hostname):
    # I tried using subprocesses, but it didn't work; but these calls do
    # Generate EC paramters and convert them in readable format
    
    print("Generating EC parameters...")
    os.system("openssl ecparam -name secp384r1 -out certs/%s.pem -param_enc explicit" % hostname)
    os.system("openssl ecparam -in certs/%s.pem -text -noout > certs/%s_params.txt" % (hostname, hostname))
    
    # Read in parameters
    file = open('certs/%s_params.txt' % hostname,'r')
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
    
    print("Generating secret and (ephemeral) public key...")
    
    generator = params["Gener"]
    order = params["Order"]
    a = params["A"]
    prime = params["Prime"]
    secret_key = 16592202607097164923902903348447898525988684857834574738015513852982997034287385876084095912327255475652277336200523
    #random.randint(2, order)
    
    while(gcd(secret_key, order) != 1):
        print("GCD of secret key and order != 1; Regenerating secret key...")
        secret_key = random.randint(2, order)
    
    public_key = point_multiply(secret_key, generator, prime, a)
    
    return secret_key, public_key, prime, a
    
# Use own secret key and other host's public key to generate shared secret
# Shared secret is SHA256 sum of x-coordinate from a*b*Generator
def gen_shared_secret(secret_key, other_host_pub_key, prime_curve, a_curve):
    
    print("Generating shared secret...")
    x_coord = point_multiply(secret_key, other_host_pub_key, prime_curve, a_curve)[0]
    
    sha256 = SHA256.new()
    sha256.update(x_coord)
    shared_secret = sha256.digest()
    
    return shared_secret

print(gen_priv_pub_keys("hostA_ECDHE")[1])