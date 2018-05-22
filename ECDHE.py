import os
from Cryptodome.Random import random
from Cryptodome.PublicKey import ECC
from fractions import gcd

# Since we are using AES-128, the equivalent security in EC would be 256 bits
# Use secp256k1 ecliptic curve

########OpenSSL + by hand method########
# hostname = "hostA_ECDHE"

# # I tried using subprocesses, but it didn't work; These calls do
# # Generate EC paramters and convert them in readable format
# os.system("openssl ecparam -name secp256k1 -out certs/%s.pem -param_enc explicit" % hostname)
# os.system("openssl ecparam -in certs/%s.pem -text -noout > certs/%s_params.txt" % (hostname, hostname))

# # Read in parameters
# file = open('certs/%s_params.txt' % hostname,'r')
# lines = file.readlines()
# file.close()

# # Get correct lines and clean them up
# prime = "".join(lines[2:5])
# prime = prime.replace(":", "").replace(" ", "").replace("\n", "")
# prime = int(prime, 16)

# generator = "".join(lines[8:13])
# generator = generator.replace(":", "").replace(" ", "").replace("\n", "")
# generator = int(generator, 16)

# order = "".join(lines[14:17])
# order = order.replace(":", "").replace(" ", "").replace("\n", "")
# order = int(order, 16)

# secret_key = random.randint(2, order)
# while(gcd(secret_key, order) != 1):
#     secret_key = random.randint(2, order)
    
########Cryptodome Method########
key = ECC.generate(curve="secp256r1")
print(key)