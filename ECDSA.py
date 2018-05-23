import os
from Cryptodome.Random import random as crypto_random
from Cryptodome.Hash import SHA256

def h2i(hexLines):
    if (hexLines == ''):
        return 0
    return int(hexLines.replace(' ','').replace(':',''), 16)

def splitPoint(hexLines):
    gen=hexLines.replace(' ','').replace(':','')[2:]
    gl=len(gen)//2
    return (int(gen[:gl],16), int(gen[gl:], 16))

def generate_ECDSA_keys(hostname):
    # Make sure folder for PEM files exists
    if not os.path.exists("certs"):
        os.makedirs("certs")
    
    print("Generating ECDHE keys...")
    err1 = os.system("openssl ecparam -name secp384r1 -genkey -noout -out certs/%s_private_ECDSA.pem -param_enc explicit" % hostname)
    err2 = os.system("openssl ec -in certs/%s_private_ECDSA.pem -noout -out certs/%s_params_ECDSA.txt -text" % (hostname, hostname))
    
    if(err1 != 0):
        print("ERROR: Could not create private key!")
        exit(1)
    if(err2 != 0):
        print("ERROR: Could not create public key and parameters!")
        exit(1)
        
    # Read in parameters
    file = open("certs/%s_params_ECDSA.txt" % hostname,'r')
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
        
def sign_data(data):
    return

generate_ECDSA_keys("hostA")