DUE LAST DAY OF FINALS: 5/24/2018

Project 3: Develop an end-to-end encryption tool set which does the modern load:
Perform an ECDHE key exchange, sign the data using ECDSA, then switch to
symmetric using the shared secret, namely send and decrypt messages using
AES_128_GCM. These are the standards for traffic communicated with facebook. If
you are feeling extremely motivated set this up as a served process, but the
requirement is merely to have the ability to do this exchange with a Python
script you write importing a module you write. You can use common crypto
libraries to assist, again dictated by motivation.

Dependencies:  
At least Python 3.4.3  
Needs version of pycrypto the supports AES in GCM mode (v2.7a1):  https://github.com/dlitz/pycrypto/releases  
secp256k1 ecliptic curve needs to be supported on system: `$ openssl ecparam -list_curves | grep secp256k1`

References:  
https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM  
https://en.wikipedia.org/wiki/Galois/Counter_Mode  
https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Cipher/AES.py  
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf  

TO DO:  
Generate ECDHE params  
Generate ECDSA params  
Set up exchange  
Do over sockets  