DUE LAST DAY OF FINALS: 5/24/2018

Project 3: Develop an end-to-end encryption tool set which does the modern load:
Perform an ECDHE key exchange, sign the data using ECDSA, then switch to
symmetric using the shared secret, namely send and decrypt messages using
AES_128_GCM. These are the standards for traffic communicated with facebook. If
you are feeling extremely motivated set this up as a served process, but the
requirement is merely to have the ability to do this exchange with a Python
script you write importing a module you write. You can use common crypto
libraries to assist, again dictated by motivation.

To run program: `python3 local_exchange.py`  
It will run through all the steps and then show the decoded messages received.  

Dependencies:  
Bash enviroment  
At least Python 3.4.3  
Needs version of Cryptodome the supports AES in GCM mode: http://pycryptodome.readthedocs.io/en/latest/src/installation.html  
`pip3 install --user pycryptodomex` if you want to keep both pycrypto and pycryptodome installed at once.  
Otherwise, pycryptodome with take the place of pycrypto: `pip3 install --user pycryptodome`  
secp384r1 ecliptic curve needs to be supported on system: `openssl ecparam -list_curves | grep secp384r1`  

References:  
http://pycryptodome.readthedocs.io/en/latest/src/api.html  
https://github.com/user8547/fast-ecc-python/blob/master/secp256k1_python.py  
https://en.wikipedia.org/wiki/Galois/Counter_Mode  
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf  

TO DO:  
Generate ECDSA params by hand  
Do over sockets  