# CPEG 672 - Project 3
# Benjamin Steenkamer
__DUE LAST DAY OF FINALS: 5/24/2018__  
Assignment site: http://crypto.prof.ninja/projects/  
Develop an end-to-end encryption tool set which does the modern load:
Perform an ECDHE key exchange, sign the data using ECDSA, then switch to
symmetric using the shared secret, namely send and decrypt messages using
AES_128_GCM. These are the standards for traffic communicated with facebook. If
you are feeling extremely motivated set this up as a served process, but the
requirement is merely to have the ability to do this exchange with a Python
script you write importing a module you write. You can use common crypto
libraries to assist, again dictated by motivation.

## To run program:
Run: `python3 local_exchange.py` or `python3 network_exchange.py`  
Either will will run through all the steps and then show the decoded messages received.
`network_exchange.py` will do the same steps as `local_exchange.py`, but it will transfer the messages over the local
network instead of just using variables to simulate a connection.
Basically `network_exchange.py` uses sockets, `local_exchange.py` uses shared variables as the "network connection."  
`ecdsa_test.py` is an attempt to roll my own ECDSA signing and verifying functions. It ended up not working, 
so I instead used OpenSSL's command line utility to handle all ECDSA operations.

## Dependencies:  
* Bash environment  
* At least Python 3.4.3 (DO NOT USE PYTHON 2! In fact, never use it for anything ever!: https://pythonclock.org/)  
* Needs a version of Cryptodome that supports AES in GCM mode: http://pycryptodome.readthedocs.io/en/latest/src/installation.html  
If you want to keep both pycrypto and pycryptodome installed at once: `pip3 install --user pycryptodomex`  
Otherwise, pycryptodome with take the place of pycrypto: `pip3 install --user pycryptodome` 
* Python's `socket` and `pickle` libraries are used (should already be installed)  
* `secp384r1` ecliptic curve needs to be supported on your system: `openssl ecparam -list_curves | grep secp384r1`  

## References:  
http://crypto.prof.ninja/notes/  
http://pycryptodome.readthedocs.io/en/latest/src/api.html  
https://github.com/user8547/fast-ecc-python/blob/master/secp256k1_python.py  
https://en.wikipedia.org/wiki/Galois/Counter_Mode  
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf  
https://docs.python.org/3/library/socket.html  
General algorithm help: http://rosettacode.org/wiki/Elliptic_curve_arithmetic

## TO DO:  
Generate ECDSA params by hand  
Separate hosts into two files; Run connection over TCP instead of UCP