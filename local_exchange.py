import ECDSA
import ECDHE
import AES_128_GCM

# Performs a local (within this python script) secure communication handshake
# and transmission using ECDSA, ECDHE, and AES_128_GCM

# Contains the information passed between the two hosts
class Message:
    def __init__(self, message="", nonce="", mac=""):
		# Can contain EC paramters or an encrypted message
        self.message = message

		# Used when the transmission has switched over to symmetric crypto
		# Is the IV for decrypting the message.
        self.nonce = nonce

        # Used when the transmission has switched over to symmetric crypto
		# Is the MAC for decrypting the message in GCM mode
        self.mac = mac
        
class Host:
    def _init__(self, name):
        self.name = name
        self.private_ECDHE_key = ""
        self.shared_ECDHE_secret = ""
        
        self.private_ECDSA_key = ""
        self.public_ECDSA_key = ""
        
        self.current_message = None
    
    def read_currnet_message(self):
        if self.current_message != None:
            return self.current_message.message, self.current_message.nonce, self.current_message.mac
        return None
    
    # Simulate sending a message over the network
    def send_message(self, message, target_Host):
        target_Host.message = message

hostA = Host("hostA")
hostB = Host("hostB")

# A generates private key
# B generates private key

# A signs and sends its public info
# B validates and generates shared secret

# B signs and sends its public info
# A validates and generates shared secret

# Using shared secret, A encrpyts message and sends to B
# B recieves and views message

# Using shared secret, B encrpyts message and sends to A
# A recieves and views message