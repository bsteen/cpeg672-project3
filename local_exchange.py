import ECDSA
import ECDHE
import AES_128_GCM

# Performs a local (within this python script) secure communication handshake
# and transmission using ECDSA, ECDHE, and AES_128_GCM

# Contains the information passed between the two hosts
class Message:
    def __init__(self):
		# Can contain EC paramters or an encrypted message
        self.message = ""

		# Used when the transmission has switched over to symmetric crypto
		# Is the IV for decrypting the message.
        self.nonce = ""

        # Used when the transmission has switched over to symmetric crypto
		# Is the MAC for decrypting the message in GCM mode
        self.MAC = ""