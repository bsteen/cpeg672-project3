import ECDHE
import ECDSA
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
    def clear(self):
        self.message = ""
        self.nonce = ""
        self.mac = ""
        
class Host:
    def _init__(self, name):
        self.name = name
        
        # Parameters and keys for ECDHE
        self.prime_ECDHE = 0
        self.a_ECDHE = 0
        self.private_key_ECDHE = ""
        self.public_key_ECDHE = ""
        self.other_public_key_ECDHE = "" # Public (ephemeral) key from other host
        self.shared_secret_ECDHE = ""
        
        self.private_key_ECDSA = ""
        self.public_key_ECDSA = ""
        
        self.current_message = None
    
    def read_currnet_message(self):
        if self.current_message != None:
            return self.current_message.message, self.current_message.nonce, self.current_message.mac
        else:
            print("Nothing to read.")
            return None, None, None
            
    def clear_current_message(self):
        self.current_message = None
    
    # Simulate sending a message over the network
    def send_message(self, message, target_Host):
        target_Host.message = message

hostA = Host("hostA")
hostB = Host("hostB")

print("Host A generating ECDHE private and public key...")
hostA.private_key_ECDHE, hostA.public_key_ECDHE, hostA.prime_ECDHE, hostA.a_ECDHE = ECDHE.gen_priv_pub_keys("hostA")

print("Host B generating ECDHE private and public key...")
hostB.private_key_ECDHE, hostB.public_key_ECDHE, hostB.prime_ECDHE, hostB.a_ECDHE = ECDHE.gen_priv_pub_keys("hostB")

# A signs public info
# TO DO

print("Host A sending public ECDHE key to Host B...")
pub_key_ECDHE_msg = Message(hostA.public_key_ECDHE)
hostA.send_message(pub_key_ECDHE_msg, hostB)
pub_key_ECDHE_msg.clear()

# B validates public key from A
# TO DO

# If valid, B stores A's public ECDHE key
print("Host B recieving Host A's public ECDHE key...")
hostB.other_public_key_ECDHE = hostB.read_currnet_message()[0] 
hostB.clear_current_message()

print("Host B generating ECDHE shared secret...")
hostB.shared_secret_ECDHE = ECDHE.gen_shared_secret(hostB.private_key_ECDHE, hostB.other_public_key_ECDHE, hostB.prime_ECDHE, hostB.a_ECDHE)

# B signs public info
# TO DO

print("Host B sending public ECDHE key to Host A...")
pub_key_ECDHE_msg = Message(hostB.public_key_ECDHE)
hostB.send_message(pub_key_ECDHE_msg, hostA)
pub_key_ECDHE_msg.clear()

# A validates public key from B
# TO DO

print("Host A recieving Host B's public ECDHE key...")
hostA.other_public_key_ECDHE = hostA.read_currnet_message()[0]
hostA.clear_current_message()

print("Host A generating ECDHE shared secret...")
hostA.shared_secret_ECDHE = ECDHE.gen_shared_secret(hostA.private_key_ECDHE, hostA.other_public_key_ECDHE, hostA.prime_ECDHE, hostA.a_ECDHE)

print("\n***KEY EXCHANGE COMPLETE***\n")

print("Switching to AES-128-GCM for further communication")

print("Host A encrypting and sending message to Host B...")
ciphertext, iv, mac = AES_128_GCM.encrypt("Hello, I'm am Host A", hostA.shared_secret_ECDHE)
encrypted_message = Message(ciphertext, iv, mac)
hostA.send_message(encrypted_message, hostB)
encrypted_message.clear()

print("Host B receving message from Host A...")
ciphertext, iv, mac = hostB.read_currnet_message()
AES_128_GCM.decrypt(ciphertext, hostB.shared_secret_ECDHE, iv, mac)
hostB.clear_current_message()

print("Host B encrypting and sending message to Host A...")
ciphertext, iv, mac = AES_128_GCM.encrypt("Hello Host A, I'm am Host B", hostB.shared_secret_ECDHE)
encrypted_message = Message(ciphertext, iv, mac)
hostB.send_message(encrypted_message, hostA)
encrypted_message.clear()

print("Host A receving message from Host B...")
ciphertext, iv, mac = hostA.read_currnet_message()
AES_128_GCM.decrypt(ciphertext, hostA.shared_secret_ECDHE, iv, mac)
hostA.clear_current_message()

print("\n***TRANSMISSION COMPLETE***")