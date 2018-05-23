import EC
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

        # Has 2 uses:
        # 1) Holds signed public ECDHE key during key exchange
        # 2) Also used when the transmission has switched over to symmetric crypto.
        #    Is the MAC for verifying during decryption of message with GCM mode
        self.mac = mac
        
    def clear(self):
        self.message = ""
        self.nonce = ""
        self.mac = ""
        
class Host:
    def __init__(self, name):
        self.name = name
        
        # Parameters and keys for ECDHE
        self.prime_ECDHE = 0
        self.a_ECDHE = 0
        self.private_key_ECDHE = ""
        self.public_key_ECDHE = ""
        self.other_public_key_ECDHE = "" # Public (ephemeral) key from other host
        self.shared_secret_ECDHE = ""
        
        # Parameters and keys for ECDHE
        # self.private_key_ECDSA = ""
        # self.public_key_ECDSA = ""
        
        self.current_message = None
    
    def read_currnet_message(self):
        if self.current_message != None:
            return self.current_message.message, self.current_message.nonce, self.current_message.mac
        else:
            print("Nothing to read.")
            return None, None, None
            
    def clear_current_message(self):
        self.current_message.clear()
        self.current_message = None
    
    # Simulate sending a message over the network
    def send_message(self, message, target_Host):
        target_Host.current_message = message

hostA = Host("hostA")
hostB = Host("hostB")

# Assume that both host's already know each others public ECDSA keys
# Thier public ECDSA keys are "common knowledge", like CA certifcates in a browser
print("Host A generating ECDSA keys...")
EC.generate_ECDSA_keys(hostA.name)
print()
print("Host B generating ECDSA keys...")
EC.generate_ECDSA_keys(hostB.name)
print()

print("***STARTING TRANSMISSION***\n")

print("Host A generating ECDHE keys...")
hostA.private_key_ECDHE, hostA.public_key_ECDHE, hostA.prime_ECDHE, hostA.a_ECDHE = EC.gen_ECDHE_keys("hostA")
print()
print("Host B generating ECDHE keys...")
hostB.private_key_ECDHE, hostB.public_key_ECDHE, hostB.prime_ECDHE, hostB.a_ECDHE = EC.gen_ECDHE_keys("hostB")
print()

print("Host A signing its ECDHE public key with its ECDSA private key...")
signed_public_key_ECDHE = EC.sign_data(hostA.name, hostA.public_key_ECDHE)
print("Host A sending public ECDHE key (and signed version) to Host B...")
pub_key_ECDHE_msg = Message(hostA.public_key_ECDHE, "", signed_public_key_ECDHE)
hostA.send_message(pub_key_ECDHE_msg, hostB)
print()

print("Host B recieving Host A's public ECDHE key...")
print("Host B validating Host A's public ECDHE key...")
data = hostB.read_currnet_message()[0]
signed_data = hostB.read_currnet_message()[2]
verified = EC.verify_data(hostA.name, data, signed_data)
if verified:
    # If valid, B stores A's public ECDHE key
    hostB.other_public_key_ECDHE = data
    hostB.clear_current_message()
else:
    print("ERROR: Could not verify Host A's public key!")
    quit(1)
print()

print("Host B signing its ECDHE public key with its ECDSA private key...")
signed_public_key_ECDHE = EC.sign_data(hostB.name, hostB.public_key_ECDHE)
print("Host B sending public ECDHE key (and signed version) to Host A...")
pub_key_ECDHE_msg = Message(hostB.public_key_ECDHE, "", signed_public_key_ECDHE)
hostB.send_message(pub_key_ECDHE_msg, hostA)
print()

print("Host A recieving Host B's public ECDHE key...")
print("Host A validating Host B's public ECDHE key...")
data = hostA.read_currnet_message()[0]
signed_data = hostA.read_currnet_message()[2]
verified = EC.verify_data(hostB.name, data, signed_data)
if verified:
    # If valid, A stores B's public ECDHE key
    hostA.other_public_key_ECDHE = data
    hostA.clear_current_message()
else:
    print("ERROR: Could not verify Host B's public key!")
    quit(1)

print("\n***KEY EXCHANGE COMPLETE***\n")

print("Host A generating ECDHE shared secret...")
hostA.shared_secret_ECDHE = EC.gen_shared_secret(hostA.private_key_ECDHE, hostA.other_public_key_ECDHE, hostA.prime_ECDHE, hostA.a_ECDHE)
print("Host B generating ECDHE shared secret...")
hostB.shared_secret_ECDHE = EC.gen_shared_secret(hostB.private_key_ECDHE, hostB.other_public_key_ECDHE, hostB.prime_ECDHE, hostB.a_ECDHE)
print("Switching to AES-128-GCM for further communication\n")

print("Host A encrypting and sending message to Host B...")
ciphertext, iv, mac = AES_128_GCM.encrypt("Hello, I'm Host A. Please send me some super special awesome secret info.", hostA.shared_secret_ECDHE)
encrypted_message = Message(ciphertext, iv, mac)
hostA.send_message(encrypted_message, hostB)

print("Host B receving message from Host A...")
ciphertext, iv, mac = hostB.read_currnet_message()
AES_128_GCM.decrypt(ciphertext, hostB.shared_secret_ECDHE, iv, mac)
hostB.clear_current_message()
print()

print("Host B encrypting and sending message to Host A...")
ciphertext, iv, mac = AES_128_GCM.encrypt("Hello Host A, I'm Host B. Here is some secret info: 09 F9 11 02 9D 74 E3 5B D8 41 56 C5 63 56 88 C0", hostB.shared_secret_ECDHE)
encrypted_message = Message(ciphertext, iv, mac)
hostB.send_message(encrypted_message, hostA)

print("Host A receving message from Host B...")
ciphertext, iv, mac = hostA.read_currnet_message()
AES_128_GCM.decrypt(ciphertext, hostA.shared_secret_ECDHE, iv, mac)
hostA.clear_current_message()

print("\n***TRANSMISSION COMPLETE***")