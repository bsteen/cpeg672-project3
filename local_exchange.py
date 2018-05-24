import EC
import AES_128_GCM

# Performs a local (within this python script) secure communication handshake
# and transmission using ECDSA, ECDHE, and AES_128_GCM

# How the sequence numbers work:
# Both initial sender and initial receiver start at the same sequence number.
# Sender sends message with its current seq number, 0.
# Sending a message causes the sender's sequence number to increase to 1
# Receiver receives the message and reads it, expecting to see the seq number 0.
# Reading the message causes the receiver's sequence number to increase to 1.
# If the sender was to send another message now. it would be sent with a seq number of 1,
# and the receiver's sequence number would still be in sync as it's expecting a seq number of 1.
# If instead the receiver becomes the sender, it would send a message with sequence number 1,
# and the new receiver (old sender) would be expecting a message with seq number 1.

# Contains the information passed between the two hosts
class Message:
    def __init__(self, message, seq_num, nonce="", mac=""):
		# Can contain EC parameters or an encrypted message
        self.message = message

        # Message's sequential number in the current conversation
        self.seq_num = seq_num

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
        self.seq_num = ""
        self.nonce = ""
        self.mac = ""
        
class Host:
    def __init__(self, name, starting_seq=0):
        self.name = name
        
        # Parameters and keys for ECDHE
        self.prime_ECDHE = 0
        self.a_ECDHE = 0
        self.private_key_ECDHE = ""
        self.public_key_ECDHE = ""
        self.other_public_key_ECDHE = "" # Public (ephemeral) key from other host
        self.shared_secret_ECDHE = ""
        
        self.current_seq_num = starting_seq
        self.current_message = None
    
    def read_currnet_message(self):
        if self.current_message.seq_num != self.current_seq_num:
            print("ERROR: Out of order message! (Expected %d, got %d)" % (self.current_seq_num, self.current_message.seq_num))
            return None, None, None
        elif self.current_message != None:
            contents = self.current_message.message, self.current_message.nonce, self.current_message.mac
            self.clear_current_message()    # Once message is read, it is cleared from the buffer
            self.current_seq_num += 1       # Next msg it sends or receives will be +1 to current seq number
            return contents
        else:
            print("Nothing to read.")
            return None, None, None
            
    # Simulate sending a message over the network
    def send_message(self, message, target_Host):
        self.current_seq_num += 1
        target_Host.current_message = message
        
    def clear_current_message(self):
        self.current_message.clear()
        self.current_message = None
    

hostA = Host("hostA")
hostB = Host("hostB")

# Assume that both host's already know each others public ECDSA keys
# Their public ECDSA keys are "common knowledge", like CA certificates in a browser
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
pub_key_ECDHE_msg = Message(hostA.public_key_ECDHE, hostA.current_seq_num, "", signed_public_key_ECDHE)
hostA.send_message(pub_key_ECDHE_msg, hostB)
print()

print("Host B receiving Host A's public ECDHE key...")
data, nonce, signed_data = hostB.read_currnet_message()     # nonce isn't used here
print("Host B validating Host A's public ECDHE key...")
verified = EC.verify_data(hostA.name, data, signed_data)
if verified:
    # If valid, B stores A's public ECDHE key
    hostB.other_public_key_ECDHE = data
else:
    print("ERROR: Could not verify Host A's public key!")
    quit(1)
print()

print("Host B signing its ECDHE public key with its ECDSA private key...")
signed_public_key_ECDHE = EC.sign_data(hostB.name, hostB.public_key_ECDHE)
print("Host B sending public ECDHE key (and signed version) to Host A...")
pub_key_ECDHE_msg = Message(hostB.public_key_ECDHE, hostB.current_seq_num, "", signed_public_key_ECDHE)
hostB.send_message(pub_key_ECDHE_msg, hostA)
print()

print("Host A receiving Host B's public ECDHE key...")
data, nonce, signed_data = hostA.read_currnet_message()    # nonce isn't used here
print("Host A validating Host B's public ECDHE key...")
verified = EC.verify_data(hostB.name, data, signed_data)
if verified:
    # If valid, A stores B's public ECDHE key
    hostA.other_public_key_ECDHE = data
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
encrypted_message = Message(ciphertext, hostA.current_seq_num, iv, mac)
hostA.send_message(encrypted_message, hostB)

print("Host B receiving message from Host A...")
ciphertext, iv, mac = hostB.read_currnet_message()
AES_128_GCM.decrypt(ciphertext, hostB.shared_secret_ECDHE, iv, mac)
print()

print("Host B encrypting and sending message to Host A...")
ciphertext, iv, mac = AES_128_GCM.encrypt("Hello Host A, I'm Host B. Here is some secret info: 09 F9 11 02 9D 74 E3 5B D8 41 56 C5 63 56 88 C0", hostB.shared_secret_ECDHE)
encrypted_message = Message(ciphertext, hostB.current_seq_num, iv, mac)
hostB.send_message(encrypted_message, hostA)

print("Host A receiving message from Host B...")
ciphertext, iv, mac = hostA.read_currnet_message()
AES_128_GCM.decrypt(ciphertext, hostA.shared_secret_ECDHE, iv, mac)

print("\n***TRANSMISSION COMPLETE***")