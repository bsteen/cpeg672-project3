import EC
import AES_128_GCM
from socket import *
import pickle

# Performs a network (on the feedback loop) secure communication handshake
# and transmission using ECDSA, ECDHE, and AES_128_GCM

# Assumptions, aka the things each host knows about the other before the connection:
# Host names, IP address, and port numbers
# Host public ECDSA keys (assume they were distributed through a CA even though I gen new ones each time)
# Whatever info they receive in the messages

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
    def __init__(self, name, address, port, starting_seq=0):
        self.name = name

        self.port = port
        self.address = address  # Use local loopback address
        self.socket = socket(AF_INET, SOCK_DGRAM)   # Make a UDP Socket (TCP would require 2 threads or processes)
        self.socket.bind((self.address, self.port))

        # Parameters and keys for ECDHE
        self.prime_ECDHE = 0
        self.a_ECDHE = 0
        self.private_key_ECDHE = ""
        self.public_key_ECDHE = ""
        self.other_public_key_ECDHE = "" # Public (ephemeral) key from other host
        self.shared_secret_ECDHE = ""

        self.current_seq_num = starting_seq
        self.current_message = None

        self.used_ivs = [] # Host must keep track of all IVs used for AES-128-GCM encryption.
                           # Not safe to use the same IV for a single key

    #Sending a message over the network
    def send_message(self, message, target_Host):
        self.current_seq_num += 1
        serial_msg = pickle.dumps(message)      # Serialize and object before sending it over the network
        self.socket.sendto(serial_msg, (target_Host.address, target_Host.port))

    # Receive a message over the network and verify it's sequence number matches the one the host expects
    def read_currnet_message(self):
        # Recieved serialized message and sender address; Throw away address (it is already know)
        # Reconstruct the Message object
        self.current_message = pickle.loads(self.socket.recvfrom(1024)[0])

        if not verify_seq_num(self.current_message.seq_num, self.current_seq_num):
            return None, None, None
        elif self.current_message != None:
            contents = self.current_message.message, self.current_message.nonce, self.current_message.mac
            self.clear_current_message()    # Once message is read, it is cleared from the buffer
            self.current_seq_num += 1       # Next msg it sends or receives will be +1 to current seq number
            return contents
        else:
            print("Nothing to read.")
            return None, None, None

    def clear_current_message(self):
        self.current_message.clear()
        self.current_message = None

# Used for verifying expected sequence number matches the once received
def verify_seq_num(actual, from_message):
    if(actual == from_message):
        return True
    else:
        print("ERROR: Out of order message! Could be an attacker message! (Expected %d, got %d)" % (actual, from_message))
        return False
        
# Extract the seq num and message from the decrypted message
def unpack_decrypted(plaintext):
    msg_seq_num = int(plaintext[:plaintext.find(":")])
    message = plaintext[plaintext.find(":") + 1:]
    return message, msg_seq_num

# The two hosts who will communicate with each other
hostA = Host("hostA", "127.0.0.1", 8888)
hostB = Host("hostB", "127.0.0.1", 6666)

# Assume that both host's already know each others public ECDSA keys
# Their public ECDSA keys are "common knowledge", like CA certificates in a browser
print("Host A generating ECDSA keys...")
EC.generate_ECDSA_keys(hostA.name)
print("\nHost B generating ECDSA keys...")
EC.generate_ECDSA_keys(hostB.name)

print("\n***STARTING LOCAL TRANSMISSION***\n")

print("Host A generating ECDHE keys...")
hostA.private_key_ECDHE, hostA.public_key_ECDHE, hostA.prime_ECDHE, hostA.a_ECDHE = EC.gen_ECDHE_keys("hostA")
print("\nHost B generating ECDHE keys...")
hostB.private_key_ECDHE, hostB.public_key_ECDHE, hostB.prime_ECDHE, hostB.a_ECDHE = EC.gen_ECDHE_keys("hostB")

print("\nHost A signing its ECDHE public key and sequence number with its ECDSA private key...")
signed_pubkey_seqnum = EC.sign_data(hostA.name, hostA.public_key_ECDHE, hostA.current_seq_num)
print("Host A sending public ECDHE key and signature to Host B...")
pub_key_ECDHE_msg = Message(hostA.public_key_ECDHE, hostA.current_seq_num, "", signed_pubkey_seqnum)
hostA.send_message(pub_key_ECDHE_msg, hostB)

# Reading message will check message seq num == host expected sequence number
# verify_data proves public ECDHE key is from A and that signed data contains B's expected sequence number
print("\nHost B receiving Host A's public ECDHE key...")
data, nonce, signed_data = hostB.read_currnet_message()     # nonce used in this step
print("Host B validating Host A's public ECDHE key and the sequence number...")
EC.verify_data(hostA.name, data, hostB.current_seq_num - 1, signed_data)
hostB.other_public_key_ECDHE = data # If valid, B stores A's public ECDHE key

print("\nHost B signing its ECDHE public key and sequence number with its ECDSA private key...")
signed_pubkey_seqnum = EC.sign_data(hostB.name, hostB.public_key_ECDHE, hostB.current_seq_num)
print("Host B sending public ECDHE key and signature to Host A...")
pub_key_ECDHE_msg = Message(hostB.public_key_ECDHE, hostB.current_seq_num, "", signed_pubkey_seqnum)
hostB.send_message(pub_key_ECDHE_msg, hostA)

print("\nHost A receiving Host B's public ECDHE key...")
data, nonce, signed_data = hostA.read_currnet_message()    # nonce used in this step
print("Host A validating Host B's public ECDHE key and the sequence number...")
EC.verify_data(hostB.name, data, hostA.current_seq_num - 1, signed_data)
hostA.other_public_key_ECDHE = data

print("\n***KEY EXCHANGE COMPLETE***\n")

print("Host A generating ECDHE shared secret...")
hostA.shared_secret_ECDHE = EC.gen_shared_secret(hostA.private_key_ECDHE, hostA.other_public_key_ECDHE, hostA.prime_ECDHE, hostA.a_ECDHE)
print("Host B generating ECDHE shared secret...")
hostB.shared_secret_ECDHE = EC.gen_shared_secret(hostB.private_key_ECDHE, hostB.other_public_key_ECDHE, hostB.prime_ECDHE, hostB.a_ECDHE)
print("Switching to AES-128-GCM for further communication\n")

print("Host A encrypting and sending message to Host B...")
plaintext = str(hostA.current_seq_num) + ":" + "Hello, I'm Host A. Please send me some super special awesome secret info." # Encrypt sequence number and message
ciphertext, iv, mac = AES_128_GCM.encrypt(plaintext, hostA.shared_secret_ECDHE, hostA.used_ivs)
encrypted_message = Message(ciphertext, hostA.current_seq_num, iv, mac)
hostA.send_message(encrypted_message, hostB)

print("Host B receiving message from Host A...")
# Reading message will check message seq num == host expected sequence number
ciphertext, iv, mac = hostB.read_currnet_message()
message, msg_seq_num = unpack_decrypted(AES_128_GCM.decrypt(ciphertext, hostB.shared_secret_ECDHE, iv, mac, hostB.used_ivs))
# Returns message and seq num. Verifies the ciphertext wasn't tampered with
verify_seq_num(hostB.current_seq_num - 1, msg_seq_num)
    # We might known now that seq number was not tampered with after it was encrpyted, but we still need to check decrypted
    # seq number matches the seq number sent with the message; An attacker could take a valid MAC and ciphertext from another message
    # and created a new message with a different sequence number
print("Showing decoded message:", message ,"\n")

print("Host B encrypting and sending message to Host A...")
plaintext = str(hostB.current_seq_num) + ":" + "Hello Host A, I'm Host B. Here is some secret info: 09 F9 11 02 9D 74 E3 5B D8 41 56 C5 63 56 88 C0"
ciphertext, iv, mac = AES_128_GCM.encrypt(plaintext, hostB.shared_secret_ECDHE, hostB.used_ivs)
encrypted_message = Message(ciphertext, hostB.current_seq_num, iv, mac)
hostB.send_message(encrypted_message, hostA)

print("Host A receiving message from Host B...")
ciphertext, iv, mac = hostA.read_currnet_message()
message, msg_seq_num = unpack_decrypted(AES_128_GCM.decrypt(ciphertext, hostA.shared_secret_ECDHE, iv, mac, hostA.used_ivs))
verify_seq_num(hostA.current_seq_num - 1, msg_seq_num)
print("Showing decoded message:", message ,"\n")

print("***TRANSMISSION COMPLETE***")