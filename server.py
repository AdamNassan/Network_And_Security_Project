from socket import *
import random
import secrets
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from utils_crypto import *

# Hardcoded RSA keys (from mod_inverse.py)
ALICE_P = 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001329
ALICE_Q = 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002011
ALICE_N = 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003340000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002672619
ALICE_E = 65537
BOB_P = 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004321
BOB_Q = 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005169
BOB_N = 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009490000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022335249
BOB_E = 65537
BOB_D = 97471657231792727772098204067931092360040892930710896135007705570898881547827944519889528052855638799456795398019439400643911073134260036315363840273433327738529380350031280040282588461479774783709965363077345621557288249385843111524787524604421929597021529822848162106901444985275493232830309596106016449648432854723286082670857683445992340204769824679188855150525657262309840242916215267711369150251003250072478142118192776599478157376749012008483757266887407113538916947678410668782519797976715443184765857454567648809069685826327112928574698262050444786914262172513236797534217312357904695057753635351023088371713
ALICE_ID = "10.0.2.15"  # Seed VM IP
BOB_ID = "192.168.56.1"      # Windows IP

# Phase 3: Hardcoded keys
BOB_PUB_KEY = (BOB_E, BOB_N)
BOB_PRIV_KEY = (BOB_D, BOB_N)
ALICE_PUB_KEY = (ALICE_E, ALICE_N)

# Encrypt using AES-256-CBC (from Phase 2)
def encrypt_message(plaintext, key):
    iv = secrets.token_bytes(16)  # 128-bit IV
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext

# Decrypt using AES-256-CBC (from Phase 2)
def decrypt_message(iv, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted_data.decode()

# Receive exact number of bytes
def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionError("Connection closed unexpectedly")
        data += packet
    return data

# Phase 3: Perform mutual authentication and key exchange
def perform_handshake(sock):
    # Step 1: Receive A, R_A
    A_len = int.from_bytes(recv_exact(sock, 4), 'big')
    A = int(recv_exact(sock, A_len).decode().strip())
    R_A_len = int.from_bytes(recv_exact(sock, 4), 'big')
    R_A = recv_exact(sock, R_A_len).decode().strip()
    
    # Step 2: Generate b, R_B, B
    b = generate_2048_bit_random()
    R_B = generate_random_256_bits()
    B = mod_exp(DH_GENERATOR, b, DH_PRIME)
    
    # Compute H and S_B
    shared_secret = mod_exp(A, b, DH_PRIME)
    H = sha256_hash(ALICE_ID, BOB_ID, R_A, R_B, A, B, shared_secret)
    S_B = rsa_sign(H, BOB_PRIV_KEY)
    
    # Send B, R_B, S_B with length prefixes
    B_bytes = str(B).encode()
    sock.send(len(B_bytes).to_bytes(4, 'big'))
    sock.send(B_bytes)
    R_B_bytes = R_B.encode()
    sock.send(len(R_B_bytes).to_bytes(4, 'big'))
    sock.send(R_B_bytes)
    S_B_bytes = S_B.encode()
    sock.send(len(S_B_bytes).to_bytes(4, 'big'))
    sock.send(S_B_bytes)
    
    # Step 3: Receive and verify S_A
    S_A_len = int.from_bytes(recv_exact(sock, 4), 'big')
    S_A = recv_exact(sock, S_A_len).decode().strip()
    H_expected = sha256_hash(ALICE_ID, BOB_ID, R_A, R_B, A, B, shared_secret)
    if not verify_signature(S_A, H_expected, ALICE_PUB_KEY):
        print("Authentication failed for Alice.")
        sock.send("AUTH_FAIL".encode())
        return None
    
    sock.send("AUTH_OK".encode())
    
    # Compute session key
    K = sha256_to_256bit_key(shared_secret)
    
    # Print for Test Case 1
    print(f"Server: b={b}, R_B={R_B}, K={K.hex()}, A={A}, R_A={R_A}")
    print("Alice authenticated successfully.")
    
    # Destroy b
    b = None
    
    return K

# Handle client connection
def handle_client(connectionSocket, addr):
    print("Connected to:", addr)
    while True:
        option = connectionSocket.recv(1024).decode()
        if option == "2":
            print("Client requested to exit.")
            break
        
        if option == "1":
            session_key = perform_handshake(connectionSocket)
            if not session_key:
                continue
            
            number = random.randint(1, 100)
            print(f"[Game Start] Secret number is: {number}")
            
            while True:
                iv = connectionSocket.recv(16)
                ciphertext = connectionSocket.recv(1024)
                
                try:
                    guess_str = decrypt_message(iv, ciphertext, session_key)
                    print(f"IV received: {iv.hex()}")  # For Test Case 1
                    guess = int(guess_str)
                    print(f"Received guess: {guess}")
                except Exception as e:
                    print(f"Decryption error: {e}")
                    break
                
                if guess < number:
                    response = "You are Lower"
                elif guess > number:
                    response = "You are Higher"
                else:
                    response = "You are Correct"
                
                resp_iv, resp_ciphertext = encrypt_message(response, session_key)
                print(f"IV sent: {resp_iv.hex()}")  # For Test Case 1
                connectionSocket.send(resp_iv)
                connectionSocket.send(resp_ciphertext)

                if response == "You are Correct":
                    # Destroy K
                    session_key = None
                    break

    connectionSocket.close()

def main():
    serverPort = 5566
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(('', serverPort))
    serverSocket.listen(1)
    print("Server is ready and listening...")
    while True:
        connectionSocket, addr = serverSocket.accept()
        handle_client(connectionSocket, addr)

if __name__ == '__main__':
    main()