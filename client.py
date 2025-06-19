from socket import *
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
ALICE_D = 165540076597952301753208111448494743427376901597570837847322886308497489967499275218578818072234005218426232509879915162427331125928864610830523215893312174802020232845568152341425454323511909303141736728870714253017379495552130857378274867632024657826876420953049422463646489769138044158261745273662206082613088209713596899461372964890062102323878114652791552863268077574499900819384469841463600714100431817141462074858476890916581473061018966385400613393960663442025115583563483223217419167798342920792834581991851930970291591009658666097013900544730457604101499916077940705250469200604238826922196621755649480888033
BOB_P = 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004321
BOB_Q = 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005169
BOB_N = 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009490000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022335249
BOB_E = 65537
ALICE_ID = "10.0.2.15"  # Seed VM IP
BOB_ID = "192.168.56.1"      # Windows IP

# Phase 3: Hardcoded keys
ALICE_PUB_KEY = (ALICE_E, ALICE_N)
ALICE_PRIV_KEY = (ALICE_D, ALICE_N)
BOB_PUB_KEY = (BOB_E, BOB_N)

# Display menu
def show_menu():
    print("\n--- Guessing Game Menu ---")
    print("1. Start a new guessing game round")
    print("2. Exit the game")
    return input("Choose an option: ")

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
def perform_key_exchange(clientSocket):
    # Step 1: Generate a, R_A
    a = generate_2048_bit_random()
    R_A = generate_random_256_bits()
    A = mod_exp(DH_GENERATOR, a, DH_PRIME)
    
    # Send A, R_A with length prefixes
    A_bytes = str(A).encode()
    clientSocket.send(len(A_bytes).to_bytes(4, 'big'))
    clientSocket.send(A_bytes)
    R_A_bytes = R_A.encode()
    clientSocket.send(len(R_A_bytes).to_bytes(4, 'big'))
    clientSocket.send(R_A_bytes)
    
    # Step 2: Receive B, R_B, S_B
    B_len = int.from_bytes(recv_exact(clientSocket, 4), 'big')
    B = int(recv_exact(clientSocket, B_len).decode().strip())
    R_B_len = int.from_bytes(recv_exact(clientSocket, 4), 'big')
    R_B = recv_exact(clientSocket, R_B_len).decode().strip()
    S_B_len = int.from_bytes(recv_exact(clientSocket, 4), 'big')
    S_B = recv_exact(clientSocket, S_B_len).decode().strip()
    
    # Compute shared secret and H
    shared_secret = mod_exp(B, a, DH_PRIME)
    H = sha256_hash(ALICE_ID, BOB_ID, R_A, R_B, A, B, shared_secret)
    
    # Verify S_B
    if not verify_signature(S_B, H, BOB_PUB_KEY):
        print("Bob authentication failed. Terminating game round.")
        clientSocket.send("AUTH_FAIL".encode())
        return None
    
    # Step 3: Sign H and send S_A
    S_A = rsa_sign(H, ALICE_PRIV_KEY)
    S_A_bytes = S_A.encode()
    clientSocket.send(len(S_A_bytes).to_bytes(4, 'big'))
    clientSocket.send(S_A_bytes)
    
    # Receive authentication result
    auth_result = clientSocket.recv(1024).decode()
    if auth_result != "AUTH_OK":
        print("Alice authentication failed by server. Terminating game round.")
        return None
    
    # Compute session key
    K = sha256_to_256bit_key(shared_secret)
    
    # Print for Test Case 1
    print(f"Client: a={a}, R_A={R_A}, K={K.hex()}, B={B}, R_B={R_B}")
    print("Bob authenticated successfully.")
    
    # Destroy a
    a = None
    
    return K

# Game loop
def start_game(clientSocket, session_key):
    while True:
        guess = input("Enter your guess (1-100): ")
        if not guess.isdigit():
            print("Please enter a valid number.")
            continue
        
        iv, ciphertext = encrypt_message(guess, session_key)
        print(f"IV sent: {iv.hex()}")  # For Test Case 1
        clientSocket.send(iv)
        clientSocket.send(ciphertext)
        
        recv_iv = clientSocket.recv(16)
        recv_ciphertext = clientSocket.recv(1024)
        print(f"IV received: {recv_iv.hex()}")  # For Test Case 1
        response = decrypt_message(recv_iv, recv_ciphertext, session_key)
        print("Server says:", response)
        
        if response == "You are Correct":
            break

def main():
    serverIP = input("Enter server IP address: ")
    serverPort = 5566
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((serverIP, serverPort))
    
    while True:
        option = show_menu()
        if option not in ["1", "2"]:
            print("Invalid option.")
            continue
        
        clientSocket.send(option.encode())
        if option == "1":
            session_key = perform_key_exchange(clientSocket)
            if session_key:
                start_game(clientSocket, session_key)
                # Destroy K
                session_key = None
        elif option == "2":
            print("Exiting game.")
            break
    
    clientSocket.close()

if __name__ == '__main__':
    main()