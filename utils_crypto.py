import secrets
import hashlib

# RFC3526 2048-bit MODP Group parameters (Phase 3: DH key exchange)
DH_GENERATOR = 2
DH_PRIME = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08
8A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D
6D51C245E485B576625E7EC6F44C42E9A63A3620
FFFFFFFFFFFFFFFF
""".replace("\n", "").replace(" ", ""), 16)

# Modular exponentiation (repeated squaring) for RSA signing/verification
def mod_exp(base, exponent, modulus):
    if modulus == 1:
        return 0
    if exponent <= 0:
        raise ValueError("Exponent must be positive")
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result

# Generate 2048-bit random exponent using CSRNG (Phase 3: DH exponent a, b)
def generate_2048_bit_random():
    return int.from_bytes(secrets.token_bytes(256), 'big') % DH_PRIME

# Generate 256-bit nonce using CSRNG (Phase 3: R_A, R_B)
def generate_random_256_bits():
    return secrets.token_hex(32)  # 256 bits = 32 bytes

# SHA-256 hash of concatenated strings (Phase 3: H = SHA256(Alice, Bob, R_A, R_B, g^a mod m, g^b mod m, g^ab mod m))
def sha256_hash(*args):
    return hashlib.sha256(''.join(str(arg) for arg in args).encode()).hexdigest()

# Convert SHA-256 hex to 256-bit binary key (Phase 3: K = SHA256(g^ab mod m))
def sha256_to_256bit_key(data):
    return hashlib.sha256(str(data).encode()).digest()

# RSA sign: H^d mod N (Phase 3: S_A, S_B)
def rsa_sign(hash_hex, priv_key):
    d, N = priv_key
    H_int = int(hash_hex, 16)
    if H_int >= N:
        raise ValueError("Hash value exceeds modulus")
    return str(mod_exp(H_int, d, N))

# RSA verify: S^e mod N == H (Phase 3: Verify S_A, S_B)
def verify_signature(signature_str, hash_hex, pub_key):
    e, N = pub_key
    S_int = int(signature_str)
    verified_hash_int = mod_exp(S_int, e, N)
    return format(verified_hash_int, '064x') == hash_hex