from sympy import nextprime

# Generate four unique 310-digit primes
start = 10**309  # Smallest 310-digit number
primes = []
increments = [0, 2000, 3000, 5000]  # Different starting points
for inc in increments:
    prime = nextprime(start + inc)
    if len(str(prime)) == 310:  # Ensure exactly 310 digits
        primes.append(prime)
    else:
        print(f"Warning: Prime {prime} has {len(str(prime))} digits, not 310")

# Print primes
for i, prime in enumerate(primes, 1):
    print(f"Prime {i} (ALICE_P, ALICE_Q, BOB_P, BOB_Q)[{i-1}]: {prime}, Digits: {len(str(prime))}")

# Verify uniqueness
print("Unique primes:", len(set(primes)) == len(primes))