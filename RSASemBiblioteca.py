import random
from sympy import isprime

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_prime_candidate(length):
    p = 1
    while not isprime(p):
        p = random.getrandbits(length)
    return p

def generate_prime_number(length=1024):
    p = generate_prime_candidate(length)
    while not isprime(p):
        p = generate_prime_candidate(length)
    return p

def generate_rsa_keys(key_size=1024):
    e = 65537
    p = generate_prime_number(key_size // 2)
    q = generate_prime_number(key_size // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    d = modinv(e, phi)
    
    return ((e, n), (d, n))

def format_key(key, key_type):
    key_str = f'{key[0]},{key[1]}'
    if key_type == "PRIVATE":
        return f"-----BEGIN RSA PRIVATE KEY-----\n{key_str}\n-----END RSA PRIVATE KEY-----"
    elif key_type == "PUBLIC":
        return f"-----BEGIN PUBLIC KEY-----\n{key_str}\n-----END PUBLIC KEY-----"

def save_key_to_file(filename, key, key_type):
    formatted_key = format_key(key, key_type)
    with open(filename, 'w') as f:
        f.write(formatted_key)

def main():
    print("Gerador de Chaves RSA")
    
    private_key_file = input("Digite o nome do arquivo para salvar a chave privada (ex: private_key.txt): ").strip()
    public_key_file = input("Digite o nome do arquivo para salvar a chave pública (ex: public_key.txt): ").strip()
    
    if not private_key_file:
        private_key_file = 'private_key.txt'
    if not public_key_file:
        public_key_file = 'public_key.txt'
    
    public_key, private_key = generate_rsa_keys()
    
    save_key_to_file(private_key_file, private_key, "PRIVATE")
    save_key_to_file(public_key_file, public_key, "PUBLIC")
    
    print(f"Chaves RSA geradas e salvas nos arquivos '{private_key_file}' e '{public_key_file}'")

if __name__ == "__main__":
    main()
