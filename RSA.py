import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys(private_key_file='private_key.pem', public_key_file='public_key.pem'):
    # Gerando a chave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Gerando a chave pública a partir da chave privada
    public_key = private_key.public_key()

    # Serializando a chave privada em PEM
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serializando a chave pública em PEM
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Salvando a chave privada em um arquivo
    with open(private_key_file, 'wb') as f:
        f.write(pem_private_key)

    # Salvando a chave pública em um arquivo
    with open(public_key_file, 'wb') as f:
        f.write(pem_public_key)

    print(f"Chaves RSA geradas e salvas nos arquivos '{private_key_file}' e '{public_key_file}'")

def main():
    print("Gerador de Chaves RSA")
    
    # Solicita o nome dos arquivos ao usuário
    private_key_file = input("Digite o nome do arquivo para salvar a chave privada (ex: private_key.pem): ").strip()
    public_key_file = input("Digite o nome do arquivo para salvar a chave pública (ex: public_key.pem): ").strip()
    
    # Usa valores padrão se o usuário não fornecer os nomes dos arquivos
    if not private_key_file:
        private_key_file = 'private_key.pem'
    if not public_key_file:
        public_key_file = 'public_key.pem'

    # Verifica se os arquivos já existem para evitar sobreescrever
    if os.path.exists(private_key_file) or os.path.exists(public_key_file):
        overwrite = input("Um ou ambos os arquivos já existem. Deseja sobrescrevê-los? (s/n): ").strip().lower()
        if overwrite != 's':
            print("Operação cancelada pelo usuário.")
            return
    
    # Gera as chaves e salva nos arquivos especificados
    generate_rsa_keys(private_key_file, public_key_file)

if __name__ == "__main__":
    main()
