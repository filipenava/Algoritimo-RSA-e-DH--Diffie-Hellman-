import socket
import secrets
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt

# Configurar logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Função para gerar chave DH
def gerar_chave_DH():
    p = 23  # Número primo
    g = 5   # Raiz primitiva
    chave_privada = secrets.randbelow(p)
    chave_publica = pow(g, chave_privada, p)
    return chave_privada, chave_publica

# Função para calcular PSK
def calcular_PSK(chave_publica_outra, chave_privada):
    p = 23  # Número primo
    PSK = pow(chave_publica_outra, chave_privada, p)
    chave_simetrica = scrypt(str(PSK).encode(), salt=b'salt', key_len=32, N=2**14, r=8, p=1)
    return chave_simetrica

# Função de criptografia AES
def criptografar(mensagem, chave):
    cipher = AES.new(chave, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(mensagem.encode(), AES.block_size))
    return cipher.iv + ct_bytes

# Função de descriptografia AES
def descriptografar(mensagem, chave):
    iv = mensagem[:AES.block_size]
    ct = mensagem[AES.block_size:]
    cipher = AES.new(chave, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# Configurações do cliente
IP = "127.0.0.1"  # Use o endereço IP adequado para o servidor
PORTA = 65432

def iniciar_cliente():
    try:
        cliente_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cliente_socket.connect((IP, PORTA))
        logging.info("Conectado ao servidor.")
        
        chave_privada, chave_publica = gerar_chave_DH()
        logging.info("Chave DH gerada.")
        chave_publica_servidor = int(cliente_socket.recv(1024).decode())
        logging.info(f"Chave pública do servidor recebida: {chave_publica_servidor}")
        cliente_socket.send(str(chave_publica).encode())
        logging.info("Chave pública enviada ao servidor.")
        
        chave_simetrica = calcular_PSK(chave_publica_servidor, chave_privada)
        logging.info("Chave simétrica calculada.")
        
        while True:
            mensagem = input("Cliente: ")
            mensagem_criptografada = criptografar(mensagem, chave_simetrica)
            cliente_socket.send(mensagem_criptografada)
            
            resposta = cliente_socket.recv(1024)
            if not resposta:
                logging.info("Conexão com servidor encerrada.")
                break
            resposta_descriptografada = descriptografar(resposta, chave_simetrica)
            logging.info(f"Servidor: {resposta_descriptografada}")
    except Exception as e:
        logging.error(f"Erro no cliente: {e}")
    finally:
        cliente_socket.close()
        logging.info("Conexão fechada.")

if __name__ == "__main__":
    iniciar_cliente()
