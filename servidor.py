import socket
import threading
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

# Função para lidar com clientes
def lidar_com_cliente(cliente_socket):
    try:
        chave_privada, chave_publica = gerar_chave_DH()
        logging.info("Chave DH gerada.")
        cliente_socket.send(str(chave_publica).encode())
        logging.info("Chave pública enviada ao cliente.")
        
        chave_publica_cliente = int(cliente_socket.recv(1024).decode())
        logging.info(f"Chave pública do cliente recebida: {chave_publica_cliente}")
        chave_simetrica = calcular_PSK(chave_publica_cliente, chave_privada)
        logging.info("Chave simétrica calculada.")
        
        while True:
            # Receber mensagem do cliente
            mensagem = cliente_socket.recv(1024)
            if not mensagem:
                logging.info("Conexão com cliente encerrada.")
                break
            mensagem_descriptografada = descriptografar(mensagem, chave_simetrica)
            logging.info(f"Cliente: {mensagem_descriptografada}")
            
            # Responder ao cliente
            resposta = input("Servidor: ")
            resposta_criptografada = criptografar(resposta, chave_simetrica)
            cliente_socket.send(resposta_criptografada)
    except Exception as e:
        logging.error(f"Erro no servidor: {e}")
    finally:
        cliente_socket.close()
        logging.info("Conexão fechada.")

# Configurações do servidor
IP = "0.0.0.0"  # Use "0.0.0.0" para aceitar conexões de qualquer interface
PORTA = 65432

def iniciar_servidor():
    try:
        servidor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor_socket.bind((IP, PORTA))
        servidor_socket.listen()
        logging.info("Servidor esperando conexão...")
    except Exception as e:
        logging.error(f"Erro ao iniciar o servidor: {e}")
        exit(1)

    while True:
        try:
            cliente_socket, endereco = servidor_socket.accept()
            logging.info(f"Conectado a {endereco}")
            threading.Thread(target=lidar_com_cliente, args=(cliente_socket,)).start()
        except Exception as e:
            logging.error(f"Erro ao aceitar conexão: {e}")

if __name__ == "__main__":
    iniciar_servidor()
