import socket
import threading
import logging
from criptografia import gerar_chave_DH, calcular_PSK, criptografar, descriptografar, gerar_hmac, verificar_hmac

# Configurar logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Configurações do servidor
IP = "0.0.0.0"  # Use "0.0.0.0" para aceitar conexões de qualquer interface
PORTA = 65432

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
            mensagem = cliente_socket.recv(1024)
            if not mensagem:
                logging.info("Conexão com cliente encerrada.")
                break
            hmac_recebido = mensagem[-32:]
            mensagem = mensagem[:-32]
            if verificar_hmac(mensagem, hmac_recebido, chave_simetrica):
                mensagem_descriptografada = descriptografar(mensagem, chave_simetrica)
                logging.info(f"Cliente: {mensagem_descriptografada}")
                
                resposta = input("Servidor: ")
                resposta_criptografada = criptografar(resposta, chave_simetrica)
                hmac_resposta = gerar_hmac(resposta_criptografada, chave_simetrica)
                cliente_socket.send(resposta_criptografada + hmac_resposta)
            else:
                logging.warning("HMAC não corresponde, mensagem possivelmente adulterada.")
    except Exception as e:
        logging.error(f"Erro no servidor: {e}")
    finally:
        cliente_socket.close()
        logging.info("Conexão fechada.")

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
