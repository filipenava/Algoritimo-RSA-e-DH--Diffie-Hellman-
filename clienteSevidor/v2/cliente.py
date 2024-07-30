import socket
import logging
from criptografia import gerar_chave_DH, calcular_PSK, criptografar, descriptografar, gerar_hmac, verificar_hmac

# Configurar logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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
            hmac_mensagem = gerar_hmac(mensagem_criptografada, chave_simetrica)
            cliente_socket.send(mensagem_criptografada + hmac_mensagem)
            
            resposta = cliente_socket.recv(1024)
            if not resposta:
                logging.info("Conexão com servidor encerrada.")
                break
            hmac_recebido = resposta[-32:]
            resposta = resposta[:-32]
            if verificar_hmac(resposta, hmac_recebido, chave_simetrica):
                resposta_descriptografada = descriptografar(resposta, chave_simetrica)
                logging.info(f"Servidor: {resposta_descriptografada}")
            else:
                logging.warning("HMAC não corresponde, mensagem possivelmente adulterada.")
    except Exception as e:
        logging.error(f"Erro no cliente: {e}")
    finally:
        cliente_socket.close()
        logging.info("Conexão fechada.")

if __name__ == "__main__":
    iniciar_cliente()
