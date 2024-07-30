import os
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt
import hmac
import hashlib

# Função para gerar chave DH usando primos maiores
def gerar_chave_DH():
    p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
    g = 2
    chave_privada = secrets.randbelow(p)
    chave_publica = pow(g, chave_privada, p)
    return chave_privada, chave_publica

# Função para calcular PSK
def calcular_PSK(chave_publica_outra, chave_privada):
    p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
    PSK = pow(chave_publica_outra, chave_privada, p)
    chave_simetrica = scrypt(str(PSK).encode(), salt=os.urandom(16), key_len=32, N=2**14, r=8, p=1)
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

# Função para gerar HMAC
def gerar_hmac(mensagem, chave):
    return hmac.new(chave, mensagem, hashlib.sha256).digest()

# Função para verificar HMAC
def verificar_hmac(mensagem, hmac_recebido, chave):
    hmac_calculado = gerar_hmac(mensagem, chave)
    return hmac.compare_digest(hmac_calculado, hmac_recebido)
