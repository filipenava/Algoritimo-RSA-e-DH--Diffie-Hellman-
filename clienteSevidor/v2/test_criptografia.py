import unittest
from criptografia import gerar_chave_DH, calcular_PSK, criptografar, descriptografar, gerar_hmac, verificar_hmac

class TestCriptografia(unittest.TestCase):

    def test_criptografia(self):
        chave_privada, chave_publica = gerar_chave_DH()
        chave_privada_outra, chave_publica_outra = gerar_chave_DH()
        
        chave_simetrica = calcular_PSK(chave_publica_outra, chave_privada)
        chave_simetrica_outra = calcular_PSK(chave_publica, chave_privada_outra)
        
        self.assertEqual(chave_simetrica, chave_simetrica_outra)
        
        mensagem = "Teste de mensagem"
        mensagem_criptografada = criptografar(mensagem, chave_simetrica)
        mensagem_descriptografada = descriptografar(mensagem_criptografada, chave_simetrica)
        
        self.assertEqual(mensagem, mensagem_descriptografada)
        
        hmac_mensagem = gerar_hmac(mensagem_criptografada, chave_simetrica)
        self.assertTrue(verificar_hmac(mensagem_criptografada, hmac_mensagem, chave_simetrica))

if __name__ == '__main__':
    unittest.main()
