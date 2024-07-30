# Projeto Algoritimo RSA e DH (Diffie–Hellman) - Segurança da Informação

Este projeto foi desenvolvido para a matéria de Segurança da Informação do Professor Ronaldo Toshiaki Oikawa. O projeto inclui a implementação de um servidor e um cliente que utilizam criptografia RSA e Diffie-Hellman para comunicação segura.

## Estrutura do Projeto

- `cliente.py`: Implementação do cliente que se conecta ao servidor, realiza troca de chaves e envia mensagens criptografadas.
- `servidor.py`: Implementação do servidor que aceita conexões de clientes, realiza troca de chaves e responde a mensagens criptografadas.
- `RSA.py`: Implementação da geração de chaves RSA e funções auxiliares.
- `RSASemBiblioteca.py`: Implementação alternativa da geração de chaves RSA sem uso de bibliotecas externas.
- `kpriv.pem` e `kpub.pem`: Arquivos contendo as chaves RSA privada e pública, respectivamente.
- `Algoritmo RSA e DH (Diffie-Hellman).zip`: Arquivo zip contendo materiais adicionais relacionados aos algoritmos RSA e Diffie-Hellman.

## Como Executar

### Requisitos

- Python 3.x
- Bibliotecas:
  - `pycryptodome`
  - `sympy`

Você pode instalar as bibliotecas necessárias com o seguinte comando:

pip install pycryptodome sympy

## Executando o Servidor
Para iniciar o servidor, execute o seguinte comando:
python servidor.py

python cliente.py

O cliente se conectará ao servidor e permitirá o envio de mensagens criptografadas.

## Funcionamento do Código

Troca de Chaves Diffie-Hellman
Ambos, o cliente e o servidor, geram pares de chaves DH (chave privada e chave pública). As chaves públicas são trocadas entre o cliente e o servidor. Usando a chave pública recebida e a chave privada gerada, ambos calculam uma chave simétrica comum para criptografia AES.

## Criptografia AES

Mensagens enviadas entre o cliente e o servidor são criptografadas usando a chave simétrica calculada com AES no modo CBC. A mensagem é primeiro padronizada para o tamanho do bloco AES e então criptografada.

## Geração de Chaves RSA

O arquivo RSA.py contém a implementação da geração de chaves RSA utilizando números primos grandes e a biblioteca sympy para verificar a primalidade dos números. A chave pública é composta pelo par (e, n) e a chave privada pelo par (d, n).

## Exemplo de Uso

Após iniciar o servidor e o cliente, você pode digitar mensagens no terminal do cliente, que serão criptografadas e enviadas ao servidor. O servidor descriptografará e exibirá a mensagem, e poderá enviar uma resposta criptografada de volta ao cliente.


