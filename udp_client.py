# Caio de Morais    RA: 082180015
# Juniior Almeida   RA: 082180035
# João Guilherme    RA: 082180011
# Wagner Olimpio    RA: 082180033

import socket
import AsynEncryption
import math
import pickle

encryptionKeys = AsynEncryption.generateKeys()
requestKeys = str.encode('Requesting server public key')
msgFromClient = None
bufferSize = 4096
privateKey = encryptionKeys[0]
publicKey = encryptionKeys[1]
serverAddressPort = ("127.0.0.1", 20001)

# Cria um soquete UDP no lado do cliente
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Obtendo a chave pública do servidor e compartilhando a chave pública do cliente
requestData = pickle.dumps((requestKeys, publicKey))
UDPClientSocket.sendto(requestData, serverAddressPort)
data1, server_address = UDPClientSocket.recvfrom(bufferSize)
firstServerMessage, serverKey = pickle.loads(data1)
print(firstServerMessage)
print('')
print('server public key => ', serverKey)

# Trocando informações entre os servers
while True:
    msgFromClient = input("\nDigite sua mensagem: ")
    if msgFromClient == 'exit':
        break

    encryptedMessage = AsynEncryption.encryptMessage(msgFromClient, serverKey)
    numberOfBytes = (encryptedMessage.bit_length() + 7) // 8
    bytesToSend = encryptedMessage.to_bytes(numberOfBytes, byteorder='big')

   # Envia para o servidor usando o soquete UDP criado
    UDPClientSocket.sendto(bytesToSend, serverAddressPort)

    serverData, clientAddress = UDPClientSocket.recvfrom(bufferSize)
    cryptedMessage = int.from_bytes(serverData, byteorder='big')
    decryptedMessage = AsynEncryption.decryptMessage(
        cryptedMessage, privateKey)

    print('')
    print('Crypted Message from server:', cryptedMessage)
    print('Decrypted Message from server:', decryptedMessage)
