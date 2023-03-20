# Caio de Morais    RA: 082180015
# Juniior Almeida   RA: 082180035
# João Guilherme    RA: 082180011
# Wagner Olimpio    RA: 082180033

import socket
import pickle
import AsynEncryption
import math

encryptionKeys = AsynEncryption.generateKeys()
localIP       = "127.0.0.1"
localPort     = 20001
bufferSize    = 4096
msgFromServer = "Hello UDP Client"
# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))
print("UDP server up and listening")
clientKey = None
decryptedMessage = None
# Send server public key on request and receive client public key
while clientKey is None:
    message, address = UDPServerSocket.recvfrom(bufferSize)
    message, publicKey = pickle.loads(message)
    clientIP = f"Client IP Address: {address}"
    print('Message from client:', message)
    # Send a reply to client
    reply = pickle.dumps((msgFromServer, encryptionKeys[1]))
    UDPServerSocket.sendto(reply, address)
    clientKey = publicKey

# Receive encrypted message from client
while clientKey is not None and decryptedMessage != 'exit':
    clientData, clientAddress = UDPServerSocket.recvfrom(bufferSize)
    cryptedMessage = int.from_bytes(clientData, byteorder='big')
    decryptedMessage = AsynEncryption.decryptMessage(cryptedMessage, encryptionKeys[0])
    clientIP = f"Client IP Address: {clientAddress}"
    print('')
    print('Crypted Message from client:', cryptedMessage)
    print('')
    print('Decrypted Message from client:', decryptedMessage)
    print(clientIP)

    # Send a reply to client
    encryptedMessage = AsynEncryption.encryptMessage(msgFromServer, clientKey)
    numberOfBytes = (encryptedMessage.bit_length() + 7) // 8  # Integer division rounding up
    bytesToSend = encryptedMessage.to_bytes(numberOfBytes, byteorder='big')

    # Send reply to client using UDP socket
    UDPServerSocket.sendto(bytesToSend, clientAddress)
