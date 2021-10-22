import socket
import random
import secrets
from Crypto import Random
from Crypto.Cipher import AES
import os


def cripteaza_cheie_ECB(mesaj, cheie):
    encryptor = AES.new(cheie.encode(), AES.MODE_ECB)
    mesaj = bytes(mesaj, 'utf-8')
    return encryptor.encrypt(mesaj)


def cripteaza_cheie_CBC(mesaj, cheie):
    encryptor = AES.new(cheie.encode(), AES.MODE_CBC, iv.encode())
    mesaj = bytes(mesaj, 'utf-8')
    return encryptor.encrypt(mesaj)


def decripteaza_cheie_CBC(mesage, ke):
    encryptor = AES.new(ke.encode(), AES.MODE_CBC, iv.encode())
    return encryptor.decrypt(mesage).decode('utf-8')


mod = ""
iv = 16 * '\x00'
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('127.0.0.1', 8091))
server.listen()
k = secrets.token_bytes(8).hex()
print(k)
key = "kkkkkkkkkkkkkkkk"

while True:
    connection, address = server.accept()
    with connection:
        print('Connected by', address)
        message = connection.recv(1024)
        if message.decode('utf-8') == "ECB":
            mod = "ECB"
        elif message.decode('utf-8') == "CBC":
            mod = "CBC"
        if mod == "CBC":
            cripKey = cripteaza_cheie_CBC(k, key)
            print(cripteaza_cheie_CBC(k, key))
            li = decripteaza_cheie_CBC(cripKey, key)
            print(li)
            connection.send(cripteaza_cheie_CBC(k, key))
        elif mod == "ECB":
            connection.send(cripteaza_cheie_ECB(k, key))
