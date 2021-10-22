import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def decrypt_key_ECB(message, key):
    encryptor = AES.new(key.encode(), AES.MODE_ECB)
    return encryptor.decrypt(message).decode('utf-8')


def decrypt_key_CBC(message, key):
    encryptor = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    return encryptor.decrypt(message).decode('utf-8')


def xor(sir1, sir2):  # functie care returneaza xorul a doua siruri de bytes, intr-un nou sir de bytes
    return bytes([a ^ b for a, b in zip(sir1, sir2)])


def encrypt_cbc(plaintext, key1, client_socket):
    encryptor = AES.new(key1.encode(), AES.MODE_ECB)
    blocks = []
    for i in range(0, int(len(plaintext) / 16) + 1):
        blocks.append(plaintext[i * 16:min(i * 16 + 16, len(plaintext))])
    if len(blocks[-1]) < 16:
        blocks[-1] = blocks[-1].ljust(16)
    criptotext = ''
    criptotext = bytes(criptotext, 'utf-8')
    iv = bytes("iviviviviviviviv", 'utf-8')
    pentru_xor = iv
    for block in blocks:
        de_criptat = xor(block.encode('utf-8'), pentru_xor)
        criptat = encryptor.encrypt(de_criptat)
        client_socket.send(criptat)
        mesaj = client_socket.recv(16).decode()
        print(mesaj)
        criptotext += criptat
        pentru_xor = criptat
    return criptotext


def encrypt_ecb(plaintext, key1, client_socket):
    encryptor = AES.new(key1.encode(), AES.MODE_ECB)
    blocks = []
    for i in range(0, int(len(plaintext) / 16) + 1):
        blocks.append(plaintext[i * 16:min(i * 16 + 16, len(plaintext))])
    if len(blocks[-1]) < 16:
        blocks[-1] = blocks[-1].ljust(16)  # pentru ca functia sa mearga, trebuie sa impartim textul in blocuri de
        # 16, deci daca este un bloc incomplet, il vom completa cu spatii pana la 16
    criptotext = ''
    criptotext = bytes(criptotext, 'utf-8')
    for block in blocks:
        client_socket.send(encryptor.encrypt(block.encode('utf-8')))
        mesaj = client_socket.recv(16).decode()
        print(mesaj)
        criptotext += encryptor.encrypt(block.encode('utf-8'))
    return criptotext


mode = ''
k = "kkkkkkkkkkkkkkkk"
iv = 16 * '\x00'
client_socket_km = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket_km.connect(('127.0.0.1', 8091))

mod_operare = input("Mod criptare:")
if mod_operare == "ECB":
    mode = mod_operare
elif mod_operare == "CBC":
    mode = mod_operare
mod_operare = mod_operare.encode('utf-8')
client_socket_km.send(mod_operare)
cheie_primita = client_socket_km.recv(16)
print(cheie_primita)
client_socket_km.close()
if mode == "ECB":
    cheie_primita_decriptata = decrypt_key_ECB(cheie_primita, k)
elif mode == "CBC":
    cheie_primita_decriptata = decrypt_key_CBC(cheie_primita, k)

print(cheie_primita_decriptata)
client_socket_km.close()
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 8093))
client_socket.send(mod_operare)
print(client_socket.recv(16).decode())
client_socket.send(cheie_primita)

while True:
    ok = client_socket.recv(16).decode()
    if ok == "ok":
        print(ok)
        f = open("1.txt", "r")
        data = f.read()
        print(data)
        if mode == "ECB":  # criptam in functie de modul ales
            criptotext = encrypt_ecb(data, cheie_primita_decriptata, client_socket)
        else:
            criptotext = encrypt_cbc(data, cheie_primita_decriptata, client_socket)
        print(str(criptotext))
        client_socket.close()
        break
