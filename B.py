import socket
from Crypto.Cipher import AES


def decrypt_key_ECB(key, k):
    encryptor = AES.new(k.encode(), AES.MODE_ECB)
    return encryptor.decrypt(key).decode('utf-8')


def decrypt_key_CBC(message, key):
    encryptor = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    return encryptor.decrypt(message).decode('utf-8')


def decrypt_ecb(key, connection):
    encryptor = AES.new(key.encode(), AES.MODE_ECB)
    blocuri = []
    for i in range(0, int(len(criptotext) / 16) + 1):
        blocuri.append(criptotext[i * 16:min(i * 16 + 16, len(criptotext))])
    plaintext = ''
    plaintext = bytes(plaintext, 'utf-8')

    while True:
        bloc = connection.recv(16)
        if not bloc:
            break
        plaintext += encryptor.decrypt(bloc)
        message_send = "ok"
        connection.send(message_send.encode())
    return plaintext.decode('utf-8').strip()


def xorare(sir1, sir2):  # functie care returneaza xorul a doua siruri de bytes, intr-un nou sir de bytes
    return bytes([a ^ b for a, b in zip(sir1, sir2)])


def decrypt_cbc(criptotext, key):
    encryptor = AES.new(key.encode(), AES.MODE_ECB)
    blocuri = []
    for i in range(0, int(len(criptotext) / 16) + 1):
        blocuri.append(criptotext[i * 16:min(i * 16 + 16, len(criptotext))])
    plaintext = ''
    plaintext = bytes(plaintext, 'utf-8')
    iv = bytes("iviviviviviviviv", 'utf-8')
    pentru_xor = iv
    while True:
        bloc = connection.recv(16)
        if not bloc:
            break
        message_send = "ok"
        connection.send(message_send.encode())
        decriptat = encryptor.decrypt(bloc)
        xorat = xorare(decriptat, pentru_xor)
        plaintext += xorat
        pentru_xor = bloc
    return plaintext


mod = ''
k = "kkkkkkkkkkkkkkkk"
iv = 16 * '\x00'
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 8093))
server_socket.listen()

while True:
    connection, address = server_socket.accept()
    with connection:
        print('Connected by', address)
        mod_operare = connection.recv(16).decode()
        if mod_operare == "ECB":
            mod = "ECB"
        elif mod_operare == "CBC":
            mod = "CBC"
        print('mod operare:' + mod_operare)
        connection.send("okk".encode())
        cheie_primita = connection.recv(16)
        if mod == "ECB":
            cheie_primita_decriptata = decrypt_key_ECB(cheie_primita, k)
        elif mod == "CBC":
            cheie_primita_decriptata = decrypt_key_CBC(cheie_primita, k)
        print(cheie_primita_decriptata)
        connection.send('ok'.encode())
        criptotext = "a"
        print('criptotext: ' + str(criptotext))
        if mod == "ECB":
            plaintext = decrypt_ecb( cheie_primita_decriptata, connection)
        else:
            plaintext = decrypt_cbc(criptotext, cheie_primita_decriptata)
        print('criptotext: ')
        print(plaintext)
        connection.close()
        exit(0)