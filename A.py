import codecs
import socket
import threading
from base64 import b64decode
from Crypto.Cipher import AES

#Cheia distribuita
K3 = 'AE8CBA23765432110123236789ABCDXY'

HOST_B = 'localhost'
PORT_B = 9997

HOST_KM = 'localhost'
PORT_KM = 9991

iv = bytearray(16)

file_to_read = ''

#Functie auxiliara pentru padding
def pad(text):
    if len(text) % 16 == 0:
        return text
    data = text + (16 - (len(text) % 16)) * b'\x00'
    return data


#criptare ECB
def encrypt_text_ECB(text, key, s):
    text = pad(text)
    cipher = AES.new(key.encode('utf8'), AES.MODE_ECB)
    for bloc in range(len(text) // 16 ):
        block_enc = cipher.encrypt(text[bloc * 16:(bloc + 1) * 16])
        s.sendall(codecs.encode(block_enc, 'base64'))

#Functie auxiliara pentru xor
def XOR(input_bytes, key_input):
    index = 0
    output_bytes = b''
    for byte in input_bytes:
        if index >= len(key_input):
            index = 0
        output_bytes += bytes([byte ^ key_input[index]])
        index += 1
    return output_bytes


#criptare CBC

def encrypt_text_CBC(text, key, s):
    global iv
    text = pad(text)
    cipher = AES.new(key.encode('utf8'), AES.MODE_ECB)
    iv = '0' * 16
    for b in range(len(text) // 16 ):
        enc = XOR(text[b * 16: (b + 1) * 16], iv)
        enc = cipher.encrypt(enc)
        iv = enc
        s.sendall(codecs.encode(enc, 'base64'))


def send_text(s, key_decrypted):
    global file_to_read
    with open(file_to_read, "rb") as fd:
        text = fd.read()
        if operation_mode == "ECB":
            encrypt_text_ECB(text, key_decrypted, s)
        elif operation_mode == "CBC":
            encrypt_text_CBC(text, key_decrypted, s)


def decrypt_key_ECB(key):
    return AES.new(K3.encode('utf8'), AES.MODE_ECB).decrypt(b64decode(key)).decode('utf8')


def decrypt_key_CBC(key):
    iv = '0' * 16
    cipher = AES.new(K3.encode('utf8'), AES.MODE_ECB)
    key = cipher.encrypt(key)
    decrypt = XOR(b64decode(key), iv)
    return decrypt.decode('utf8')


def receive_KM(s_km, s):
    while True:
        received = s_km.recv(1024)
        received = received.decode()
        if not received:
            break
        else:
            # print(received)
            key = received.split()[-1]
            if operation_mode == "ECB":
                key_decrypted = decrypt_key_ECB(key)
                send_text(s, key_decrypted)
            else:
                key_decrypted = decrypt_key_CBC(key)
                send_text(s, key_decrypted)


def receive_B(s):
    global start_communication
    while True:
        try:
            r_msg = s.recv(1024).decode()
            if not r_msg:
                break
            else:
                if "Start" in r_msg:
                    start_communication = 1
        except:
            raise
            break


def send_msg(s, s_km):
    global file_to_read
    global operation_mode
    while True:
        operare = input("Introduceti modul de operare(ECB sau CBC)")
        file_to_read = input("Introduceti numele fisierului de criptat: ")
        if operare == '':
            pass
        else:
            if operare.upper().strip() == "ECB" or operare.upper().strip() == "CBC":
                operation_mode = operare
                try:
                    s.sendall("[A] [MODE]: {}".format(operare).encode())
                    s_km.sendall("[A] [KEY-A]: {}".format(operare).encode())
                except:
                    raise
            else:
                print("Modul de criptare indisponibil.")


if __name__ == '__main__':
    start_communication = 0
    operation_mode = ''

    socket_B = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_KM = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    socket_B.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socket_KM.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    socket_B.connect((HOST_B, PORT_B))
    socket_KM.connect((HOST_KM, PORT_KM))

    thread1 = threading.Thread(target=receive_B, args=([socket_B]))
    thread2 = threading.Thread(target=receive_KM, args=([socket_KM, socket_B]))
    thread3 = threading.Thread(target=send_msg, args=([socket_B, socket_KM]))
    try:
        thread1.start()
        thread2.start()
        thread3.start()
    except:
        thread1.join()
        thread2.join()
        thread3.join()
        socket_B.close()
        socket_KM.close()
