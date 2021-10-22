import codecs
import socket
import threading
from base64 import b64encode
from Crypto.Cipher import AES

K1, K2, K3 = 'BE9C1AD806A4B2C0A02C459789A1CDE1', 'A9DC9E08795432100A134567E9AD0DEF', 'AE8CBA23765432110123236789ABCDXY'
BLOCK_SIZE = 16  # Bytes


def recMsgA(conn):
    while True:
        received = conn.recv(1024)
        if not received:
            break
        if received == '':
            pass
        else:
            send_key(conn, received, "A")


def recMsgB(conn):
    while True:
        received = conn.recv(1024)
        if not received:
            break
        if received == '':
            pass
        else:
            send_key(conn, received, "B")


def validMode(opt):
    opt = str(opt)
    return True if opt.upper().endswith("ECB") or opt.upper().endswith("CBC") else False


def encrypt_key_ECB():
    global K3
    cipher = AES.new(K3.encode('utf8'), AES.MODE_ECB)
    return b64encode(cipher.encrypt(K1.encode('utf-8')))

def XOR(input_bytes, key_input):
    index = 0
    output_bytes = b''
    for byte in input_bytes:
        if index >= len(key_input):
            index = 0
        output_bytes += bytes([byte ^ key_input[index]])
        index += 1
    return output_bytes


def encrypt_key_CBC():
    global K3
    iv = '0' * 16
    cipher = AES.new(K3.encode('utf8'), AES.MODE_ECB)
    enc = XOR(K2.encode('utf-8'), iv)
    enc = cipher.encrypt(enc)
    return b64encode(enc)


def send_key(conn, received, node):
    operation_mode = received.split()[-1].decode()
    if validMode(operation_mode):
        print("Am primit de la {} modul de operare: ".format(node) + operation_mode)
        if str(operation_mode).upper().endswith("ECB"):
            K1 = encrypt_key_ECB().decode()
            conn.sendall("[KM] [KEY1]: {}".format(str(K1)).encode())
        else:
            K2 = encrypt_key_CBC().decode()
            conn.sendall("[KM] [KEY2]: {}".format(str(K2)).encode())


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 9991))
    s.listen(10)
    print("Listening on localhost, PORT = 9998")
    connection = 0
    while True:
        (conn, addr) = s.accept()
        if connection == 0:
            thread1 = threading.Thread(target=recMsgB, args=([conn]))
        else:
            thread1 = threading.Thread(target=recMsgA, args=([conn]))
        connection += 1
        try:
            thread1.start()
        except KeyboardInterrupt:
            thread1.join()
            conn.close()
            break
