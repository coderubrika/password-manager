from PyQt5.QtWidgets import *
import sys

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

# первым шагом попробую получить ключи для двух пользователей и передать зашифрованное сообщение в обе стороны
def start():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()

    data = "I met aliens in UFO. Here is the map.".encode("utf-8")
    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    file_out.close()

    file_in = open("encrypted_data.bin", "rb")

    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
        [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data.decode("utf-8"))

    #https://www.pycryptodome.org/en/latest/src/examples.html#encrypt-data-with-rsa
    # key1 = RSA.generate(2048)
    # private_key1 = key1.export_key()
    # public_key1 = key1.publickey().export_key()
    #
    # key2 = RSA.generate(2048)
    # private_key2 = key2.export_key()
    # public_key2 = key2.publickey().export_key()
    #
    # ready_pubk_1 = RSA.import_key(public_key1)
    # ready_pubk_2 = RSA.import_key(public_key2)
    #
    # session_key1_2 = get_random_bytes(16)
    # session_key2_1 = get_random_bytes(16)
    #
    # cipher_rsa1_2 = PKCS1_OAEP.new(ready_pubk_1)
    # cipher_rsa2_1 = PKCS1_OAEP.new(ready_pubk_2)
    #
    # enc_session_key1_2 = cipher_rsa1_2.encrypt(session_key1_2)
    # enc_session_key2_1 = cipher_rsa2_1.encrypt(session_key2_1)
    #
    # cipher_aes1_2 = AES.new(session_key1_2, AES.MODE_EAX)
    # cipher_aes2_1 = AES.new(session_key2_1, AES.MODE_EAX)
    #
    # data1_2 = str.encode('1 to 2   ')
    # data2_1 = str.encode('2 to 1   ')
    #
    # ciphertext1_2, tag1_2 = cipher_aes1_2.encrypt_and_digest(data1_2)
    # ciphertext2_1, tag2_1 = cipher_aes2_1.encrypt_and_digest(data2_1)
    #
    # encrypted_data1_2_before = (enc_session_key1_2, cipher_aes1_2.nonce, tag1_2, ciphertext1_2)
    # encrypted_data2_1_before = (enc_session_key2_1, cipher_aes2_1.nonce, tag2_1, ciphertext2_1)
    #
    # #[print(len(i)) for i in encrypted_data1_2_before]
    # #[print(len(i)) for i in encrypted_data2_1_before]
    # # [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ] reading from file or stream
    #
    #
    # # for 1
    # ready_privk1 = RSA.import_key(private_key1)
    # cipher_rsa1 = PKCS1_OAEP.new(ready_privk1)
    # session_key2_1 = cipher_rsa1.decrypt(encrypted_data2_1_before[0])
    # cipher_aes_after2_1 = AES.new(session_key2_1, AES.MODE_EAX, encrypted_data2_1_before[1])
    # data2_1_after = cipher_aes_after2_1.decrypt_and_verify(encrypted_data2_1_before[3], encrypted_data2_1_before[2])
    # print(data2_1_after.decode("utf-8"))
    #
    # #for 2
    # ready_privk2 = RSA.import_key(private_key2)
    # cipher_rsa2 = PKCS1_OAEP.new(ready_privk2)
    # session_key1_2 = cipher_rsa2.decrypt(encrypted_data1_2_before[0])
    # cipher_aes_after1_2 = AES.new(session_key1_2, AES.MODE_EAX, encrypted_data1_2_before[1])
    # data1_2_after = cipher_aes_after1_2.decrypt_and_verify(encrypted_data1_2_before[3], encrypted_data1_2_before[2])
    # print(data1_2_after.decode("utf-8"))

"""
что делать то будем, во первых мне нужно работать с несколькими окнами, эти окна типо представления
реализую стандартную систему MVC 
есть представления которые работают с контроллерами, а те получают данные из моделей и отдают из представлениям
вроде все просто, но вот что важно, так это что мне нужно как то обеспечить правильную работу представлений, 
и наверное конроллеры будут ее обеспечивать, включать и выключать окна

мне нужен механизм отображения типо скрин фреймов и в рамках вроде как одного окна
и я уверен эта концепция уже есть в QT тогда напишем пока контроллеры не трогабщие прям представление

пока напишем папку 

надо что сделать наладить обмен данными с сервисом как его, с сервисом Firebase

хоть какой то
"""