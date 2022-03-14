from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

import io

#https://www.pycryptodome.org/en/latest/src/examples.html#encrypt-data-with-rsa

class Recipient:
    def __init__(self, public_key: bytes):
        self.public_key = RSA.import_key(public_key)
        self.session_key = get_random_bytes(16)
        self.cipher_rsa = PKCS1_OAEP.new(self.public_key)
        self.enc_session_key = self.cipher_rsa.encrypt(self.session_key)
        self.cipher_aes = AES.new(self.session_key, AES.MODE_EAX)


class Domain:
    def __init__(self):
        key = RSA.generate(2048)
        self.recipients = {}

        self.private_key = key.export_key()
        self.RSA_private_key = RSA.import_key(self.private_key)

        self.public_key = key.publickey().export_key()
        self.RSA_public_key = RSA.import_key(self.public_key)

    def sign_up(self, recipient_key: bytes):
        recipient = Recipient(recipient_key)
        self.recipients[recipient_key] = recipient
        return recipient

    @staticmethod
    def encrypt_data(data: bytes, recipient: Recipient):
        stream = io.BytesIO()
        cipher_text, tag = recipient.cipher_aes.encrypt_and_digest(data)
        [stream.write(b) for b in (recipient.enc_session_key, recipient.cipher_aes.nonce, tag, cipher_text)]
        return stream.getvalue()

    def decrypt_data(self, data_pack: bytes):
        stream = io.BytesIO(data_pack)
        enc_session_key, nonce, tag, cipher_text = \
            [stream.read(x) for x in (self.RSA_private_key.size_in_bytes(), 16, 16, -1)]

        cipher_rsa = PKCS1_OAEP.new(self.RSA_private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(cipher_text, tag)
        return data


if __name__ == '__main__':
    domain = Domain()
    recipient = domain.sign_up(domain.public_key)
    encrypted_data = domain.encrypt_data('Секретное сообщение!'.encode("utf-8"), recipient)
    decrypted_data = domain.decrypt_data(encrypted_data)
    print(decrypted_data.decode('utf-8'))