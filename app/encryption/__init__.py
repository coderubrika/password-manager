from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

from app.utils.converters import *

import io
import hashlib
import uuid
import copy
import json
import pickle

# https://www.pycryptodome.org/en/latest/src/examples.html#encrypt-data-with-rsa
# https://stackoverflow.com/questions/54082280/typeerror-decrypt-cannot-be-called-after-encrypt

class Recipient:
    def __init__(self, public_key: bytes):
        self.public_key = RSA.import_key(public_key)
        self.session_key = get_random_bytes(16)
        self.cipher_rsa = PKCS1_OAEP.new(self.public_key)
        self.enc_session_key = self.cipher_rsa.encrypt(self.session_key)
        self.cipher_aes = AES.new(self.session_key, AES.MODE_EAX)


class Domain:
    # domain = Domain()
    # recipient = domain.sign_up(domain.public_key)
    # encrypted_data = domain.encrypt_data('Секретное сообщение!'.encode("utf-8"), recipient)
    # decrypted_data = domain.decrypt_data(encrypted_data)
    # print(decrypted_data.decode('utf-8'))
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


class EncryptUserModel:
    id = None
    session_key = None
    nonce = None
    tag = None


class EncryptUser:
    def __init__(self):
        self.model: EncryptUserModel

    def create(self):
        self.model = EncryptUserModel()
        self.model.id = str(uuid.uuid4())
        self.model.session_key = get_random_bytes(16)
        self.model.e_cipher = AES.new(self.model.session_key, AES.MODE_EAX)
        return self

    def load(self, model: EncryptUserModel):
        self.model = copy.deepcopy(model)

    def to_json(self):
        json_model = {
            "id": self.model.id,
            "session_key": bytes_to_base64_utf8(self.model.session_key),
            "e_cipher" : bytes_to_base64_utf8(self.model.e_cipher),
            "d_cipher" : bytes_to_base64_utf8(self.model.d_cipher),
            "tag" : bytes_to_base64_utf8(self.model.tag),
        }
        return json.dumps(json_model)

    def from_json(self, json_dump):
        json_model = json.load(json_dump)
        self.model = EncryptUserModel()

        json_model['session_key'] = base64_utf8_to_bytes(json_model['session_key'])
        json_model['e_cipher'] = base64_utf8_to_bytes(json_model['e_cipher'])
        json_model['d_cipher'] = base64_utf8_to_bytes(json_model['d_cipher'])
        json_model['tag'] = base64_utf8_to_bytes(json_model['tag'])

        self.update(**json_model)

    def update(self, **kwarg):
        self.model.id = kwarg['id']
        self.model.session_key = kwarg['session_key']
        self.model.e_cipher = kwarg['e_cipher']
        self.model.d_cipher = kwarg['d_cipher']
        self.model.tag = kwarg['tag']

    def get_model(self):
        return copy.deepcopy(self.model)

    def get_id(self):
        return self.model.id

    def encrypt(self, raw_data: bytes):
        cipher_data, tag = self.model.e_cipher.encrypt_and_digest(raw_data)
        self.model.d_cipher = AES.new(self.model.session_key,
                                      AES.MODE_EAX,
                                      self.model.e_cipher.nonce)
        self.model.tag = tag
        return cipher_data

    def decrypt(self, cipher_data: bytes):
        raw_data = self.model.d_cipher.decrypt_and_verify(cipher_data, self.model.tag)
        return raw_data


if __name__ == '__main__':
    user = EncryptUser().create()
    enc_data = user.encrypt('Секретное сообщение!'.encode("utf-8"))
    print(user.decrypt(enc_data).decode('utf-8'))

    # print(hashlib.sha3_512(cipher1.nonce).hexdigest())
    # print(hashlib.sha3_512(cipher1.nonce).hexdigest())

