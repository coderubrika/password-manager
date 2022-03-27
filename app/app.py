from PyQt5.QtWidgets import *
import sys, uuid, hashlib, base64
from app.firebase import FirestoreCrudService
from app.encryption import EncryptUser, EncryptUserModel
from app.utils.converters import *


def start():
    FirestoreCrudService.clear()

    # user = EncryptUser(uuid.uuid4())
    #
    # enc_data = user.encrypt(b'Some data')
    #
    #
    # data_pack = {
    #     "hash": hashlib.sha1(enc_data).hexdigest(),
    #     "encrypted_data": bytes_to_base64_utf8(enc_data)
    # }
    #
    # FirestoreCrudService.create(user.get_id(), data_pack)

