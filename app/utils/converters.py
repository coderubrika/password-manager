import base64


def bytes_to_base64_utf8(data: bytes):
    return base64.b64encode(data).decode('utf-8')


def base64_utf8_to_bytes(data: str):
    return base64.b64decode(data.encode('utf-8'))