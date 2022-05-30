import random
from .mytypes import AnyBytes, CipherProtocol, EntropySource


def _xor_encrypt(msg: AnyBytes, key: AnyBytes) -> AnyBytes:
    if len(key) > len(msg):
        key = key[:len(msg)]
    key, var = key[:len(msg)], msg[:len(key)]
    int_var = int.from_bytes(var, byteorder="big")
    int_key = int.from_bytes(key, byteorder="big")
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), byteorder="big")


def _xor_decrypt(msg: AnyBytes, key: AnyBytes) -> AnyBytes:
    return _xor_encrypt(msg, key)


def uuid() -> bytes:
    """
    :return: Уникальный ID системы. В пределах сессии один и тот же,
             гарантий на повторное значение при следующем запуске нет.
             Представлен в виде байтов для удобства пересылки через сокет.
    """
    from uuid import getnode
    from getpass import getuser
    from sys import platform
    from hashlib import md5
    u = md5(f"[{platform.upper()}-{getuser()}]$({getnode()})".encode()).digest()[:16]
    while len(u) < 16:
        u += random.getrandbits(8).to_bytes(1, byteorder="big", signed=False)
    return u


class XORBlockCipher(CipherProtocol):
    def __init__(self, key: AnyBytes) -> None:
        self.key = key

    def encrypt(self, msg: AnyBytes) -> AnyBytes:
        key_length = len(self.key)
        message_length = len(msg)
        assert key_length > 0 and message_length > 0
        chunks = []
        for i in range(0, message_length, key_length):
            chunk = msg[i:i + key_length + 1]
            chunks.append(_xor_encrypt(chunk, self.key))
        return b''.join(chunks)

    def decrypt(self, msg: AnyBytes) -> AnyBytes:
        return self.encrypt(msg)


class XORStreamCipher(CipherProtocol):
    ek: EntropySource
    dk: EntropySource

    def __init__(self,
                 ek: EntropySource,
                 dk: EntropySource) -> None:
        self.ek = ek
        self.dk = dk
        self._encryptor_stream = random.Random()
        self._encryptor_stream.seed(ek, version=2)
        self._decryptor_stream = random.Random()
        self._decryptor_stream.seed(dk, version=2)

    @staticmethod
    def _crypt(cryptor_stream: random.Random, message: AnyBytes) -> AnyBytes:
        if not message:
            return bytearray()
        crypted = []
        for b in message:
            key = cryptor_stream.getrandbits(8)
            val = b ^ key
            crypted.append(val)
        return bytearray(crypted)

    def encrypt(self, message: AnyBytes) -> AnyBytes:
        return self._crypt(self._encryptor_stream, message)

    def decrypt(self, message: AnyBytes) -> AnyBytes:
        return self._crypt(self._decryptor_stream, message)
