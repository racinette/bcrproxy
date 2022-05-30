import socket
from typing import Optional, Tuple, Iterator
from .mytypes import AnyBytes, CipherFunc
from .encryption import CipherProtocol
from secrets import token_bytes


class ProtocolViolationError(Exception):
    pass


def no_encryption(msg: AnyBytes) -> AnyBytes:
    return msg


def polling_time(mn: float, mx: float, c: float) -> Iterator[float]:
    """
    :param mn: стартовое количество
    :param mx: последнее количество
    :param c: коэффициент умножения
    :return: каждый раз возвращает само себя умноженное на коэффициент, пока не достигнет максимального значения.
             после этого всегда возвращает максимум.
    """
    cur = mn
    while True:
        if cur >= mx:
            cur = mx
            yield mx
        else:
            yield cur
        cur = cur * c


def addrinfo_connect(addrinfo: Tuple) -> Optional[socket.socket]:
    family, type, proto, _, address = addrinfo
    sock = socket.socket(family, type, proto)
    try:
        sock.connect(address)
        return sock
    except socket.error:
        sock.close()
        return None


def tcp_connect(host: str, port: int) -> Tuple[Optional[socket.socket], Tuple]:
    """
    Функция пробует подключиться по TCP к удаленному хосту host на порту port
    :param host: хост
    :param port: порт
    :return: кортеж из сокета и результата функции getaddrinfo, при котором удалось подключиться к серверу
             если подключения не вышло, то возвращает (None, ())
    """
    # получить адрес для TCP соединения
    try:
        addrinfos = socket.getaddrinfo(host, port,
                                       socket.AF_UNSPEC,
                                       socket.SOCK_STREAM,
                                       socket.IPPROTO_TCP,
                                       socket.AI_ADDRCONFIG)
    except socket.gaierror:
        # невозможно найти реальный IP
        return None, ()
    # попробовать подключиться к каждому возможному IP
    for addrinfo in addrinfos:
        sock = addrinfo_connect(addrinfo)
        if sock:  # если получилось, верни сокет и информацию об адресе
            return sock, addrinfo
    return None, ()


def different_bytes(b: AnyBytes) -> AnyBytes:
    """
    :param b: данная строка байт
    :return: генерирует случайную строку байт, длиной с данную, но отличную от данной строки
    """
    if not b:
        raise ValueError("Zero length bytes string.")
    diff = token_bytes(len(b))
    while diff == b:
        diff = token_bytes(len(b))
    return diff


def encode_int(i: int, order: str = "big", signed: bool = False) -> bytes:
    """
    :param i: целое число
    :param order: Endianness
    :param signed: знаковое или нет
    :return: кодирует число в байтовый формат, где первый байт - количество байт,
             из скольки состоит число, а остальные - само число
             по понятным причинам число не может быть больше 255 байт
    """
    length = (i.bit_length() + 7) // 8
    try:
        assert 0 < length < 256
    except AssertionError:
        raise ProtocolViolationError(f"{i} length is invalid. Must be (0, 256). Length: {length}.")
    return length.to_bytes(1, byteorder="big", signed=False) + i.to_bytes(length, byteorder=order, signed=signed)


class Socket(socket.socket):
    """
    Convenience wrapper around socket.socket class.
    """
    _encrypt: Optional[CipherFunc]
    _decrypt: Optional[CipherFunc]

    def __init__(self, sock: Optional[socket.socket] = None, encryption: Optional[CipherProtocol] = None):
        # https://stackoverflow.com/questions/51528188/how-to-init-mysocket-object-with-standard-socket-object
        if sock is None:
            super().__init__(family=socket.AF_INET, type=socket.SOCK_STREAM)
        else:
            super().__init__(fileno=sock.detach())
        self.set_encryption(encryption)

    def accept(self):
        addr, s = super().accept()
        s = Socket(s)
        return addr, s

    def set_encryption(self, encryption: Optional[CipherProtocol]):
        if encryption:
            self._encrypt = encryption.encrypt
            self._decrypt = encryption.decrypt
        else:
            self._encrypt = no_encryption
            self._decrypt = no_encryption

    def recv_exact(self, b: AnyBytes) -> bool:
        r = self.recv_raw(len(b))
        return r == b

    def send_raw(self, b: AnyBytes) -> None:
        b = self._encrypt(b)
        self.sendall(b)

    def recv_raw(self, n: int) -> AnyBytes:
        b = self.recv(n)
        return self._decrypt(b)

    def send_msg(self, msg: AnyBytes) -> None:
        if not msg:
            # ничего не отсылай на пустое сообщение
            return
        # Пусть будет так: сообщение может быть длиной от 1 до 255 байт.
        # Если сообщение больше 255 байт, то остальная часть идет в следующий кусок
        for i in range(0, len(msg), 255):
            chunk = msg[i:i + 255]
            length = len(chunk).to_bytes(1, byteorder="big", signed=False)
            self.send_raw(length)
            self.send_raw(chunk)
        # так как длина куска сообщения не может быть 0, то это означает конец сообщения
        self.send_raw(b"\x00")

    def recv_msg(self) -> AnyBytes:
        message = bytearray()
        end_of_message = False
        while not end_of_message:
            chunk_length = self.recv_raw(1)
            if not chunk_length:
                raise ProtocolViolationError(f"Protocol violation. EOF reached before message end. Message: {message}.")
            chunk_length = chunk_length[0]
            if chunk_length == 0:
                break  # конец сообщения
            chunk = self.recv_raw(chunk_length)
            if not chunk or len(chunk) < chunk_length:
                raise ProtocolViolationError("Protocol violation. "
                                             f"Expected: {chunk_length} bytes. Received: {len(chunk)} bytes.")
            message += chunk  # присоединить к сообщению
        return message

    def recv_int(self, order: str = "big", signed: bool = False) -> int:
        length = self.recv_raw(1)
        if not length:
            raise ProtocolViolationError("No length received.")
        length = length[0]
        i = self.recv_raw(length)
        if not i or len(i) != length:
            raise ProtocolViolationError(f"Received: {len(i)} bytes; expected: {length} bytes.")
        i = int.from_bytes(i, byteorder=order, signed=signed)
        return i

    def send_int(self, i: int, order: str = "big", signed: bool = False) -> None:
        return self.send_raw(encode_int(i, order, signed))

    def is_open(self) -> bool:
        return self.fileno() != -1
