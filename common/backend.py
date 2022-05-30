from typing import List, Optional
import socket
from threading import Thread
from .connection import Socket
from .mytypes import Address
from abc import ABC, abstractmethod
import logging
import select


class StreamServer(ABC):
    sock: socket.socket
    addr: Address
    serving: bool

    def __init__(self, addr: Address) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addr = addr
        self.serving = False

    @abstractmethod
    def handle(self, conn: socket.socket, addr: Address) -> None:
        ...

    def serve_forever(self) -> None:
        self.sock.bind(self.addr)
        self.sock.listen()
        self.serving = True
        while self.serving:
            conn, addr = self.sock.accept()
            spawn(self.handle, conn, addr)

    def close(self):
        self.serving = False


def spawn(f, *args):
    t = Thread(target=f, daemon=True, args=args)
    t.start()
    return t


def joinall(threads: List[Thread], start=True) -> None:
    if start:
        for t in threads:
            t.start()
    for t in threads:
        t.join()


def forward(src: Socket, dst: Socket, buffer: int = 1024, logger: Optional[logging.Logger] = None) -> None:
    try:
        while src.is_open() and dst.is_open():
            data = src.recv(buffer)
            # if logger:
            #   logger.debug(f"[forward] {data}")
            if not data:
                break
            dst.send(data)
    except Exception as ex:
        if logger:
            logger.error(f"[forward] {ex}")


def relay(src: Socket, dst: Socket,
          buffer: int = 1024, timeout: Optional[float] = None) -> None:
    relaying = True
    try:
        while relaying:
            readable, _, _ = select.select([src, dst], [], [], timeout)
            relaying = len(readable) > 0  # если список пуст, это значит, что истек таймаут
            for readable_socket in readable:
                source = readable_socket
                if source is src:
                    destination = dst
                else:
                    destination = src
                data = source.recv_raw(buffer)
                if destination.is_open():  # если есть куда пересылать
                    # перешли трафик на сокет
                    destination.send_raw(data)
                else:  # если нет
                    # то перестань пытаться переслать трафик (тупо некуда слать)
                    relaying = False
    finally:  # любая ошибка - оба сокета сразу закрываются и бб
        src.close()
        dst.close()
