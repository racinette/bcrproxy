import rsa
import logging
from typing import Optional, Tuple
from common.connection import tcp_connect, addrinfo_connect, polling_time, Socket, ProtocolViolationError
from common.encryption import uuid, XORStreamCipher, XORBlockCipher
from common.mytypes import AnyBytes
from common.backend import spawn, relay
from common.socks5.const import *
from common.const import *
from secrets import token_bytes
import signal
import socket
from time import sleep


# logger
logging.basicConfig(level="DEBUG")
logger = logging.getLogger()


class ReverseProxyClient:
    """
    Подключается к серверу, получает от него запросы на создание новых сокетов.
    Подключение полностью шифруется.
    """
    host: str
    port: int
    _running: bool
    _master_socket: Optional[Socket]
    _cached_addrinfo: Tuple
    _rsa_public_key: Optional[rsa.PublicKey]
    _uuid: bytes
    new_tunnel_req: Optional[AnyBytes]
    ping_req: Optional[AnyBytes]
    reconnect_req: Optional[AnyBytes]
    pong_resp: Optional[AnyBytes]

    def __init__(self, host: str, port: int, buffer_size: int = 1024) -> None:
        # айди клиента
        self._uuid = uuid()
        print(f"UUID: {self._uuid.hex()}")

        self.host = host
        self.port = port
        self._running = False

        self._master_socket = None
        self._cached_addrinfo = ()
        self._rsa_public_key = None

        self.buffer_size = buffer_size
        self.reconnect_req = None
        self.ping_req = None
        self.pong_resp = None
        self.new_tunnel_req = None

    def _connect_to_master(self) -> bool:
        if self._master_socket is not None:
            # закрыть предыдущее соединение
            self._master_socket.close()
            self._master_socket = None
        if self._cached_addrinfo != ():  # если есть закэшированная информация о адресе сервера
            master_socket = addrinfo_connect(self._cached_addrinfo)
            if master_socket:  # если получилось подключиться к адресу в кэше
                master_socket = Socket(master_socket)
                self._master_socket = master_socket
                return True
        # в другом случае попробовать подключиться заново
        master_socket, self._cached_addrinfo = tcp_connect(self.host, self.port)
        if master_socket is not None:  # если есть сокет и адрес закэшировался, то подключение установлено
            self._master_socket = Socket(master_socket)
            return True
        else:
            self._master_socket = None
            return False

    def create_tunnel(self, tid: bytes, ek: bytes, dk: bytes, cipher_ok: bytes) -> None:
        """
        В этом методе создается обратное прокси соединение к реальному прокси серверу.
        При этом метод не гарантирует создания соединения, он лишь попытается это сделать.
        Расчет идет на то, что если серверу понадобятся еще соединения, то он их запросит.
        :param tid: айди соединения, по которому сервер будет понимать, кто с ним разговаривает
        :param ek: ключ потокового шифрования, который будет использоваться для шифрования трафика
        :param dk: ключ потокового шифрования, который будет использоваться для расшифрования трафика
        :param cipher_ok: сообщение, которое сервер отошлет клиенту при успешной настройке тоннеля
        :return: ничего.
        """

        def f(msg) -> str:
            return f"[create_tunnel]: {msg}"

        tunnel = None
        if self._cached_addrinfo != ():  # попробуй достать из кэша
            tunnel = addrinfo_connect(self._cached_addrinfo)
        if not tunnel:  # все еще нет туннеля
            tunnel, self._cached_addrinfo = tcp_connect(self.host, self.port)
        if not tunnel:
            logger.error(f("Main server connection error."))
            return  # не получилось подключиться, забей

        # подключение получилось!
        tunnel = Socket(tunnel)  # обернем сокет для удобства
        tunnel.send_msg(TUNNEL_SIGNAL)  # отправляем сообщение, что это туннель
        tunnel.send_msg(tid)  # затем сообщаем айди тоннеля
        handshake = tunnel.recv_msg()  # ждем разрешения на подключение

        if handshake != HANDSHAKE_SUCCESS:  # если неправильно, то нет смысла в дальнейшей комуникации
            logger.error(f(f"The server rejected the connection: "
                           f"received: {handshake.hex()}; expected: {HANDSHAKE_SUCCESS.hex()}."))
            tunnel.close()
            return

        cipher = XORStreamCipher(ek=ek, dk=dk)
        tunnel.set_encryption(cipher)  # ставим шифрование
        secret = tunnel.recv_msg()
        tunnel.send_msg(secret)
        status = tunnel.recv_msg()
        if status != cipher_ok:
            logger.error(f(f"The cipher didn't match: "
                           f"received: {status.hex()}; expected: {cipher_ok.hex()}."))
            tunnel.close()
            return
        # все, шифрование настроено
        # теперь необходимо договориться с прокси сервером, к какому удаленному серверу он хочет подключиться
        # основа - 4 секция из SOCKs5 протокола RFC1928 (https://datatracker.ietf.org/doc/html/rfc1928#section-4)
        # receive protocol version
        version = tunnel.recv_raw(1)
        if not version:
            logger.error(f("No response from the server."))
            tunnel.close()
            return
        if version != PROTOCOL_VERSION:
            logger.error(f(f"Wrong SOCKs protocol version: {version}."))
            reply = form_socks5_reply(CONNECTION_REFUSED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
            tunnel.send_raw(reply)
            tunnel.close()
            return

        # receive command
        cmd = tunnel.recv_raw(1)
        if not cmd:
            # reply is empty, drop the connection
            tunnel.close()
            return
        if cmd != CONNECT_CMD:
            reply = form_socks5_reply(CMD_NOT_SUPPORTED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
            tunnel.send_raw(reply)
            tunnel.close()
            return
        # TODO: the only supported cmd is CONNECT: no BIND or UDP (DIY and commit)

        # next byte must be 0 (reserved value)
        rsv = tunnel.recv_raw(1)
        if not rsv or rsv != RSV:
            # malformed client request
            reply = form_socks5_reply(CONNECTION_REFUSED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
            tunnel.send_raw(reply)
            tunnel.close()
            return None

        atyp = tunnel.recv_raw(1)
        if not atyp:
            # received no data
            tunnel.close()
            return
        if atyp == IPv4_ADDRESS_TYPE:
            # ipv4 has 4 octets (bytes)
            raw_address = tunnel.recv_raw(4)
            if not raw_address:  # no ip received
                tunnel.close()
                return
            if len(raw_address) != 4:
                # got ip address which consists of less than 4 bytes. WTF, client?
                reply = form_socks5_reply(CONNECTION_REFUSED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
                tunnel.send_raw(reply)
                tunnel.close()
                return
            host = socket.inet_ntop(socket.AF_INET, raw_address)  # now it's a string
        elif atyp == IPv6_ADDRESS_TYPE:
            # ipv6 has 16 octets (bytes)
            raw_address = tunnel.recv_raw(16)
            if not raw_address:  # no ip received
                tunnel.close()
                return None
            if len(raw_address) != 16:
                # got ip address which consists of less than 16 bytes
                reply = form_socks5_reply(CONNECTION_REFUSED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
                tunnel.send_raw(reply)
                tunnel.close()
                return
            host = socket.inet_ntop(socket.AF_INET6, raw_address)  # now it's a string
        elif atyp == DOMAIN_NAME_ADDRESS_TYPE:
            domain_length = tunnel.recv_raw(1)
            if not domain_length:  # no data: dump the client
                tunnel.close()
                return None
            raw_address = domain_length
            domain_length = domain_length[0]
            if domain_length < 1:
                # domain with 0 length? srsly?
                reply = form_socks5_reply(CONNECTION_REFUSED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
                tunnel.send_raw(reply)
                tunnel.close()
                return
            # recv domain
            domain = tunnel.recv_raw(domain_length)
            if not domain:
                tunnel.close()
                return
            elif len(domain) < domain_length:
                reply = form_socks5_reply(CONNECTION_REFUSED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
                tunnel.send_raw(reply)
                tunnel.close()
                return
            raw_address += domain
            host = domain.decode("idna")
        else:
            # such address type is not supported
            reply = form_socks5_reply(ADDRESS_TYPE_NOT_SUPPORTED_REPLY, atyp, IPv4_ADDRESS_TYPE, PORT_0)
            tunnel.send_raw(reply)
            tunnel.close()
            return

        # now receive port
        raw_port = tunnel.recv_raw(2)
        if not raw_port or len(raw_port) != 2:
            tunnel.close()
            return
        # big endian
        port = int.from_bytes(raw_port, "big", signed=False)
        # now the proxy server should try to connect to the remote server
        dst, addrinfo = tcp_connect(host, port)
        if (dst, addrinfo) == (None, ()):
            reply = form_socks5_reply(HOST_UNREACHABLE_REPLY, atyp, raw_address, raw_port)
            tunnel.send_raw(reply)
            tunnel.close()
            return

        family, type, proto, _, address = addrinfo
        # only two valid address families: IPv4 and IPv6
        if family == socket.AF_INET:
            str_ip, int_port = address
            int_port = int(port)
            raw_ip = socket.inet_pton(socket.AF_INET, str_ip)
            raw_port = int_port.to_bytes(2, "big", signed=False)
            # server responds to the client, that it has successfully connected to the remote server,
            # using the IPv4 address
            reply = form_socks5_reply(SUCCEEDED_REPLY, IPv4_ADDRESS_TYPE, raw_ip, raw_port)
            tunnel.send_raw(reply)
            logger.debug(f(f"-> {str_ip}:{int_port}"))
        elif family == socket.AF_INET6:
            # getaddrinfo returns a tuple of 4 elements for IPv6 addresses
            str_ip, int_port, _, _ = address
            int_port = int(port)
            raw_ip = socket.inet_pton(socket.AF_INET6, str_ip)
            raw_port = int_port.to_bytes(2, "big", signed=False)
            # server responds to the client, that it has successfully connected to the remote server,
            # using the IPv4 address
            reply = form_socks5_reply(SUCCEEDED_REPLY, IPv6_ADDRESS_TYPE, raw_ip, raw_port)
            tunnel.send_raw(reply)
            logger.debug(f(f"-> {str_ip}:{int_port}"))
        else:
            # wasn't able to connect to any of the hosts
            reply = form_socks5_reply(HOST_UNREACHABLE_REPLY, atyp, raw_address, raw_port)
            tunnel.send_raw(reply)
            tunnel.close()
            return

        dst = Socket(dst)  # обернуть для удобства
        # если код дошел сюда, то прокси соединение было успешно установлено
        # и дальше можно просто херачить траффик в обе стороны до закрытия сокетов
        logger.debug(f(f"Tunnel to {host}:{port} open."))
        timeout = 10.
        relay(tunnel, dst, self.buffer_size, timeout)
        # туннель выполнил обмен данными и закрылся

    def pong(self) -> None:
        self._master_socket.send_msg(self.pong_resp)

    def close(self):
        self._running = False

    def serve_forever(self) -> None:
        def f(m) -> str:
            return f"[serve_forever]: {m}"

        dt = 5.
        self._running = True
        while self._running:
            try:
                # время ожидания до повторного подключения
                # сначала ждет 3 секунды, потом 3 * 1.2 и тд до 90 секунд, и теперь вечно ждет по 90 сек
                t = polling_time(3., 90., 1.2)
                connected_to_master = False
                while not connected_to_master:
                    connected_to_master = self._connect_to_master()
                    if not connected_to_master:
                        t1 = next(t)
                        logger.error(f(f"Couldn't connect to the server. Retrying in {t1} seconds."))
                        sleep(t1)  # подождать перед переподключением
                # на этом моменте подключение к мастер каналу уже установлено
                # показать серверу, что устанавливается мастер соединение
                self._master_socket.send_msg(MASTER_SIGNAL)
                handshake_response = self._master_socket.recv_msg()
                if handshake_response != HANDSHAKE_SUCCESS:
                    logger.error(f(f"Handshake unsuccessful. Retrying in {dt} seconds."))
                    sleep(dt)  # подождать перед переподключением
                    continue  # вернуться в начало while петли и пробовать сначала

                # теперь клиент получает свой публичный ключ
                n = self._master_socket.recv_int("big", False)
                e = self._master_socket.recv_int("big", False)
                status_msg_len = self._master_socket.recv_int("big", False)
                stream_key_len = self._master_socket.recv_int("big", False)

                if n is None or e is None:
                    logger.error(f(f"RSA key exchange failure: n = {n}, e = {e}. Retrying in {dt} seconds."))
                    sleep(dt)
                    continue
                self._rsa_public_key = rsa.PublicKey(n, e)

                # теперь можно договориться о поточном шифровании
                # клиент генерирует ключи
                encryption_key = token_bytes(stream_key_len)
                decryption_key = token_bytes(stream_key_len)
                status_ok = token_bytes(status_msg_len)

                c1 = rsa.encrypt(encryption_key, self._rsa_public_key)  # первая часть
                self._master_socket.send_msg(c1)
                c2 = rsa.encrypt(decryption_key, self._rsa_public_key)  # вторая часть
                self._master_socket.send_msg(c2)
                c3 = rsa.encrypt(status_ok, self._rsa_public_key)
                self._master_socket.send_msg(c3)

                cipher = XORStreamCipher(ek=encryption_key, dk=decryption_key)  # сервер поставит их наоборот
                self._master_socket.set_encryption(cipher)  # поставить шифрование на сокет

                # проверка, являются ли сгенерированные последовательности одинаковыми.
                # сервер генерирует случайную последовательность байт, которую шифрует заранее обговоренным ключом
                secret = self._master_socket.recv_msg()
                # последовательность будет другой, т.к. для шифрования используется 2 разных ключа
                self._master_socket.send_msg(secret)
                status = self._master_socket.recv_msg()  # ждем ответа
                if status != status_ok:
                    logger.error(f(f"Stream ciphers didn't match. Retrying in {dt} seconds."))
                    sleep(dt)
                    continue
                # если дошло сюда, то все окей и шифрование можно спокойно использовать
                # финальный шаг рукопожатия: передача идентификатора клиента
                pk_enc_uuid = rsa.encrypt(self._uuid, self._rsa_public_key)
                # практически ради этого момента существовало все шифрование
                # если атакующий сервер знал бы uuid клиента, он бы мог в момент отсоединения мастер сокета
                # притвориться этим клиентом. Благодаря шифрованию, невозможно узнать, какой uuid имеет подключившийся
                # клиент в случае MITM атаки.
                self._master_socket.send_msg(pk_enc_uuid)

                # новое статус ок сообщение
                status_ok = token_bytes(status_msg_len)
                self._master_socket.send_msg(status_ok)

                # если получили то же, что отправили, то все круто
                final_status = self._master_socket.recv_msg()
                if final_status != status_ok:
                    # сервер может уже иметь мастер подключение с таким айди
                    logger.error(f(f"Server didn't accept the connection. Retrying in {dt} seconds."))
                    sleep(dt)
                    continue
                # теперь получаем значения каждого возможного сообщения:
                self.new_tunnel_req = self._master_socket.recv_msg()
                self.ping_req = self._master_socket.recv_msg()
                self.reconnect_req = self._master_socket.recv_msg()
                self.pong_resp = self._master_socket.recv_msg()
                # готово!
            except socket.gaierror as ex:
                logger.error(f(f"Gaierror: {ex}"))
                continue  # начни петлю заново
            except socket.error as ex:
                logger.error(f(f"Socket error: {ex}"))
                continue  # начни петлю заново
            except ProtocolViolationError as ex:
                logger.error(f(f"Protocol error: {ex}"))
                continue  # начни петлю заново
            except Exception as ex:
                logger.error(f(f"Unknown error: {ex}"))
                continue
            # после этого в петле получает сообщения от сервера
            while self._running:
                try:
                    req = self._master_socket.recv_msg()
                    if req == self.new_tunnel_req:
                        # создание нового TCP туннеля
                        # сервер должен прислать еще:
                        # - id туннеля, XOR-зашифрованное uuid клиента
                        # - ключ для потокового шифрования
                        # - ключ для потокового расшифрования
                        # - сигнал, который придет от сервера, если настройка шифрования будет удачной

                        # это значение скорее обфусцируется, чем шифруется,
                        # т.к. впоследствии оно передается без шифра, а это может ставить под угрозу
                        # мастер-ключ от основного соединения
                        tid = self._master_socket.recv_msg()

                        xor = XORBlockCipher(self._uuid)
                        tid = xor.decrypt(tid)

                        encryption_key = self._master_socket.recv_msg()
                        decryption_key = self._master_socket.recv_msg()
                        cipher_ok = self._master_socket.recv_msg()

                        logger.debug(f(f"Tunnel {tid.hex()} requested."))
                        spawn(self.create_tunnel, tid, encryption_key, decryption_key, cipher_ok)
                    elif req == self.ping_req:
                        # понгнуть сервер
                        logger.debug(f("Pong requested."))
                        spawn(self.pong)
                    elif req == self.reconnect_req:
                        # выходим из этого лупа, родительский начинается заново
                        logger.debug(f("Reconnection requested."))
                        break
                    else:
                        logger.debug(f(f"Unknown message: {req}."))
                    # в принципе, больше ничего не нужно
                except socket.error or socket.gaierror as ex:
                    # переподключение при ошибке
                    logger.error(f(f"Socket error: {ex}"))
                    sleep(dt)
                    break
                except ProtocolViolationError as ex:
                    logger.error(f(f"Protocol violation error: {ex}"))
                    sleep(dt)
                    break
                except Exception as ex:
                    logger.error(f(f"Unknown error: {ex}"))
                    sleep(dt)
                    break


def print_help():
    print("Use exactly 1 argument in form of 'host:port' string.")
    print("To see this message again, use '-h' or '--help'.")


if __name__ == "__main__":
    import sys

    host = None
    port = None

    args = sys.argv[1:]

    if len(args) == 1 and args[0].lower() in {"--help", "-h"}:
        print_help()
        sys.exit(0)

    if len(args) == 1:
        host, port = args[0].rsplit(":", 1)
    else:
        print(f"Wrong number of arguments: {len(args)}.")
        print_help()
        sys.exit(-1)

    try:
        port = int(port)
        assert 0 < port < 65536
    except ValueError:
        print(f"Unable to parse value to port number: {port}.")
        sys.exit(-1)

    client = ReverseProxyClient(host, port)

    def stop(sig, frame):
        client.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    client.serve_forever()
