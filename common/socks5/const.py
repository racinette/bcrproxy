PROTOCOL_VERSION = b'\x05'

NO_AUTH_METHOD = b'\x00'
GSSAPI_METHOD = b'\x01'
USERNAME_PASSWORD_METHOD = b'\x02'
NO_ACCEPTABLE_METHODS = b'\xFF'

# when client sends authentication methods and none of them match the accepted ones
HANDSHAKE_FAILURE_MESSAGE = PROTOCOL_VERSION + NO_ACCEPTABLE_METHODS

# client commands
CONNECT_CMD = b'\x01'
BIND_CMD = b'\x02'
UPD_ASSOCIATE_CMD = b'\x03'

# server replies
SUCCEEDED_REPLY = b'\x00'
SERVER_FAILURE_REPLY = b'\x01'
CONNECTION_NOT_ALLOWED_REPLY = b'\x02'
NETWORK_UNREACHABLE_REPLY = b'\x03'
HOST_UNREACHABLE_REPLY = b'\x04'
CONNECTION_REFUSED_REPLY = b'\x05'
TTL_EXPIRED_REPLY = b'\x06'
CMD_NOT_SUPPORTED_REPLY = b'\x07'
ADDRESS_TYPE_NOT_SUPPORTED_REPLY = b'\x08'

# reserved
RSV = b'\x00'

# address types
IPv4_ADDRESS_TYPE = b'\x01'
DOMAIN_NAME_ADDRESS_TYPE = b'\x03'
IPv6_ADDRESS_TYPE = b'\x04'

EMPTY_IPv4 = b'\x00\x00\x00\x00'
PORT_0 = b'\x00\x00'

USERNAME_PASSWORD_AUTH_FAILED = b'\x01\x01'
USERNAME_PASSWORD_AUTH_SUCCESS = b'\x01\x00'


def form_socks5_reply(rep: bytes, atyp: bytes, bnd_addr: bytes, bnd_port: bytes) -> bytearray:
    try:
        assert len(rep) == 1
        assert len(atyp) == 1
        if atyp == IPv4_ADDRESS_TYPE:
            assert len(bnd_addr) == 4
        elif atyp == IPv6_ADDRESS_TYPE:
            assert len(bnd_addr) == 16
        elif atyp == DOMAIN_NAME_ADDRESS_TYPE:
            assert len(bnd_addr) - 1 == bnd_addr[0]
        else:
            raise AssertionError(f"Address Type is: {atyp}, but {bnd_addr} was provided.")
        assert len(bnd_port) == 2
    except AssertionError:
        raise ValueError(f'REP:{rep};\nATYP:{atyp};\nBND_ADDR:{bnd_addr};\nBND_PORT:{bnd_port};')
    arr = bytearray()
    arr += PROTOCOL_VERSION
    arr += rep
    arr += RSV
    arr += atyp
    arr += bnd_addr
    arr += bnd_port
    return arr
