from typing import Union, Protocol, Callable, Tuple


AnyBytes = Union[bytes, bytearray]
EntropySource = Union[int, bytes, bytearray, float, str]

CipherFunc = Callable[[AnyBytes], AnyBytes]
Address = Tuple[str, int]


class CipherProtocol(Protocol):
    def encrypt(self, message: AnyBytes) -> AnyBytes:
        ...

    def decrypt(self, message: AnyBytes) -> AnyBytes:
        ...
