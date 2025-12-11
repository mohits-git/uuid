import os
import time
"""
UUID Custom implementation with python

Implementing only the OSF-DCE (10xx) variant
"""

# 128 bit mask to clear version and variant bits from uuid int
_CLEARFLAG_MASK = ~((0xf000c << 60))
# 128 bit flags to set variant 10xx
_VARIANT_FLAGS = (0x8 << 60)
# 128 bit flags to set version bits for variant 10xx
_VERSION_1_FLAGS = (0x10008 << 60)
_VERSION_2_FLAGS = (0x20008 << 60)
_VERSION_3_FLAGS = (0x30008 << 60)
_VERSION_4_FLAGS = (0x40008 << 60)
_VERSION_5_FLAGS = (0x50008 << 60)
_VERSION_6_FLAGS = (0x60008 << 60)
_VERSION_7_FLAGS = (0x70008 << 60)
_VERSION_8_FLAGS = (0x80008 << 60)

# built-in types to avoid naming conflict
int_ = int
bytes_ = bytes


class UUID:
    def __init__(
            self,
            hex: str | None = None,
            int: int_ | None = None,
            version: int_ | None = None):
        if hex is not None:
            hex = hex.replace('-', '')
            if len(hex) != 32:
                raise ValueError("invalid hexadecimal uuid format")
            int = int_(hex, base=16)

        if int is not None and not 0 <= int <= ((1 << 128) - 1):
            raise ValueError("int out of range, 128 bit value is required")

        if int is not None and version is not None:
            if not 1 <= version <= 8:
                raise ValueError("invalid version")
            # set version and variant for the uuid
            int &= _CLEARFLAG_MASK
            int |= _VARIANT_FLAGS
            int |= version << 76

        self.int = int

    def __str__(self):
        hex = self.hex
        return f"{hex[:8]}-{hex[8:12]}-{hex[12:16]}-{hex[16:20]}-{hex[20:]}"

    def __int__(self):
        return self.int

    @property
    def bytes(self):
        if self.int is None:
            raise ValueError("int is None in uuid")
        return self.int.to_bytes(16)

    @property
    def hex(self):
        return self.bytes.hex()


# returns a random node using csprng to simulate getting a node id
def _random_node():
    return int_.from_bytes(os.urandom(6))


_last_timestamp = None


def uuidv1(clock_seq=None, node=None):
    global _last_timestamp

    timestamp = time.time_ns()
    if _last_timestamp is not None and timestamp <= _last_timestamp:
        timestamp = _last_timestamp + 1
    _last_timestamp = timestamp

    if clock_seq is None:
        clock_seq = int_.from_bytes(os.urandom(2))

    time_low = timestamp & 0xffffffff
    time_mid = (timestamp >> 32) & (0xffff)
    time_hi_version = (timestamp >> 48) & (0x0fff)
    clock_seq = clock_seq & 0x3fff
    if node is None:
        node = _random_node()
    uuid_int = (time_low << 96) | (time_mid << 80) | (
        time_hi_version << 64) | (clock_seq << 48) | (node)
    return UUID(int=uuid_int, version=1)


def uuidv3(namespace: UUID, name: bytes | str):
    if isinstance(name, str):
        name = bytes_(name, "utf-8")
    import hashlib
    hash = hashlib.md5(namespace.bytes + name, usedforsecurity=False)
    uuid_int = int_.from_bytes(hash.digest())
    uuid_int &= _CLEARFLAG_MASK
    uuid_int |= _VERSION_3_FLAGS
    return UUID(int=uuid_int)


def uuidv4():
    uuid_int = int_.from_bytes(os.urandom(16))
    uuid_int &= _CLEARFLAG_MASK
    uuid_int |= _VERSION_4_FLAGS
    return UUID(int=uuid_int)


def uuidv5(namespace: UUID, name: bytes | str):
    if isinstance(name, str):
        name = bytes_(name, "utf-8")
    import hashlib
    hash = hashlib.sha1(namespace.bytes + name, usedforsecurity=False)
    uuid_int = int_.from_bytes(hash.digest()[:16])
    uuid_int &= _CLEARFLAG_MASK
    uuid_int |= _VERSION_5_FLAGS
    return UUID(int=uuid_int)


_last_timestamp_v6 = None


def uuidv6(clock_seq=None, node=None):
    global _last_timestamp_v6

    timestamp = time.time_ns()
    if _last_timestamp_v6 is not None and timestamp <= _last_timestamp_v6:
        timestamp = _last_timestamp_v6 + 1
    _last_timestamp_v6 = timestamp

    if clock_seq is None:
        clock_seq = int_.from_bytes(os.urandom(2))

    time_low = timestamp & 0x0fff
    time_hi_mid = (timestamp >> 12) & (0xffff_ffff_ffff)
    clock_seq = clock_seq & 0x3fff
    if node is None:
        node = _random_node()
    uuid_int = (time_hi_mid << 80) | (
        time_low << 64) | (clock_seq << 48) | (node & 0xffff_ffff_ffff)
    return UUID(int=uuid_int, version=6)


def _uuid_get_counter_and_tail():
    rand = int_.from_bytes(os.urandom(10))
    counter = (rand >> 32) & 0x1ff_ffff_ffff
    tail = rand & 0xffff_ffff
    return counter, tail


_last_timestamp_v7 = None
_last_counter_v7 = None


def uuidv7():
    global _last_timestamp_v7
    global _last_counter_v7

    timestamp = time.time_ns() // 1000000

    # if last timestamp is set to past, reseed the counter
    if _last_timestamp_v7 is None or _last_counter_v7 is None or (
            timestamp > _last_timestamp_v7):
        counter, tail = _uuid_get_counter_and_tail()
    else:
        if timestamp < _last_timestamp_v7:
            timestamp = _last_timestamp_v7 + 1
        counter = _last_counter_v7 + 1
        if counter > 0x3ff_ffff_ffff:
            timestamp += 1
            counter, tail = _uuid_get_counter_and_tail()
        else:
            tail = int_.from_bytes(os.urandom(4))

    unix_timestamp = timestamp & 0xffff_ffff_ffff
    counter_hi = (counter >> 30) & 0x0fff  # clear version bits
    counter_lo = counter & 0x3fff_ffff  # clear variant bits
    tail &= 0xffff_ffff

    uuid_int = unix_timestamp << 80
    uuid_int |= counter_hi << 64
    uuid_int |= counter_lo << 32
    uuid_int |= tail

    uuid = UUID(int=uuid_int, version=7)

    _last_timestamp_v7 = timestamp
    _last_counter_v7 = counter
    return uuid


def uuidv8(a=None, b=None, c=None):
    if a is None:
        import random
        a = random.getrandbits(48)
    if b is None:
        import random
        b = random.getrandbits(12)
    if c is None:
        import random
        c = random.getrandbits(62)
    int_uuid_8 = (a & 0xffff_ffff_ffff) << 80
    int_uuid_8 |= (b & 0xfff) << 64
    int_uuid_8 |= c & 0x3fff_ffff_ffff_ffff
    return UUID(int=int_uuid_8, version=8)


def main():
    uuid = uuidv7()
    print(uuid)


if __name__ == "__main__":
    main()
