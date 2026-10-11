from Crypto.Hash import keccak
from ecrecover.curve import p, n, G

EMPTY = b"\x00" * 32

def ecrecover(data: bytes) -> bytes:
    data = data.ljust(128, b"\x00")
    h = data[0:32]
    r = int.from_bytes(data[64:96], "big")
    s = int.from_bytes(data[96:128], "big")
    v = (data[63] - 27) % 256

    if not validate_input(data, r, s, v):
        return EMPTY

    R = point_with_x(r, y_is_odd=(v == 1))
    if R is None:
        return EMPTY

    z = int.from_bytes(h, "big") % n
    r1 = pow(r, -1, n)

    Q = point_add(point_mul((s * r1) % n, R), point_mul((-(z * r1)) % n, G), )

    if Q is None:
        return EMPTY

    pub = b"\x04" + Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
    addr = keccak256(pub[1:])[12:]

    return b"\x00" * 12 + addr

def validate_input(data: bytes, r: int, s: int, v: int) -> bool:
    if any(data[32:63]):
        return False
    if not (0 < r < n and 0 < s < n):
        return False
    if v not in (0, 1):
        return False
    return True

def point_with_x(x: int, y_is_odd: bool):
    y2 = (pow(x, 3, p) + 7) % p
    y = pow(y2, (p + 1) // 4, p)
    if (y * y) % p != y2:
        return None
    if (y % 2 == 1) != y_is_odd:
        y = p - y
    return (x, y)

p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)

def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mul(k, P):
    k %= n
    result = None
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def keccak256(b: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=b).digest()