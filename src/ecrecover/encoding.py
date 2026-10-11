from ecrecover.curve import p, x, y, a, b, g_x, g_y, n, h

# helper function for encoding h
def decode_h(input_h: bytes) -> int | None:
    """
    Read 32-byte big-endian input as integer and reduce mod n.
    Any 32-byte value is accepted (spec: "Any value is accepted").
    """

    if len(input_h) != 32:
        raise ValueError("h must be 32 bytes")

    h_int = int.from_bytes(input_h, "big")
    return h_int % n