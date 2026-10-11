# tests/test_ecrecover.py
import json
from pathlib import Path

from hypothesis import given, strategies as st
from eth_keys import keys

import pytest

from ecrecover.ecrecover import ecrecover, EMPTY
from ecrecover.curve import n

VECTORS = {
    # geth: core/vm/testdata/precompiles/ecRecover.json
    "CallEcrecoverUnrecoverableKey": (
        "a8b53bdf3306a35a7103ab5504a0c9b492295564b6202b1942a84ef300107281"
        "000000000000000000000000000000000000000000000000000000000000001b"
        "307835653165303366353363653138623737326363623030393366663731663366"
        "353366356337356237346463623331613835616138623838393262346538621122"
        "334455667788991011121314151617181920212223242526272829303132",
        "",
    ),
    "ValidKey": (
        "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
        "000000000000000000000000000000000000000000000000000000000000001c"
        "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
        "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549",
        "000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
    ),
    "InvalidHighV-bits-1": (
        "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
        "100000000000000000000000000000000000000000000000000000000000001c"
        "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
        "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549",
        "",
    ),
    "InvalidHighV-bits-2": (
        "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
        "000000000000000000000000000000000000001000000000000000000000001c"
        "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
        "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549",
        "",
    ),
    "InvalidHighV-bits-3": (
        "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
        "000000000000000000000000000000000000001000000000000000000000011c"
        "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
        "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549",
        "",
    ),
}


@pytest.mark.parametrize("name", VECTORS)
def test_geth_vectors(name):
    inp, expected = VECTORS[name]
    expected_bytes = bytes.fromhex(expected) if expected else EMPTY
    assert ecrecover(bytes.fromhex(inp)) == expected_bytes


# --- negative tests

VALID = bytes.fromhex(VECTORS["ValidKey"][0])


def with_byte(data: bytes, i: int, val: int) -> bytes:
    b = bytearray(data)
    b[i] = val
    return bytes(b)


def test_v_27_ok():
    assert ecrecover(VALID) != EMPTY


@pytest.mark.parametrize("v", [0, 26, 29, 30, 255])
def test_invalid_v(v):
    assert ecrecover(with_byte(VALID, 63, v)) == EMPTY


@pytest.mark.parametrize("i", [32, 40, 62])
def test_v_upper_bytes_nonzero(i):
    assert ecrecover(with_byte(VALID, i, 1)) == EMPTY


def test_r_zero():
    assert ecrecover(VALID[:64] + bytes(32) + VALID[96:]) == EMPTY


def test_s_zero():
    assert ecrecover(VALID[:96] + bytes(32)) == EMPTY


def test_r_equals_n():
    from ecrecover.curve import n
    assert ecrecover(VALID[:64] + n.to_bytes(32, "big") + VALID[96:]) == EMPTY


def test_s_equals_n():
    from ecrecover.curve import n
    assert ecrecover(VALID[:96] + n.to_bytes(32, "big")) == EMPTY


def test_empty_input():
    assert ecrecover(EMPTY) == EMPTY


def test_trailing_bytes_ignored():
    assert ecrecover(VALID + b"\xff" * 32) == ecrecover(VALID)


def test_short_input_right_padded():
    assert ecrecover(VALID[:-1]) == ecrecover(VALID[:-1] + b"\x00")


def test_output_is_32_bytes_on_success():
    assert len(ecrecover(VALID)) == 32
    assert ecrecover(VALID)[:12] == bytes(12)

# --- fuzz

@given(st.binary(min_size=32, max_size=32), st.integers(min_value=1, max_value=n - 1))
def test_roundtrip(msg_hash, priv_int):
    priv = keys.PrivateKey(priv_int.to_bytes(32, "big"))
    sig = priv.sign_msg_hash(msg_hash)
    data = (
        msg_hash
        + (sig.v + 27).to_bytes(32, "big")
        + sig.r.to_bytes(32, "big")
        + sig.s.to_bytes(32, "big")
    )
    assert ecrecover(data)[12:] == priv.public_key.to_canonical_address()