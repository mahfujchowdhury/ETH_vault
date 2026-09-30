"""
evur.py — EIP-4527 helpers for ETHVault (Ethereum only).

Lets ETHVault act as a QR-only "hardware wallet" for apps that speak EIP-4527
(MetaMask QR-hardware flow, Keystone-style coordinators):

    pairing   : offline device shows   ur:crypto-hdkey       (account xpub)
    request   : coordinator shows      ur:eth-sign-request   (unsigned tx)
    response  : offline device shows   ur:eth-signature      (65-byte sig)

The generic UR/bytewords codec lives in ur.py (keep it alongside).
Requires: pip install cbor2 rlp eth_account
Only EIP-1559 (type 2) transactions are supported for signing; legacy / typed-data / personal-message
requests are refused with a clear error.
"""
import hashlib, hmac, struct, uuid
import cbor2
from ur import (crc32, bytewords_encode, bytewords_decode,      # re-exported for ethvault.py
                ur_encode_single, ur_encode_frames, URDecoder)


# --------------------------- BIP32 / EIP-4527 keys ---------------------------
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def _pub33(k: int) -> bytes:
    from eth_keys import keys
    return keys.PrivateKey(k.to_bytes(32, "big")).public_key.to_compressed_bytes()

def _hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

def _ckd(k: int, c: bytes, i: int):
    data = (b"\x00" + k.to_bytes(32, "big") if i >= 0x80000000 else _pub33(k)) + struct.pack(">I", i)
    I = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(I[:32], "big") + k) % _N, I[32:]

def derive_account_xpub(mnemonic: str, passphrase: str = ""):
    """m/44'/60'/0' → dict(pub, chain, parent_fp, master_fp) for pairing."""
    from eth_account.hdaccount import Mnemonic
    seed = Mnemonic.to_seed(mnemonic, passphrase)
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(I[:32], "big"), I[32:]
    master_fp = _hash160(_pub33(k))[:4]
    H = 0x80000000
    parent_fp = master_fp
    for idx in (44 + H, 60 + H, 0 + H):
        parent_fp = _hash160(_pub33(k))[:4]
        k, c = _ckd(k, c, idx)
    return {"pub": _pub33(k), "chain": c, "parent_fp": parent_fp, "master_fp": master_fp}

def hdkey_cbor(x: dict, name="ETHVault") -> bytes:
    """crypto-hdkey (BCR-2020-007 / EIP-4527) for m/44'/60'/0' with children 0/*."""
    origin = cbor2.CBORTag(304, {1: [44, True, 60, True, 0, True],
                                 2: int.from_bytes(x["master_fp"], "big"), 3: 3})
    children = cbor2.CBORTag(304, {1: [0, False, [], False]})
    return cbor2.dumps({3: x["pub"], 4: x["chain"], 6: origin, 7: children,
                        8: int.from_bytes(x["parent_fp"], "big"), 9: name})


# ---------------------------- sign request / signature -----------------------
DT_LEGACY, DT_TYPED, DT_PERSONAL, DT_TYPED_DATA = 1, 2, 3, 4

def sign_request_cbor(unsigned_typed_tx: bytes, master_fp: bytes, address: bytes = None,
                      chain_id: int = None, origin="ETHVault", req_id: bytes = None):
    rid = req_id or uuid.uuid4().bytes
    m = {1: cbor2.CBORTag(37, rid), 2: unsigned_typed_tx, 3: DT_TYPED,
         4: cbor2.CBORTag(304, {1: [44, True, 60, True, 0, True, 0, False, 0, False],
                                2: int.from_bytes(master_fp, "big")}),
         7: origin}
    if chain_id is not None: m[5] = chain_id
    if address: m[6] = address
    return cbor2.dumps(m), rid

def _rid(x) -> bytes:
    """Request id may decode as a UUID object (cbor2 knows tag 37) or a raw tag/bytes."""
    if isinstance(x, uuid.UUID): return x.bytes
    return x.value if isinstance(x, cbor2.CBORTag) else x

def parse_sign_request(cbor_bytes: bytes) -> dict:
    m = cbor2.loads(cbor_bytes)
    rid = _rid(m[1])
    path = None
    if 4 in m:
        kp = m[4].value if isinstance(m[4], cbor2.CBORTag) else m[4]
        comps = kp.get(1, [])
        path = "m/" + "/".join(f"{comps[i]}{'' if not comps[i+1] else chr(39)}" for i in range(0, len(comps) - 1, 2))
    return {"request_id": rid, "sign_data": m[2], "data_type": m.get(3, DT_TYPED), "path": path,
            "chain_id": m.get(5), "address": m.get(6), "origin": m.get(7)}

def signature_cbor(request_id: bytes, sig65: bytes, origin="ETHVault") -> bytes:
    return cbor2.dumps({1: cbor2.CBORTag(37, request_id), 2: sig65, 3: origin})

def parse_signature(cbor_bytes: bytes):
    m = cbor2.loads(cbor_bytes)
    return _rid(m[1]), m[2]


# -------------------------- EIP-1559 tx <-> bytes ----------------------------
def encode_unsigned_1559(tx: dict) -> bytes:
    import rlp
    def i(x): return int(x).to_bytes((int(x).bit_length() + 7) // 8, "big")
    data = bytes.fromhex(tx.get("data", "0x")[2:]) if isinstance(tx.get("data", "0x"), str) else tx["data"]
    to = bytes.fromhex(tx["to"][2:]) if tx.get("to") else b""
    return b"\x02" + rlp.encode([i(tx["chainId"]), i(tx["nonce"]), i(tx["maxPriorityFeePerGas"]),
                                 i(tx["maxFeePerGas"]), i(tx["gas"]), to, i(tx["value"]), data, []])

def decode_unsigned_1559(b: bytes) -> dict:
    import rlp
    from eth_utils import to_checksum_address
    if not b or b[0] != 2:
        raise ValueError("Only EIP-1559 (type 2) transactions are supported by ETHVault.")
    f = rlp.decode(b[1:], strict=True)
    if len(f) != 9: raise ValueError("Unexpected transaction field count.")
    n = lambda x: int.from_bytes(x, "big")
    if f[8]: raise ValueError("Transactions with an access list are not supported.")
    return {"chainId": n(f[0]), "nonce": n(f[1]), "maxPriorityFeePerGas": n(f[2]),
            "maxFeePerGas": n(f[3]), "gas": n(f[4]),
            "to": to_checksum_address(f[5]) if f[5] else None,
            "value": n(f[6]), "data": "0x" + f[7].hex(), "type": 2}

def sig65_from_signed(signed) -> bytes:
    return signed.r.to_bytes(32, "big") + signed.s.to_bytes(32, "big") + bytes([signed.v & 1])


def assemble_signed_1559(tx: dict, sig65: bytes) -> str:
    """Coordinator side: unsigned tx + 65-byte signature -> raw signed tx hex (0x02...)."""
    import rlp
    def i(x): return int(x).to_bytes((int(x).bit_length() + 7) // 8, "big")
    data = bytes.fromhex(tx.get("data", "0x")[2:])
    to = bytes.fromhex(tx["to"][2:]) if tx.get("to") else b""
    v = sig65[64] - 27 if sig65[64] >= 27 else sig65[64]
    r, s = int.from_bytes(sig65[:32], "big"), int.from_bytes(sig65[32:64], "big")
    raw = b"\x02" + rlp.encode([i(tx["chainId"]), i(tx["nonce"]), i(tx["maxPriorityFeePerGas"]),
                                i(tx["maxFeePerGas"]), i(tx["gas"]), to, i(tx["value"]), data, [], i(v), i(r), i(s)])
    return "0x" + raw.hex()


# ------------------------- signer-side helpers (used by GUI) -----------------
def validate_sign_request(text: str):
    """Single-part UR text -> (request dict, tx dict). Raises ValueError with a user-readable reason."""
    d = URDecoder()
    if not d.add(text):
        raise ValueError("This UR is only one fragment of a multi-part QR. Use 'Scan QR with camera' "
                         "so every frame is collected.")
    t, body = d.result()
    if t != "eth-sign-request":
        raise ValueError(f"Expected ur:eth-sign-request but got ur:{t}")
    rq = parse_sign_request(body)
    if rq["data_type"] != DT_TYPED:
        raise ValueError("ETHVault signs only EIP-1559 (type 2) transactions from QR requests. "
                         "Legacy, personal-message and typed-data requests are refused.")
    tx = decode_unsigned_1559(rq["sign_data"])
    if encode_unsigned_1559(tx) != rq["sign_data"]:
        raise ValueError("Transaction encoding is non-canonical; refusing to sign.")
    if rq["chain_id"] is not None and rq["chain_id"] != tx["chainId"]:
        raise ValueError("chainId in the request does not match the chainId inside the transaction.")
    return rq, tx


def sign_request_with_key(rq: dict, tx: dict, key: bytes):
    """Sign after checking the key is the account the request asks for. Returns (sig65, address)."""
    from eth_account import Account
    from eth_keys import keys
    from eth_utils import keccak
    acct = Account.from_key(key)
    want = rq.get("address")
    if want:
        if acct.address.lower() != "0x" + bytes(want).hex():
            raise ValueError(f"The request is for 0x{bytes(want).hex()} but this keystore is {acct.address}.")
    elif rq.get("path") not in (None, "m/44'/60'/0'/0/0"):
        raise ValueError(f"The request asks for {rq['path']}; this keystore only holds the m/44'/60'/0'/0/0 key.")
    signed = Account.sign_transaction({k: v for k, v in tx.items() if k != "type"}, key)
    sig = sig65_from_signed(signed)
    rec = keys.Signature(vrs=(sig[64], int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"))
                         ).recover_public_key_from_msg_hash(keccak(rq["sign_data"])).to_checksum_address()
    if rec != acct.address:
        raise ValueError("Internal check failed: signature does not verify over the request data. Not exporting.")
    return sig, acct.address
