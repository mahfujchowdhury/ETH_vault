"""
keystone.py — Keystone hardware-wallet support for ETHVault (EIP-4527 *coordinator* side, ONLINE machine).

    Keystone  --ur:crypto-hdkey-->      ETHVault   (pairing: account xpub + master fingerprint)
    ETHVault  --ur:eth-sign-request-->  Keystone   (unsigned EIP-1559 tx, shown as animated QR)
    Keystone  --ur:eth-signature-->     ETHVault   (65-byte r||s||v)  -> raw tx -> broadcast (tab 4)

Pure logic, no GUI / camera code (ethvault.py's tab 7 does that).
Needs: cbor2, rlp, eth_account (+ evur.py and ur.py next to this file). No coincurve.
"""
import hashlib, hmac, json, os, struct, uuid
import cbor2
import evur

# EIP-4527 eth-sign-request data-type values
DT_LEGACY, DT_TYPED_DATA, DT_PERSONAL, DT_TYPED_TX = 1, 2, 3, 4

# ------------------------------ secp256k1 (public derivation) ------------------------------
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _decompress(k33: bytes):
    x = int.from_bytes(k33[1:], "big")
    y = pow((pow(x, 3, _P) + 7) % _P, (_P + 1) // 4, _P)
    if (y & 1) != (k33[0] & 1):
        y = _P - y
    return x, y


def _add(a, b):
    if a is None: return b
    if b is None: return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % _P == 0: return None
    if a == b: m = 3 * x1 * x1 * pow(2 * y1, -1, _P) % _P
    else:      m = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    return x3, (m * (x1 - x3) - y1) % _P


def _pt_of_scalar(k: int):
    from eth_keys import keys
    raw = keys.PrivateKey(k.to_bytes(32, "big")).public_key.to_bytes()      # 64 bytes x||y
    return int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")


def _compress(pt) -> bytes:
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def ckd_pub(key33: bytes, chain32: bytes, i: int):
    """BIP32 non-hardened public child derivation."""
    if i >= 0x80000000:
        raise ValueError("cannot derive a hardened child from a public key")
    I = hmac.new(chain32, key33 + struct.pack(">I", i), hashlib.sha512).digest()
    il = int.from_bytes(I[:32], "big")
    if il >= _N: raise ValueError("invalid child")
    return _compress(_add(_decompress(key33), _pt_of_scalar(il))), I[32:]


def addr_of_pub33(k33: bytes) -> str:
    from eth_utils import keccak, to_checksum_address
    x, y = _decompress(k33)
    return to_checksum_address(keccak(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:])


# ------------------------------------ pairing ------------------------------------
def _untag(v):
    return v.value if isinstance(v, cbor2.CBORTag) else v


def _path_str(flat) -> str:
    return "m/" + "/".join(f"{flat[i]}{chr(39) if flat[i + 1] else ''}" for i in range(0, len(flat) - 1, 2))


def parse_hdkey(payload: bytes) -> dict:
    """crypto-hdkey CBOR (from a Keystone / MetaMask-QR pairing screen) -> dict."""
    m = _untag(cbor2.loads(payload))
    if not hasattr(m, "get") or 3 not in m:
        raise ValueError("Not a crypto-hdkey (no public key inside).")
    if m.get(2):
        raise ValueError("This is a private key export, not a pairing QR.")
    key, chain = m[3], m.get(4)
    if not chain:
        raise ValueError("Device sent a key without a chain code; cannot derive addresses.")
    origin = _untag(m.get(6)) or {}
    flat = list(origin.get(1, []))
    xfp = int(origin.get(2, 0)).to_bytes(4, "big")
    return {"key": key.hex(), "chain": chain.hex(), "xfp": xfp.hex(), "flat": flat,
            "path": _path_str(flat) if flat else "m", "name": m.get(9), "source": m.get(10)}


def parse_pairing_ur(text: str) -> dict:
    d = evur.URDecoder()
    if not d.add(text):
        raise ValueError("Incomplete multi-part QR.")
    t, body = d.result()
    if t != "crypto-hdkey":
        raise ValueError(f"Expected ur:crypto-hdkey but got ur:{t}")
    return parse_hdkey(body)


def derive_addresses(hd: dict, count: int = 5):
    """Receiving addresses .../0/i from the paired account key (or the single leaf if a leaf was sent)."""
    key, chain = bytes.fromhex(hd["key"]), bytes.fromhex(hd["chain"])
    if len(hd["flat"]) >= 10:                       # device gave a leaf key
        return [addr_of_pub33(key)]
    ext_c = ckd_pub(key, chain, 0)                  # external chain (…/0), then index
    out = []
    for i in range(count):
        ck, _ = ckd_pub(ext_c[0], ext_c[1], i)
        out.append(addr_of_pub33(ck))
    return out


def full_path(hd: dict, index: int) -> list:
    """Flat [idx, hardened, ...] path of the signing key."""
    if len(hd["flat"]) >= 10:
        return hd["flat"]
    return list(hd["flat"]) + [0, False, index, False]


# ------------------------------------ signing ------------------------------------
def build_sign_request(tx: dict, hd: dict, index: int, address: str, origin="ETHVault"):
    """EIP-1559 tx dict -> (request_id bytes, list of QR frame strings)."""
    sign_data = evur.encode_unsigned_1559(tx)
    rid = uuid.uuid4().bytes
    m = {1: cbor2.CBORTag(37, rid),
         2: sign_data,
         3: DT_TYPED_TX,
         4: tx["chainId"],
         5: cbor2.CBORTag(304, {1: full_path(hd, index), 2: int(hd["xfp"], 16)}),
         6: bytes.fromhex(address[2:]),
         7: origin}
    return rid, sign_data, evur.ur_encode_frames("eth-sign-request", cbor2.dumps(m), 100)


def finish_signature(text: str, rid: bytes, tx: dict, expected_addr: str) -> str:
    """ur:eth-signature text -> raw signed tx hex, verified against the paired address."""
    from eth_account import Account
    d = evur.URDecoder()
    if not d.add(text):
        raise ValueError("Incomplete multi-part QR.")
    t, body = d.result()
    if t != "eth-signature":
        raise ValueError(f"Expected ur:eth-signature but got ur:{t}")
    got_rid, sig = evur.parse_signature(body)
    if got_rid != rid:
        raise ValueError("This signature answers a DIFFERENT request. Re-run the sign step.")
    if len(sig) != 65:
        raise ValueError("Signature is not 65 bytes.")
    for parity in (sig[64] & 1, (sig[64] & 1) ^ 1):            # tolerate 0/1, 27/28 conventions
        raw = evur.assemble_signed_1559(tx, sig[:64] + bytes([parity]))
        try:
            if Account.recover_transaction(raw).lower() == expected_addr.lower():
                return raw
        except Exception:
            pass
    raise ValueError("Signature does not recover to the paired Keystone address. Not exporting.")


# ------------------------------- pairing persistence -------------------------------
PAIR_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keystone_pairing.json")


def save_pairing(hd: dict, index: int):
    json.dump({"hd": hd, "index": index}, open(PAIR_FILE, "w"))     # public data only


def load_pairing():
    try:
        d = json.load(open(PAIR_FILE)); return d["hd"], d.get("index", 0)
    except Exception:
        return None, 0


# ------------------------------------ self-test ------------------------------------
if __name__ == "__main__":
    from eth_account import Account
    Account.enable_unaudited_hdwallet_features()
    words = "test test test test test test test test test test test junk"
    x = evur.derive_account_xpub(words)
    hd = parse_hdkey(evur.hdkey_cbor(x))
    want = Account.from_mnemonic(words).address
    got = derive_addresses(hd, 3)
    assert got[0] == want, (got[0], want)
    print("pairing + address derivation OK:", got[0])
    tx = {"chainId": 11155111, "nonce": 1, "maxPriorityFeePerGas": 10**9, "maxFeePerGas": 30 * 10**9,
          "gas": 21000, "to": got[1], "value": 10**16, "data": "0x"}
    rid, sd, frames = build_sign_request(tx, hd, 0, want)
    acct = Account.from_mnemonic(words)
    signed = Account.sign_transaction({**tx}, acct.key)
    sig = evur.sig65_from_signed(signed)
    ur = evur.ur_encode_frames("eth-signature", evur.signature_cbor(rid, sig), 1000)[0].lower()
    raw = finish_signature(ur, rid, tx, want)
    assert Account.recover_transaction(raw) == want
    print("sign-request", len(frames), "frame(s); signature round-trip OK")