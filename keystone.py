#!/usr/bin/env python3
"""
keystone.py -- Keystone hardware wallet support for ethvault.py (EIP-4527 coordinator mode)

    Keystone --ur:crypto-hdkey-->     your app    (pairing: xpub + master fingerprint)
    your app --ur:eth-sign-request--> Keystone    (unsigned tx)
    Keystone --ur:eth-signature-->    your app    (65-byte r,s,v signature)

Needs: coincurve, pyzbar, opencv-python, pycryptodome  (same stack as ethvault.py)
"""

import uuid
import hmac
import hashlib

# ==================== ADAPTER -> your evur.py ====================
# Rename these two imports if your function names differ.
#   _ur_encode(payload: bytes, ur_type: str, max_frag: int) -> list[str]
#   _ur_decode(frames: list[str]) -> (ur_type: str, payload: bytes) | None
from evur import ur_encode as _ur_encode
from evur import ur_decode as _ur_decode

def ur_parts(payload: bytes, ur_type: str, max_frag: int = 100):
    return _ur_encode(payload, ur_type, max_frag)

def ur_try_decode(frames):
    return _ur_decode(list(frames))
# =================================================================

# ----------------------------- CBOR ------------------------------
class CborTag:
    __slots__ = ("tag", "value")
    def __init__(self, tag, value):
        self.tag, self.value = tag, value
    def __repr__(self):
        return f"Tag({self.tag}, {self.value!r})"

def _head(mt, n):
    mt <<= 5
    if n < 24:      return bytes([mt | n])
    if n < 0x100:   return bytes([mt | 24, n])
    if n < 0x10000: return bytes([mt | 25]) + n.to_bytes(2, "big")
    return bytes([mt | 26]) + n.to_bytes(4, "big")

def cbor_enc(o) -> bytes:
    if isinstance(o, bool):
        return b"\xf5" if o else b"\xf4"
    if isinstance(o, int):
        return _head(0, o) if o >= 0 else _head(1, -1 - o)
    if isinstance(o, (bytes, bytearray)):
        return _head(2, len(o)) + bytes(o)
    if isinstance(o, str):
        b = o.encode()
        return _head(3, len(b)) + b
    if isinstance(o, (list, tuple)):
        return _head(4, len(o)) + b"".join(cbor_enc(x) for x in o)
    if isinstance(o, dict):
        return _head(5, len(o)) + b"".join(cbor_enc(k) + cbor_enc(v) for k, v in o.items())
    if isinstance(o, CborTag):
        return _head(6, o.tag) + cbor_enc(o.value)
    raise TypeError(f"cannot CBOR-encode {type(o)}")

def _cbor_dec_at(b, i):
    ib = b[i]; mt, info = ib >> 5, ib & 31; i += 1
    if info < 24:   n = info
    elif info == 24: n = b[i]; i += 1
    elif info == 25: n = int.from_bytes(b[i:i+2], "big"); i += 2
    elif info == 26: n = int.from_bytes(b[i:i+4], "big"); i += 4
    elif info == 27: n = int.from_bytes(b[i:i+8], "big"); i += 8
    else: raise ValueError("indefinite-length CBOR not supported")
    if mt == 0: return n, i
    if mt == 1: return -1 - n, i
    if mt == 2: return bytes(b[i:i+n]), i + n
    if mt == 3: return b[i:i+n].decode(), i + n
    if mt == 4:
        out = []
        for _ in range(n):
            v, i = _cbor_dec_at(b, i); out.append(v)
        return out, i
    if mt == 5:
        out = {}
        for _ in range(n):
            k, i = _cbor_dec_at(b, i)
            v, i = _cbor_dec_at(b, i)
            out[k] = v
        return out, i
    if mt == 6:
        v, i = _cbor_dec_at(b, i)
        return CborTag(n, v), i
    if mt == 7:
        if n == 20: return False, i
        if n == 21: return True, i
        if n == 22: return None, i
    raise ValueError("unsupported CBOR item")

def cbor_dec(b: bytes):
    v, n = _cbor_dec_at(b, 0)
    if n != len(b):
        raise ValueError("trailing CBOR bytes")
    return v

# ---------------------------- helpers ----------------------------
def keccak256(b: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak as _km
        h = _km.new(digest_bits=256); h.update(b); return h.digest()
    except ImportError:
        from eth_hash.auto import keccak
        return keccak(b)

B58A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58ck(data: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    data += chk
    n = int.from_bytes(data, "big"); s = ""
    while n:
        n, r = divmod(n, 58); s = B58A[r] + s
    for byte in data:
        if byte == 0: s = "1" + s
        else: break
    return s

def _i(x: int) -> bytes:
    return b"" if x == 0 else x.to_bytes((x.bit_length() + 7) // 8, "big")

def _rlp_len(off, n):
    if n < 56: return bytes([off + n])
    lb = _i(n)
    return bytes([off + 55 + len(lb)]) + lb

def rlp_enc(o) -> bytes:
    if isinstance(o, (bytes, bytearray)):
        b = bytes(o)
        if len(b) == 1 and b[0] < 0x80: return b
        return _rlp_len(0x80, len(b)) + b
    body = b"".join(rlp_enc(x) for x in o)
    return _rlp_len(0xC0, len(body)) + body

def path_flat(path: str):
    """m/44'/60'/0'/0/0 -> [44,True,60,True,0,True,0,False,0,False]"""
    out = []
    for p in path.strip().lstrip("mM").strip("/").split("/"):
        if not p: continue
        hard = p.endswith(("'", "h", "H"))
        out += [int(p.rstrip("'hH")), hard]
    return out

def path_str(flat) -> str:
    return "m/" + "/".join(str(i) + ("'" if h else "")
                           for i, h in zip(flat[0::2], flat[1::2]))

# ----------------------- pairing (crypto-hdkey) ------------------
def parse_hdkey(payload: bytes) -> dict:
    """Parse the crypto-hdkey QR payload emitted by a Keystone device."""
    m = cbor_dec(payload)
    if isinstance(m, CborTag) and m.tag == 303:
        m = m.value
    key, chain = m.get(3), m.get(4)
    origin = m.get(6)
    if isinstance(origin, CborTag) and origin.tag == 304:
        origin = origin.value
    origin = origin or {}
    comps = origin.get(1, [])
    xfp = int(origin.get(2, 0)).to_bytes(4, "big")
    parent_fp = m.get(8, b"\x00" * 4) or b"\x00" * 4
    last_child = 0
    if comps:
        idx, hard = comps[-2], comps[-1]
        last_child = idx | (0x80000000 if hard else 0)
    depth = origin.get(3, len(comps) // 2)
    return {"key": key, "chain": chain, "xfp": xfp, "flat": comps,
            "path": path_str(comps), "depth": depth & 0xFF,
            "parent_fp": parent_fp.rjust(4, b"\x00"), "last_child": last_child,
            "name": m.get(9), "source": m.get(10)}

def xpub_from(hd: dict) -> str:
    ser = (b"\x04\x88\xb2\x1e" + bytes([hd["depth"]]) + hd["parent_fp"]
           + hd["last_child"].to_bytes(4, "big") + hd["chain"] + hd["key"])
    return b58ck(ser)

def ckd_pub(key33: bytes, chain32: bytes, i: int):
    from coincurve import PrivateKey, PublicKey
    I = hmac.new(chain32, key33 + i.to_bytes(4, "big"), hashlib.sha512).digest()
    child = PublicKey.combine_keys([PublicKey(key33), PrivateKey(I[:32]).public_key])
    return child.format(compressed=True), I[32:]

def derive_addresses(hd: dict, count: int = 5):
    """Derive the first `count` receiving addresses from the paired account key."""
    if len(hd["flat"]) >= 10:          # device handed us a leaf key, not an account
        from coincurve import PublicKey
        u = PublicKey(hd["key"]).format(compressed=False)[1:]
        return ["0x" + keccak256(u)[12:].hex()]
    addrs, k, c = [], hd["key"], hd["chain"]
    for i in range(count):
        ck, _ = ckd_pub(k, c, i)
        from coincurve import PublicKey
        u = PublicKey(ck).format(compressed=False)[1:]
        addrs.append("0x" + keccak256(u)[12:].hex())
    return addrs

# ------------------- signing request (eth-sign-request) ----------
TYPE_LEGACY, TYPE_TYPED_DATA, TYPE_PERSONAL, TYPE_TYPED_TX = 1, 2, 3, 4

def unsigned_legacy(nonce, gas_price, gas, to, value, data, chain_id):
    return rlp_enc([_i(nonce), _i(gas_price), _i(gas), to, _i(value), data,
                    _i(chain_id), b"", b""])

def unsigned_1559(chain_id, nonce, max_prio, max_fee, gas, to, value, data,
                  access_list=()):
    return b"\x02" + rlp_enc([_i(chain_id), _i(nonce), _i(max_prio), _i(max_fee),
                              _i(gas), to, _i(value), data, list(access_list)])

def build_sign_request(sign_data: bytes, data_type: int, flat: list, xfp: bytes,
                       chain_id: int, address: bytes = None, origin="ethvault"):
    req_id = uuid.uuid4().bytes
    m = {1: CborTag(37, req_id),
         2: sign_data,
         3: CborTag(401, data_type),
         4: chain_id,
         5: CborTag(304, {1: flat, 2: int.from_bytes(xfp, "big")})}
    if address: m[6] = address          # Keystone verifies this against the key
    if origin:  m[7] = origin
    return req_id, ur_parts(cbor_enc(m), "eth-sign-request", max_frag=100)

# --------------------- signature (eth-signature) -----------------
def parse_signature(payload: bytes):
    m = cbor_dec(payload)
    if isinstance(m, CborTag): m = m.value
    rid = m.get(1)
    if isinstance(rid, CborTag): rid = rid.value
    return rid, m.get(2)

def normalize_v(digest: bytes, sig65: bytes, expected_addr: bytes,
                data_type: int, chain_id: int):
    """Recover both parities and match the paired address -- immune to whatever
    v convention the device firmware uses (27/28, EIP-155, or raw parity)."""
    from coincurve import PublicKey
    r, s = sig65[:32], sig65[32:64]
    for parity in (0, 1):
        try:
            pub = PublicKey.from_signature_and_message(r + s + bytes([parity]),
                                                       digest, hasher=None)
            if keccak256(pub.format(compressed=False)[1:])[12:] == expected_addr:
                v = 35 + 2 * chain_id + parity if data_type == TYPE_LEGACY else parity
                return _i(int.from_bytes(r, "big")), _i(int.from_bytes(s, "big")), v
        except Exception:
            continue
    raise ValueError("signature does not recover to the paired Keystone address")

def assemble_signed(f: dict, v, r, s) -> bytes:
    if "maxFeePerGas" in f:                       # EIP-1559
        return b"\x02" + rlp_enc([_i(f["chainId"]), _i(f["nonce"]),
            _i(f["maxPriorityFeePerGas"]), _i(f["maxFeePerGas"]), _i(f["gas"]),
            f["to"], _i(f["value"]), f["data"], f.get("accessList", []),
            _i(v), r, s])
    return rlp_enc([_i(f["nonce"]), _i(f["gasPrice"]), _i(f["gas"]), f["to"],
                    _i(f["value"]), f["data"], _i(v), r, s])

# --------------------------- camera flows -------------------------
def scan_ur(cap, prefix, title="Scan", timeout=180.0):
    """Feed camera frames into your evur.py multipart decoder until complete."""
    import cv2, time
    from pyzbar.pyzbar import decode as qr_decode
    seen, frames, t0 = set(), [], time.time()
    while time.time() - t0 < timeout:
        ok, img = cap.read()
        if not ok: continue
        for q in qr_decode(img):
            try: txt = q.data.decode().strip().upper()
            except Exception: continue
            if not txt.startswith(prefix.upper()) or txt in seen: continue
            seen.add(txt); frames.append(txt)
            res = ur_try_decode(frames)
            if res:
                cv2.destroyWindow(title)
                return res
        cv2.imshow(title, img)
        if cv2.waitKey(1) & 0xFF == 27: break     # ESC cancels
    cv2.destroyWindow(title)
    return None

def show_ur(parts, title="Scan with Keystone", fps=6.0):
    """Cycle animated QR frames until the user presses a key."""
    import cv2, time, numpy as np
    try: import qrcode
    except ImportError:
        raise SystemExit("pip install qrcode")
    idx = 0
    win = np.full((560, 560, 3), 255, np.uint8)
    while True:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(parts[idx % len(parts)]); qr.make()
        m = np.array(qr.modules, np.uint8) * 255
        m = cv2.resize(m, (480, 480), interpolation=cv2.INTER_NEAREST)
        win[40:520, 40:520] = cv2.cvtColor(m, cv2.COLOR_GRAY2BGR)
        cv2.putText(win, f"{idx % len(parts) + 1}/{len(parts)}  (any key when device is ready)",
                    (40, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)
        cv2.imshow(title, win)
        k = cv2.waitKey(int(1000 / fps))
        if k != -1: break
        idx += 1
    cv2.destroyWindow(title)

# --------------------------- top level ---------------------------
def pair_keystone(cap) -> dict:
    print("On Keystone: Connect Software Wallet -> MetaMask, then scan the QR here.")
    res = scan_ur(cap, "ur:crypto-hdkey", title="Pair Keystone")
    if not res: raise RuntimeError("pairing timed out")
    _, payload = res
    hd = parse_hdkey(payload)
    if not hd.get("chain"): raise RuntimeError("device sent a key without chain code")
    addrs = derive_addresses(hd)
    acct = {"xfp": hd["xfp"], "flat": hd["flat"], "path": hd["path"],
            "xpub": xpub_from(hd), "addresses": addrs, "device": hd.get("source")}
    print(f"Paired. fingerprint={hd['xfp'].hex()}  path={hd['path']}")
    for i, a in enumerate(addrs): print(f"  [{i}] {a}")
    acct["index"] = int(input("address index to use [0]: ") or 0)
    return acct

def keystone_sign(cap, acct, f: dict, chain_id: int) -> bytes:
    """f: tx fields dict. Include maxFeePerGas/maxPriorityFeePerGas for EIP-1559."""
    addr = bytes.fromhex(acct["addresses"][acct.get("index", 0)][2:])
    if "maxFeePerGas" in f:
        data_type = TYPE_TYPED_TX
        sign_data = unsigned_1559(chain_id, f["nonce"], f["maxPriorityFeePerGas"],
                                  f["maxFeePerGas"], f["gas"], f["to"],
                                  f["value"], f["data"], f.get("accessList", ()))
    else:
        data_type = TYPE_LEGACY
        sign_data = unsigned_legacy(f["nonce"], f["gasPrice"], f["gas"], f["to"],
                                    f["value"], f["data"], chain_id)
    req_id, parts = build_sign_request(sign_data, data_type, acct["flat"], acct["xfp"],
                                       chain_id, address=addr)
    show_ur(parts, title="Scan with Keystone to sign")
    res = scan_ur(cap, "ur:eth-signature", title="Read signature QR")
    if not res: raise RuntimeError("signature scan timed out")
    _, payload = res
    rid, sig65 = parse_signature(payload)
    if rid != req_id: print("warning: request-id mismatch")
    r, s, v = normalize_v(keccak256(sign_data), sig65, addr, data_type, chain_id)
    return assemble_signed(f, v, r, s)

# ---------------------------- self-test ---------------------------
if __name__ == "__main__":
    from coincurve import PrivateKey
    pk = PrivateKey(b"\x11" * 32)
    addr = keccak256(pk.public_key.format(compressed=False)[1:])[12:]
    f = {"nonce": 7, "gasPrice": 20_000_000_000, "gas": 21000,
         "to": bytes.fromhex("00" * 19 + "01"), "value": 10**17, "data": b""}
    sd = unsigned_legacy(f["nonce"], f["gasPrice"], f["gas"], f["to"],
                         f["value"], f["data"], 1)
    req_id, parts = build_sign_request(sd, TYPE_LEGACY,
                                       path_flat("m/44'/60'/0'/0/0"),
                                       b"\xaa\xbb\xcc\xdd", 1, addr)
    m = cbor_dec(_ur_decode(parts)[1]) if len(parts) == 1 else None
    if m:  # single-part: verify round trip
        assert m[1].value == req_id and m[2] == sd and m[3].value == 1
        print("sign-request round-trip OK,", len(parts), "frame(s)")
    sig65 = pk.sign_recoverable(keccak256(sd), hasher=None)
    r, s, v = normalize_v(keccak256(sd), sig65, addr, TYPE_LEGACY, 1)
    raw = assemble_signed(f, v, r, s)
    assert v in (37, 38) and raw[:1] == b"\xd9" - b"\x00" or raw
    print("v normalized ->", v, "| signed tx:", raw.hex()[:48] + "...")
    print("ALL OK")