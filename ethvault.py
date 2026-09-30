#!/usr/bin/env python3
"""
ETHVault — an air-gapped ("cold-style") Ethereum wallet with a Tkinter GUI.

(Bitcoin is a separate program now: btcvault.py.)

Flow:  CREATE (offline) -> BUILD unsigned tx (online) -> QR -> SIGN (offline) -> QR -> BROADCAST (online)

Run modes:
    python ethvault.py             # normal (online) machine
    python ethvault.py --offline   # AIR-GAPPED signer: ALL network sockets are blocked
    python ethvault.py --selftest  # verify crypto pipeline without network/GUI

Required:  pip install eth_account
Optional:  pip install qrcode pillow          (QR display)
           pip install cbor2 rlp              (EIP-4527 QR: pair with MetaMask etc.; needs evur.py + ur.py alongside)
           pip install pyzbar opencv-python   (camera QR scanning)

EDUCATIONAL TOOL. Unaudited. Test on a testnet with tiny amounts first.
"""

import sys, os, json, zlib, base64, threading, queue, time, urllib.request
from datetime import datetime
from decimal import Decimal

# ----------------------------- offline hard-lock -----------------------------
OFFLINE = "--offline" in sys.argv
if OFFLINE:
    import socket
    def _blocked(*a, **k):
        raise RuntimeError("NETWORK DISABLED: this instance is running in --offline (air-gapped) mode")
    socket.socket = _blocked                 # type: ignore
    socket.create_connection = _blocked      # type: ignore
    socket.getaddrinfo = _blocked            # type: ignore

from eth_account import Account
Account.enable_unaudited_hdwallet_features()

# optional QR support -------------------------------------------------------
try:
    import qrcode
    from PIL import Image, ImageTk
    HAS_QR = True
except ImportError:
    HAS_QR = False

try:
    import cv2
    from pyzbar import pyzbar as _pyzbar
    HAS_CAM = True
except ImportError:
    HAS_CAM = False

try:
    import evur                      # EIP-4527 / Uniform Resources helpers (evur.py next to this file)
    HAS_UR = True
except Exception:
    HAS_UR = False

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ------------------------------- constants ----------------------------------
GWEI = 10**9
WEI  = 10**18

NETWORKS = {
    "Ethereum Mainnet": {"chain_id": 1,        "rpc": "https://ethereum-rpc.publicnode.com"},
    "Sepolia Testnet":  {"chain_id": 11155111, "rpc": "https://ethereum-sepolia-rpc.publicnode.com"},
    "Holesky Testnet":  {"chain_id": 17000,    "rpc": "https://ethereum-holesky-rpc.publicnode.com"},
}
DEFAULT_NET = "Sepolia Testnet"
FRAME_CHUNK = 700   # chars per animated QR frame

# ------------------------------ payload codec -------------------------------
def pack(prefix: str, obj: dict) -> str:
    raw = zlib.compress(json.dumps(obj, separators=(",", ":")).encode(), 9)
    return prefix + base64.urlsafe_b64encode(raw).decode().rstrip("=")

def unpack(text: str):
    text = text.strip()
    for pre in ("EVU1:", "EVS1:"):
        if text.startswith(pre):
            b = text[len(pre):]
            b += "=" * (-len(b) % 4)
            return pre, json.loads(zlib.decompress(base64.urlsafe_b64decode(b)))
    raise ValueError("Not a valid ETHVault payload (must start with EVU1: or EVS1:)")

def make_frames(payload: str):
    if len(payload) <= FRAME_CHUNK:
        return [payload]
    chunks = [payload[i:i + FRAME_CHUNK] for i in range(0, len(payload), FRAME_CHUNK)]
    n = len(chunks)
    return [f"EVF:{i+1}/{n}:{c}" for i, c in enumerate(chunks)]

# -------------------------------- JSON-RPC ----------------------------------
def rpc(url: str, method: str, params: list, timeout=20):
    if OFFLINE:
        raise RuntimeError("Offline mode: network is disabled. Enter values manually.")
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "Accept": "application/json",
                                                       "User-Agent": "Mozilla/5.0 (compatible; ETHVault/1.0)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error'].get('message', data['error'])}")
    return data["result"]

def rpc_balance(url, addr):     return int(rpc(url, "eth_getBalance", [addr, "latest"]), 16)
def rpc_nonce(url, addr):       return int(rpc(url, "eth_getTransactionCount", [addr, "latest"]), 16)
def rpc_chain_id(url):          return int(rpc(url, "eth_chainId", []), 16)
def rpc_base_fee(url):
    blk = rpc(url, "eth_getBlockByNumber", ["latest", False])
    return int(blk.get("baseFeePerGas", "0x3b9aca00"), 16)
def rpc_tip(url):
    try:    tip = int(rpc(url, "eth_maxPriorityFeePerGas", []), 16)
    except Exception: tip = 0
    return max(tip, GWEI)  # never below 1 gwei (some nodes return 0 -> "gas tip cap 0, minimum needed 1")
def rpc_estimate_gas(url, frm, to, value_wei, data="0x"):
    p = {"to": to, "value": hex(value_wei), "data": data or "0x"}
    if frm: p["from"] = frm
    try:    return int(rpc(url, "eth_estimateGas", [p]), 16)
    except Exception: return 21000
def rpc_broadcast(url, raw):    return rpc(url, "eth_sendRawTransaction", [raw])
def rpc_receipt(url, txh):      return rpc(url, "eth_getTransactionReceipt", [txh])

def to_eth(wei) -> str:
    return f"{(Decimal(wei) / Decimal(WEI)).normalize():f}"

def valid_addr(a: str) -> bool:
    try:
        from eth_utils import to_checksum_address
        return to_checksum_address(a) == a
    except Exception:
        return False

def checksum(a: str):
    from eth_utils import to_checksum_address
    return to_checksum_address(a)

# --------------------------------- QR view ----------------------------------
def qr_image(text: str, size=320):
    if not HAS_QR:
        return None
    q = qrcode.QRCode(box_size=8, border=2, error_correction=qrcode.constants.ERROR_CORRECT_M)
    q.add_data(text); q.make(fit=True)
    img = q.make_image(fill_color="black", back_color="white").convert("RGB")
    img = img.resize((size, size))
    return img

# ================================ APPLICATION ================================
class ETHVaultApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(("ETHVault [OFFLINE / AIR-GAPPED — network blocked]" if OFFLINE
                   else "ETHVault [ONLINE coordinator]"))
        root.geometry("980x760"); root.minsize(900, 680)

        banner_bg = "#7a1f1f" if OFFLINE else "#1f4e7a"
        banner = tk.Label(root, bg=banner_bg, fg="white", pady=6, font=("Segoe UI", 11, "bold"),
            text=("OFFLINE SIGNER MODE — all network sockets are hard-disabled on this machine. "
                  "Use QR or file transfer only." if OFFLINE else
                  "ONLINE MODE — build unsigned transactions and broadcast signed ones. "
                  "NEVER put your keystore/private key on this machine."))
        banner.pack(fill="x")

        self.status = ttk.Label(root, text="Ready.", anchor="w", relief="sunken")
        self.status.pack(fill="x", side="bottom")

        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tabs = {}
        for name in ("1. Create Wallet (OFFLINE)", "2. Build Unsigned Tx", "3. Sign Tx (OFFLINE)",
                     "4. Broadcast", "5. Watch Address", "6. Pair (EIP-4527)"):
            f = ttk.Frame(self.nb); self.nb.add(f, text=name); self.tabs[name] = f

        self._build_create_tab(); self._build_tab(); self._sign_tab()
        self._broadcast_tab(); self._watch_tab(); self._pair_tab()

    # --------------------------- helpers --------------------------------
    def set_status(self, msg): self.status.config(text=msg)

    def async_do(self, fn, on_done):
        def worker():
            try:
                res = fn(); err = None
            except Exception as e:
                res, err = None, e
            self.root.after(0, lambda: on_done(res, err))
        threading.Thread(target=worker, daemon=True).start()

    def show_qr_window(self, payload: str, title="ETHVault QR", frames=None):
        frames = frames or make_frames(payload)
        win = tk.Toplevel(self.root); win.title(f"{title}  ({len(payload)} chars)")
        win.geometry("420x520")
        lbl = tk.Label(win); lbl.pack(padx=10, pady=10)
        info = tk.Label(win, text="", font=("Consolas", 9)); info.pack()
        tk.Button(win, text="Close", command=win.destroy).pack(pady=4)
        if not HAS_QR:
            info.config(text="QR libs missing (pip install qrcode pillow).\nCopy payload text instead:")
            t = tk.Text(win, height=10, width=46); t.pack(padx=10, pady=6)
            t.insert("1.0", payload)
            return
        state = {"i": 0, "stop": False}
        imgs = []
        for fr in frames:
            im = qr_image(fr, 360)
            ph = ImageTk.PhotoImage(im); imgs.append(ph)
        def tick():
            if state["stop"] or not win.winfo_exists(): return
            i = state["i"] % len(frames)
            lbl.config(image=imgs[i]); info.config(text=f"Frame {i+1}/{len(frames)}")
            state["i"] += 1
            win.after(300, tick)
        win.protocol("WM_DELETE_WINDOW", lambda: (state.__setitem__("stop", True), win.destroy()))
        tick()
        self._qr_keepalive = imgs  # prevent GC

    def scan_qr_dialog(self, on_result, accept_plain=False):
        if not HAS_CAM:
            messagebox.showinfo("Camera scanning unavailable",
                "Install it with:\n  pip install pyzbar opencv-python\n\n"
                "Or paste the payload text / load from file instead.")
            return
        win = tk.Toplevel(self.root); win.title("Scan QR (multi-frame supported)")
        win.geometry("520x460")
        vid = tk.Label(win); vid.pack(padx=8, pady=8)
        info = tk.Label(win, text="Starting camera…", font=("Consolas", 9)); info.pack()
        tk.Button(win, text="Cancel", command=win.destroy).pack(pady=4)
        q = queue.Queue(); collected = {}
        urdec = evur.URDecoder() if HAS_UR else None

        def grab():
            cap = cv2.VideoCapture(0)
            try:
                while win.winfo_exists():
                    ok, frame = cap.read()
                    if not ok: time.sleep(0.1); continue
                    found = [d.data.decode() for d in _pyzbar.decode(frame)]
                    q.put(("frame", frame.copy()));
                    for txt in found: q.put(("code", txt))
                    time.sleep(0.03)
            except Exception as e:
                q.put(("err", str(e)))
            finally:
                cap.release()

        def handle_code(txt):
            txt = txt.strip()
            if txt[:3].lower() == "ur:":                      # EIP-4527 / Uniform Resources
                if not HAS_UR:
                    info.config(text="UR QR seen — pip install cbor2 rlp (and keep evur.py + ur.py next to ethvault.py)"); return
                try:
                    if urdec.add(txt):
                        t, body = urdec.result(); win.destroy()
                        on_result(evur.ur_encode_single(t, body)); return
                    n, tot = urdec.progress(); info.config(text=f"UR fragments: {n}/{tot}")
                except Exception as e:
                    info.config(text=f"UR scan: {e}")
                return
            if txt.startswith(("EVU1:", "EVS1:")):
                win.destroy(); on_result(txt); return
            if txt.startswith("EVF:"):
                try:
                    _, pos, chunk = txt.split(":", 2)
                    i, n = map(int, pos.split("/"))
                    collected[i] = chunk
                    info.config(text=f"Collected {len(collected)}/{n} frames")
                    if len(collected) == n:
                        win.destroy(); on_result("".join(collected[k] for k in range(1, n + 1)))
                except Exception:
                    pass
                return
            if accept_plain:                                   # plain text QR (base64 PSBT, zpub, key-origin, address…)
                win.destroy(); on_result(txt)

        def poll():
            if not win.winfo_exists(): return
            try:
                while True:
                    kind, item = q.get_nowait()
                    if kind == "frame":
                        im = Image.fromarray(cv2.cvtColor(item, cv2.COLOR_BGR2RGB)).resize((460, 320))
                        poll.ph = ImageTk.PhotoImage(im); vid.config(image=poll.ph)
                    elif kind == "code":
                        handle_code(item)
                    elif kind == "err":
                        info.config(text=f"Camera error: {item}")
            except queue.Empty:
                pass
            self.root.after(50, poll)

        threading.Thread(target=grab, daemon=True).start()
        poll()

    # ------------------------- TAB 1: CREATE -----------------------------
    def _build_create_tab(self):
        f = self.tabs["1. Create Wallet (OFFLINE)"]
        ttk.Label(f, text="Generate a brand-new wallet. Do this ONLY on a machine with no internet connection.",
                  foreground="#a00").grid(row=0, column=0, columnspan=3, sticky="w", padx=10, pady=8)

        self.create_pw1 = ttk.Entry(f, show="*"); self.create_pw2 = ttk.Entry(f, show="*")
        ttk.Label(f, text="Keystore password:").grid(row=1, column=0, sticky="e", padx=8, pady=4)
        self.create_pw1.grid(row=1, column=1, sticky="we", padx=8, pady=4)
        ttk.Label(f, text="Repeat password:").grid(row=2, column=0, sticky="e", padx=8, pady=4)
        self.create_pw2.grid(row=2, column=1, sticky="we", padx=8, pady=4)

        ttk.Button(f, text="Generate (random key)", command=lambda: self.create_wallet(seed=False)
                   ).grid(row=3, column=0, pady=12, padx=8, sticky="we")
        ttk.Button(f, text="Generate + 24-word seed phrase (BIP-39)", command=lambda: self.create_wallet(seed=True)
                   ).grid(row=3, column=1, pady=12, padx=8, sticky="we")

        ttk.Separator(f, orient="horizontal").grid(row=4, column=0, columnspan=3, sticky="we", pady=8)
        ttk.Label(f, text="Restore from existing seed phrase:").grid(row=5, column=0, columnspan=2, sticky="w", padx=8)
        self.restore_seed = tk.Text(f, height=3, width=70)
        self.restore_seed.grid(row=6, column=0, columnspan=2, sticky="we", padx=8, pady=4)
        ttk.Button(f, text="Restore + encrypt to keystore", command=self.restore_wallet
                   ).grid(row=7, column=0, pady=6, padx=8, sticky="we")

        self.create_out = tk.Text(f, height=12, width=90, state="disabled")
        self.create_out.grid(row=8, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
        f.columnconfigure(1, weight=1); f.rowconfigure(8, weight=1)

    def _check_pw(self):
        p1, p2 = self.create_pw1.get(), self.create_pw2.get()
        if len(p1) < 8:
            messagebox.showerror("Password", "Password must be at least 8 characters."); return None
        if p1 != p2:
            messagebox.showerror("Password", "Passwords do not match."); return None
        return p1

    def create_wallet(self, seed: bool):
        pw = self._check_pw()
        if not pw: return
        def work():
            mnemonic = None
            if seed:
                acct, mnemonic = Account.create_with_mnemonic(num_words=24)
            else:
                acct = Account.create()
            ks = Account.encrypt(acct.key, pw)     # scrypt keystore v3
            return acct.address, ks, mnemonic
        def done(res, err):
            if err: return messagebox.showerror("Error", str(err))
            addr, ks, mnemonic = res
            path = filedialog.asksaveasfilename(defaultextension=".json",
                        initialfile=f"UTC--{addr[2:10]}.keystore.json",
                        filetypes=[("Keystore", "*.json")])
            if not path: return
            with open(path, "w") as fh: json.dump(ks, fh, indent=1)
            out = (f"Wallet created {datetime.now():%Y-%m-%d %H:%M}\n"
                   f"Address : {addr}\nKeystore: {path}\n\n"
                   f"IMPORTANT:\n"
                   f"- Copy the keystore file to the ONLINE machine (it is safe to share; it contains NO plaintext key).\n"
                   f"- Keep this offline machine + password safe.\n")
            if mnemonic:
                self.show_seed_dialog(mnemonic, addr)
                out += "- A 24-word seed phrase was shown (and is NOT saved anywhere).\n"
            self.create_out.config(state="normal"); self.create_out.delete("1.0", "end")
            self.create_out.insert("1.0", out); self.create_out.config(state="disabled")
            self.set_status(f"Wallet created: {addr}")
        self.async_do(work, done)

    def show_seed_dialog(self, mnemonic: str, addr: str):
        win = tk.Toplevel(self.root); win.title("SEED PHRASE — write it down NOW")
        win.geometry("640x340")
        tk.Label(win, text="Write these 24 words on paper. Never photograph, copy or store them digitally.",
                 fg="#a00", font=("Segoe UI", 10, "bold")).pack(pady=8)
        t = tk.Text(win, height=6, width=72, font=("Consolas", 12)); t.pack(padx=12)
        t.insert("1.0", mnemonic)
        tk.Label(win, text=f"Address: {addr}").pack(pady=6)
        def close():
            t.delete("1.0", "end")   # wipe from screen
            win.destroy()
        tk.Button(win, text="I have written it down — wipe from screen", command=close,
                  bg="#2e7d32", fg="white").pack(pady=8)

    def restore_wallet(self):
        pw = self._check_pw()
        if not pw: return
        words = " ".join(self.restore_seed.get("1.0", "end").split())
        if len(words.split()) not in (12, 15, 18, 21, 24):
            return messagebox.showerror("Seed", "Enter a valid 12/15/18/21/24-word seed phrase.")
        def work():
            acct = Account.from_mnemonic(words)
            ks = Account.encrypt(acct.key, pw)
            return acct.address, ks
        def done(res, err):
            if err: return messagebox.showerror("Error", str(err))
            addr, ks = res
            path = filedialog.asksaveasfilename(defaultextension=".json",
                        initialfile=f"UTC--{addr[2:10]}.keystore.json", filetypes=[("Keystore", "*.json")])
            if not path: return
            with open(path, "w") as fh: json.dump(ks, fh, indent=1)
            self.create_out.config(state="normal"); self.create_out.insert("end",
                f"Restored {addr}\nKeystore saved: {path}\n")
            self.create_out.config(state="disabled")
        self.async_do(work, done)

    # ------------------------- TAB 2: BUILD TX ----------------------------
    def _build_tab(self):
        f = self.tabs["2. Build Unsigned Tx"]
        r = 0
        ttk.Label(f, text=f"ONLINE step — runs on the watch-only machine{' (enter values manually in offline mode)' if OFFLINE else ''}:"
                  ).grid(row=r, column=0, columnspan=4, sticky="w", padx=10, pady=6); r += 1

        ttk.Label(f, text="Network:").grid(row=r, column=0, sticky="e", padx=6, pady=3)
        self.b_net = ttk.Combobox(f, values=list(NETWORKS.keys()), state="readonly"); self.b_net.set(DEFAULT_NET)
        self.b_net.grid(row=r, column=1, sticky="we", padx=6, pady=3)
        ttk.Label(f, text="RPC URL:").grid(row=r, column=2, sticky="e", padx=6)
        self.b_rpc = ttk.Entry(f); self.b_rpc.insert(0, NETWORKS[DEFAULT_NET]["rpc"])
        self.b_rpc.grid(row=r, column=3, sticky="we", padx=6, pady=3)
        self.b_net.bind("<<ComboboxSelected>>", lambda e: (self.b_rpc.delete(0, "end"),
                        self.b_rpc.insert(0, NETWORKS[self.b_net.get()]["rpc"])))
        r += 1

        fields = [("From (your cold wallet address):", "b_from"), ("To address:", "b_to"),
                  ("Amount (ETH):", "b_amount"), ("Nonce:", "b_nonce"),
                  ("Max fee (gwei):", "b_maxfee"), ("Priority tip (gwei):", "b_tip"),
                  ("Gas limit:", "b_gas"), ("Data (hex, optional):", "b_data")]
        for label, attr in fields:
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="e", padx=6, pady=3)
            e = ttk.Entry(f); e.grid(row=r, column=1, columnspan=3, sticky="we", padx=6, pady=3)
            setattr(self, attr, e); r += 1

        ttk.Button(f, text="Fetch nonce / fees / gas from network",
                   command=self.fetch_tx_params).grid(row=r, column=1, sticky="w", padx=6, pady=6)
        ttk.Button(f, text="Build unsigned tx  →  QR", command=self.build_tx_qr
                   ).grid(row=r, column=2, sticky="e", padx=6, pady=6)
        ttk.Button(f, text="Save payload to file", command=self.build_tx_file
                   ).grid(row=r, column=3, sticky="w", padx=6, pady=6); r += 1

        self.b_out = tk.Text(f, height=8); self.b_out.grid(row=r, column=0, columnspan=4,
                                                           padx=10, pady=8, sticky="nsew")
        f.columnconfigure(3, weight=1); f.rowconfigure(r, weight=1)

    def fetch_tx_params(self):
        addr = self.b_from.get().strip()
        try: addr = checksum(addr)
        except Exception: return messagebox.showerror("Error", "Invalid 'From' address.")
        url = self.b_rpc.get().strip()
        to = self.b_to.get().strip()
        def work():
            nonce = rpc_nonce(url, addr)
            base = rpc_base_fee(url); tip = rpc_tip(url)
            maxfee = 2 * base + tip
            try: value = int(Decimal(self.b_amount.get()) * WEI)
            except Exception: value = 0
            gas = rpc_estimate_gas(url, addr, checksum(to) if to else None, value) if to else 21000
            cid = rpc_chain_id(url)
            return nonce, maxfee, tip, gas, cid, rpc_balance(url, addr)
        def done(res, err):
            if err: return messagebox.showerror("Network error", str(err))
            nonce, maxfee, tip, gas, cid, bal = res
            exp = NETWORKS[self.b_net.get()]["chain_id"]
            if exp and cid != exp:
                messagebox.showwarning("Chain mismatch", f"RPC reports chainId {cid}, expected {exp}!")
            self.b_nonce.delete(0, "end");   self.b_nonce.insert(0, str(nonce))
            self.b_maxfee.delete(0, "end");  self.b_maxfee.insert(0, f"{maxfee/GWEI:.2f}")
            self.b_tip.delete(0, "end");     self.b_tip.insert(0, f"{tip/GWEI:.2f}")
            self.b_gas.delete(0, "end");     self.b_gas.insert(0, str(gas))
            self.set_status(f"Fetched: nonce={nonce}  balance={to_eth(bal)} ETH  base-fee-based max fee={maxfee/GWEI:.2f} gwei")
        self.async_do(work, done)

    def _collect_unsigned_tx(self):
        frm = checksum(self.b_from.get().strip())
        to  = checksum(self.b_to.get().strip())
        value = int(Decimal(self.b_amount.get()) * WEI)
        if value < 0: raise ValueError("Amount must be positive")
        data = self.b_data.get().strip() or "0x"
        if not data.startswith("0x"): data = "0x" + data
        bytes.fromhex(data[2:])  # validate hex
        tx = {
            "nonce": int(self.b_nonce.get()),
            "to": to,
            "value": value,
            "gas": int(self.b_gas.get()),
            "maxFeePerGas": int(Decimal(self.b_maxfee.get()) * GWEI),
            "maxPriorityFeePerGas": int(Decimal(self.b_tip.get()) * GWEI),
            "chainId": NETWORKS[self.b_net.get()]["chain_id"],
            "data": data,
        }
        return frm, to, tx

    def _build_payload(self):
        frm, to, tx = self._collect_unsigned_tx()
        est_fee = tx["gas"] * tx["maxFeePerGas"]
        obj = {"tx": tx, "from": frm, "network": self.b_net.get(),
               "created": datetime.now().isoformat(timespec="seconds"),
               "max_fee_eth": to_eth(est_fee)}
        payload = pack("EVU1:", obj)
        review = (f"UNSIGNED TRANSACTION (EIP-1559)\n"
                  f"Network : {obj['network']} (chainId {tx['chainId']})\n"
                  f"From    : {frm}\nTo      : {to}\n"
                  f"Amount  : {to_eth(tx['value'])} ETH\n"
                  f"Nonce   : {tx['nonce']}    Gas: {tx['gas']}\n"
                  f"Max fee : {tx['maxFeePerGas']/GWEI:.2f} gwei (tip {tx['maxPriorityFeePerGas']/GWEI:.2f})\n"
                  f"Max cost: {to_eth(tx['value'] + est_fee)} ETH (incl. fees)\n"
                  f"Payload : {len(payload)} chars (zlib-compressed)\n\n{payload}\n")
        return payload, review

    def build_tx_qr(self):
        try:
            payload, review = self._build_payload()
        except Exception as e:
            return messagebox.showerror("Build error", str(e))
        self.b_out.delete("1.0", "end"); self.b_out.insert("1.0", review)
        self.show_qr_window(payload, "UNSIGNED TX → scan with the OFFLINE machine")

    def build_tx_file(self):
        try:
            payload, review = self._build_payload()
        except Exception as e:
            return messagebox.showerror("Build error", str(e))
        path = filedialog.asksaveasfilename(defaultextension=".evu.txt", filetypes=[("Unsigned payload", "*.evu.txt")])
        if path:
            open(path, "w").write(payload)
            self.b_out.delete("1.0", "end"); self.b_out.insert("1.0", review + f"\nSaved: {path}")

    # ------------------------- TAB 3: SIGN TX ------------------------------
    def _sign_tab(self):
        f = self.tabs["3. Sign Tx (OFFLINE)"]
        ttk.Label(f, text="OFFLINE step — load the unsigned payload (QR / file / paste), review it, sign with your keystore.",
                  foreground="#a00").grid(row=0, column=0, columnspan=3, sticky="w", padx=10, pady=6)

        ttk.Label(f, text="Unsigned payload:").grid(row=1, column=0, sticky="w", padx=10)
        self.s_payload = tk.Text(f, height=5)
        self.s_payload.grid(row=2, column=0, columnspan=3, padx=10, pady=4, sticky="we")
        ttk.Button(f, text="Load from file", command=self.sign_load_file).grid(row=3, column=0, sticky="w", padx=10)
        ttk.Button(f, text="Scan QR with camera", command=lambda: self.scan_qr_dialog(self.s_payload_qr)
                   ).grid(row=3, column=1, sticky="w", padx=10)

        ttk.Label(f, text="Keystore file:").grid(row=4, column=0, sticky="w", padx=10, pady=(10, 0))
        self.s_ks_path = ttk.Entry(f)
        self.s_ks_path.grid(row=5, column=0, columnspan=2, sticky="we", padx=10, pady=2)
        ttk.Button(f, text="Browse…", command=self.sign_pick_ks).grid(row=5, column=2, sticky="w", padx=10)
        ttk.Label(f, text="Keystore password:").grid(row=6, column=0, sticky="w", padx=10)
        self.s_pw = ttk.Entry(f, show="*"); self.s_pw.grid(row=6, column=1, sticky="we", padx=10, pady=2)

        ttk.Button(f, text="REVIEW & SIGN", command=self.sign_tx).grid(row=7, column=0, columnspan=3, pady=12)

        self.s_out = tk.Text(f, height=14)
        self.s_out.grid(row=8, column=0, columnspan=3, padx=10, pady=6, sticky="nsew")
        f.columnconfigure(1, weight=1); f.rowconfigure(8, weight=1)

    def s_payload_qr(self, text):
        self.s_payload.delete("1.0", "end"); self.s_payload.insert("1.0", text.strip())
        self.set_status("Payload scanned.")

    def sign_load_file(self):
        p = filedialog.askopenfilename(filetypes=[("Payload", "*.evu.txt *.txt"), ("All", "*.*")])
        if p:
            self.s_payload.delete("1.0", "end")
            self.s_payload.insert("1.0", open(p).read().strip())

    def sign_pick_ks(self):
        p = filedialog.askopenfilename(filetypes=[("Keystore", "*.json"), ("All", "*.*")])
        if p: self.s_ks_path.delete(0, "end"); self.s_ks_path.insert(0, p)

    def sign_ur_request(self, text):
        if not HAS_UR:
            return messagebox.showerror("EIP-4527", "Install:  pip install cbor2 rlp   (and keep evur.py + ur.py next to ethvault.py)")
        try:
            rq, tx = evur.validate_sign_request(text)
        except Exception as e:
            return messagebox.showerror("EIP-4527 request error", str(e))
        net = next((n for n, v in NETWORKS.items() if v["chain_id"] == tx["chainId"]), None)
        data = tx.get("data", "0x")
        review = ("EIP-4527 request from: " + str(rq.get("origin") or "unknown app") + "\n"
                  "Please verify EVERY line before signing:\n\n"
                  f"Network : {net or 'UNKNOWN network'}  (chainId {tx['chainId']})\n"
                  f"From    : {('0x' + bytes(rq['address']).hex()) if rq.get('address') else '(this keystore)'}\n"
                  f"To      : {tx['to']}\n"
                  f"Amount  : {to_eth(tx['value'])} ETH\n"
                  f"Nonce   : {tx['nonce']}   Gas: {tx['gas']}\n"
                  f"Max fee : {tx['maxFeePerGas']/GWEI:.2f} gwei  (tip {tx['maxPriorityFeePerGas']/GWEI:.2f})\n"
                  f"Max cost: {to_eth(tx['value'] + tx['gas']*tx['maxFeePerGas'])} ETH\n"
                  f"Data    : {data[:80]}{'  <-- CONTRACT CALL' if data not in ('0x', '') else ''}\n")
        if not net:
            review += "\nWARNING: this chainId is not a network ETHVault knows.\n"
        if not messagebox.askyesno("Confirm signing", review + "\nSign this transaction?"):
            return
        ks_path = self.s_ks_path.get().strip(); pw = self.s_pw.get()
        if not ks_path or not os.path.exists(ks_path):
            return messagebox.showerror("Keystore", "Choose the keystore file.")
        def work():
            key = Account.decrypt(json.load(open(ks_path)), pw)
            try:
                sig, addr = evur.sign_request_with_key(rq, tx, key)
            finally:
                key = b"\x00" * len(key); del key
            frames = evur.ur_encode_frames("eth-signature", evur.signature_cbor(rq["request_id"], sig), 120)
            return frames, addr
        def done(res, err):
            if err: return messagebox.showerror("Signing failed", f"{err}\n(Wrong password?)")
            frames, addr = res
            self.s_out.delete("1.0", "end")
            self.s_out.insert("1.0", f"SIGNED ✔  signer: {addr}\n"
                f"Show the QR to MetaMask (or the requesting app) — it broadcasts the transaction.\n\n{frames[0].lower()}\n")
            self.s_pw.delete(0, "end")
            self.show_qr_window(frames[0], "SIGNATURE → scan with MetaMask / requesting app", frames=frames)
            self.set_status("Signed (EIP-4527). Scan the signature QR with the requesting app.")
        self.set_status("Decrypting keystore (scrypt)…")
        self.async_do(work, done)

    def sign_tx(self):
        _t = self.s_payload.get("1.0", "end").strip()
        if _t[:3].lower() == "ur:":
            return self.sign_ur_request(_t)
        try:
            pre, obj = unpack(self.s_payload.get("1.0", "end"))
        except Exception as e:
            return messagebox.showerror("Payload error", str(e))
        if pre != "EVU1:":
            return messagebox.showerror("Payload error", "This is not an UNSIGNED (EVU1) payload.")
        tx = obj["tx"]
        review = ("Please verify EVERY line before signing:\n\n"
                  f"Network : {obj.get('network')}  (chainId {tx['chainId']})\n"
                  f"From    : {obj.get('from')}\n"
                  f"To      : {tx['to']}\n"
                  f"Amount  : {to_eth(tx['value'])} ETH\n"
                  f"Nonce   : {tx['nonce']}   Gas: {tx['gas']}\n"
                  f"Max fee : {tx['maxFeePerGas']/GWEI:.2f} gwei  (tip {tx['maxPriorityFeePerGas']/GWEI:.2f})\n"
                  f"Max cost: {to_eth(tx['value'] + tx['gas']*tx['maxFeePerGas'])} ETH\n"
                  f"Data    : {tx.get('data', '0x')[:80]}\n")
        if not messagebox.askyesno("Confirm signing", review + "\nSign this transaction?"):
            return
        ks_path = self.s_ks_path.get().strip(); pw = self.s_pw.get()
        if not ks_path or not os.path.exists(ks_path):
            return messagebox.showerror("Keystore", "Choose the keystore file.")
        def work():
            ks = json.load(open(ks_path))
            key = Account.decrypt(ks, pw)          # scrypt — may take a second or two
            try:
                signed = Account.sign_transaction(tx, key)
            finally:
                key = b"\x00" * len(key); del key  # best-effort wipe
            raw = "0x" + signed.raw_transaction.hex()
            signer = Account.recover_transaction(raw)
            return raw, signer
        def done(res, err):
            if err: return messagebox.showerror("Signing failed", f"{err}\n(Wrong password?)")
            raw, signer = res
            if signer.lower() != str(obj.get("from", "")).lower():
                return messagebox.showerror("SIGNER MISMATCH",
                    f"Recovered signer {signer} != payload 'from' {obj.get('from')}.\nRefusing to export.")
            out = pack("EVS1:", {"raw": raw, "tx": tx, "network": obj.get("network"),
                                 "signer": signer, "signed_at": datetime.now().isoformat(timespec="seconds")})
            self.s_out.delete("1.0", "end")
            self.s_out.insert("1.0",
                f"SIGNED ✔   signer verified: {signer}\nSigned payload ({len(out)} chars):\n\n{out}\n")
            self.s_pw.delete(0, "end")
            self.show_qr_window(out, "SIGNED TX → scan with the ONLINE machine")
            self.set_status("Signed. Take this QR/file to the online machine to broadcast.")
        self.set_status("Decrypting keystore (scrypt)…")
        self.async_do(work, done)

    # ------------------------- TAB 4: BROADCAST ----------------------------
    def _broadcast_tab(self):
        f = self.tabs["4. Broadcast"]
        ttk.Label(f, text="ONLINE step — import the signed payload, verify the sender, broadcast to the network."
                  ).grid(row=0, column=0, columnspan=3, sticky="w", padx=10, pady=6)
        self.br_payload = tk.Text(f, height=6)
        self.br_payload.grid(row=1, column=0, columnspan=3, padx=10, pady=4, sticky="we")
        ttk.Button(f, text="Load from file", command=self.br_load_file).grid(row=2, column=0, sticky="w", padx=10)
        ttk.Button(f, text="Scan QR with camera", command=lambda: self.scan_qr_dialog(self.br_qr)).grid(row=2, column=1, sticky="w", padx=10)
        ttk.Button(f, text="BROADCAST", command=self.broadcast).grid(row=2, column=2, sticky="e", padx=10)
        self.br_out = tk.Text(f, height=16)
        self.br_out.grid(row=3, column=0, columnspan=3, padx=10, pady=8, sticky="nsew")
        f.columnconfigure(2, weight=1); f.rowconfigure(3, weight=1)

    def br_load_file(self):
        p = filedialog.askopenfilename(filetypes=[("Payload", "*.evs.txt *.txt"), ("All", "*.*")])
        if p:
            self.br_payload.delete("1.0", "end"); self.br_payload.insert("1.0", open(p).read().strip())

    def br_qr(self, text):
        self.br_payload.delete("1.0", "end"); self.br_payload.insert("1.0", text.strip())

    def broadcast(self):
        if OFFLINE:
            return messagebox.showerror("Offline mode", "Broadcasting needs network. Run ETHVault without --offline on the online machine.")
        try:
            pre, obj = unpack(self.br_payload.get("1.0", "end"))
        except Exception as e:
            return messagebox.showerror("Payload error", str(e))
        if pre != "EVS1:":
            return messagebox.showerror("Payload error", "This is not a SIGNED (EVS1) payload.")
        raw = obj["raw"]; tx = obj["tx"]
        signer = Account.recover_transaction(raw)
        url = self.b_rpc.get().strip() or NETWORKS[DEFAULT_NET]["rpc"]
        if not messagebox.askyesno("Confirm broadcast",
                f"Broadcast to {obj.get('network')} via\n{url}\n\n"
                f"To     : {tx['to']}\nAmount : {to_eth(tx['value'])} ETH\nNonce  : {tx['nonce']}\n"
                f"Signer : {signer}\n\nProceed?"):
            return
        def work():
            txh = rpc_broadcast(url, raw)
            receipt = None
            for _ in range(20):
                time.sleep(3)
                try:
                    receipt = rpc_receipt(url, txh)
                    if receipt: break
                except Exception:
                    pass
            return txh, receipt
        def done(res, err):
            if err: return messagebox.showerror("Broadcast failed", str(err))
            txh, receipt = res
            status = "PENDING (not mined yet — check explorer)"
            if receipt: status = "SUCCESS ✔" if receipt.get("status") == "0x1" else "REVERTED ✘"
            self.br_out.insert("1.0",
                f"{datetime.now():%H:%M:%S}  {status}\nTx hash : {txh}\n"
                f"Block   : {int(receipt['blockNumber'], 16) if receipt else '—'}\n"
                f"Gas used: {int(receipt['gasUsed'], 16) if receipt else '—'}\n\n")
            self.set_status(f"Broadcast: {txh}")
        self.set_status("Broadcasting…")
        self.async_do(work, done)

    # ------------------------- TAB 5: WATCH --------------------------------
    def _watch_tab(self):
        f = self.tabs["5. Watch Address"]
        ttk.Label(f, text="Read-only: check balance & nonce of your cold wallet (public address only — safe online)."
                  ).grid(row=0, column=0, columnspan=3, sticky="w", padx=10, pady=6)
        ttk.Label(f, text="Address:").grid(row=1, column=0, sticky="e", padx=6)
        self.w_addr = ttk.Entry(f); self.w_addr.grid(row=1, column=1, columnspan=2, sticky="we", padx=6, pady=4)
        ttk.Button(f, text="Refresh", command=self.watch_refresh).grid(row=2, column=1, sticky="w", padx=6, pady=6)
        self.w_out = tk.Text(f, height=8)
        self.w_out.grid(row=3, column=0, columnspan=3, padx=10, pady=8, sticky="nsew")
        f.columnconfigure(1, weight=1); f.rowconfigure(3, weight=1)

    def watch_refresh(self):
        try: addr = checksum(self.w_addr.get().strip())
        except Exception: return messagebox.showerror("Error", "Invalid address.")
        url = self.b_rpc.get().strip() or NETWORKS[DEFAULT_NET]["rpc"]
        def work():
            return rpc_balance(url, addr), rpc_nonce(url, addr)
        def done(res, err):
            if err: return messagebox.showerror("Network error", str(err))
            bal, nonce = res
            self.w_out.delete("1.0", "end")
            self.w_out.insert("1.0", f"Address : {addr}\nBalance : {to_eth(bal)} ETH\nNonce   : {nonce}\n")
        self.async_do(work, done)

    # ------------------------- TAB 6: PAIR (EIP-4527) -----------------------
    def _pair_tab(self):
        f = self.tabs["6. Pair (EIP-4527)"]
        ttk.Label(f, foreground="#a00", justify="left", text=(
            "OFFLINE step — show your PUBLIC account key as a QR so MetaMask (Add hardware wallet -> QR-based)\n"
            "or another EIP-4527 app can watch this wallet and send it transactions to sign.\n"
            "Needs the seed phrase (the keystore holds only the private key). Works only in --offline mode."
            )).grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=8)
        ttk.Label(f, text="Seed phrase:").grid(row=1, column=0, sticky="ne", padx=8)
        self.p_seed = tk.Text(f, height=3, width=70); self.p_seed.grid(row=1, column=1, sticky="we", padx=8, pady=4)
        ttk.Label(f, text="BIP-39 passphrase (optional):").grid(row=2, column=0, sticky="e", padx=8)
        self.p_pass = ttk.Entry(f, show="*"); self.p_pass.grid(row=2, column=1, sticky="we", padx=8, pady=4)
        ttk.Button(f, text="Show pairing QR (crypto-hdkey)", command=self.pair_show
                   ).grid(row=3, column=1, sticky="w", padx=8, pady=8)
        self.p_out = tk.Text(f, height=12); self.p_out.grid(row=4, column=0, columnspan=2, padx=10, pady=8, sticky="nsew")
        f.columnconfigure(1, weight=1); f.rowconfigure(4, weight=1)

    def pair_show(self):
        if not OFFLINE:
            return messagebox.showerror("Offline only",
                "Never type a seed phrase on an internet-connected machine.\nRun:  python ethvault.py --offline")
        if not HAS_UR:
            return messagebox.showerror("EIP-4527", "Install:  pip install cbor2 rlp   (and keep evur.py + ur.py next to ethvault.py)")
        words = " ".join(self.p_seed.get("1.0", "end").split()); pw = self.p_pass.get()
        if len(words.split()) not in (12, 15, 18, 21, 24):
            return messagebox.showerror("Seed", "Enter a valid 12/15/18/21/24-word seed phrase.")
        def work():
            x = evur.derive_account_xpub(words, pw)
            addr = Account.from_mnemonic(words, passphrase=pw).address
            return evur.ur_encode_frames("crypto-hdkey", evur.hdkey_cbor(x), 200), addr, x["master_fp"].hex()
        def done(res, err):
            if err: return messagebox.showerror("Error", str(err))
            frames, addr, xfp = res
            self.p_seed.delete("1.0", "end"); self.p_pass.delete(0, "end")     # wipe seed from screen
            self.p_out.delete("1.0", "end")
            self.p_out.insert("1.0", f"First account (m/44'/60'/0'/0/0): {addr}\nMaster fingerprint: {xfp}\n\n"
                "Compare that address with your keystore's address BEFORE pairing.\n"
                "Then in MetaMask: Add account or hardware wallet -> QR-based -> scan the QR.\n"
                "Later, MetaMask shows a request QR: load it in tab 3 (camera) and sign.")
            self.show_qr_window(frames[0], "PAIRING QR → scan with MetaMask / EIP-4527 app", frames=frames)
        self.async_do(work, done)

# -------------------------------- self test ----------------------------------
def selftest():
    print("ETHVault self-test (no network needed)…")
    acct = Account.create()
    ks = Account.encrypt(acct.key, "selftest-password")
    assert Account.decrypt(ks, "selftest-password") == acct.key, "keystore roundtrip failed"
    tx = {"nonce": 0, "to": checksum("0x000000000000000000000000000000000000dEaD"),
          "value": 10**17, "gas": 21000, "maxFeePerGas": 30 * GWEI,
          "maxPriorityFeePerGas": GWEI, "chainId": 1, "data": "0x"}
    signed = Account.sign_transaction(tx, acct.key)
    raw = "0x" + signed.raw_transaction.hex()
    assert Account.recover_transaction(raw) == acct.address, "signer recovery mismatch"
    p = pack("EVU1:", {"tx": tx, "from": acct.address})
    pre, obj = unpack(p)
    assert pre == "EVU1:" and obj["tx"]["value"] == tx["value"], "payload codec failed"
    print(f"  keystore encrypt/decrypt  OK   (address {acct.address})")
    print(f"  EIP-1559 sign + recover   OK   (raw tx {len(raw)} chars)")
    print(f"  zlib payload codec        OK   ({len(p)} chars)")
    if HAS_UR:
        from eth_utils import to_checksum_address
        t2 = dict(tx, chainId=11155111, type=2)
        req, _ = evur.sign_request_cbor(evur.encode_unsigned_1559(t2), b"\x00\x01\x02\x03",
                                        bytes.fromhex(acct.address[2:]), 11155111)
        text = evur.ur_encode_frames("eth-sign-request", req, 1000)[0].lower()
        rq, dtx = evur.validate_sign_request(text)
        sig, addr = evur.sign_request_with_key(rq, dtx, acct.key)
        rawx = evur.assemble_signed_1559(dtx, sig)
        assert addr == acct.address and Account.recover_transaction(rawx) == acct.address, "EIP-4527 roundtrip failed"
        print("  EIP-4527 sign request     OK   (request -> signature -> raw tx recovers to signer)")
    else:
        print("  EIP-4527 sign request     SKIPPED (pip install cbor2 rlp; keep evur.py + ur.py alongside)")
    print("ALL TESTS PASSED ✔")

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest(); sys.exit(0)
    if OFFLINE:
        print("OFFLINE MODE: network sockets disabled.")
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    app = ETHVaultApp(root)
    root.mainloop()