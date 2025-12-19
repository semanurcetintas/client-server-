import socket
import threading
import struct
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import math
import math as _math  # gcd
from Crypto.Cipher import DES, AES
import base64
from PIL import Image, ImageTk
import os
from manual_block_ciphers import des_encrypt_text, aes_encrypt_text
from tkinter import filedialog
from kdf_utils import make_salt, kdf_pbkdf2_sha256, b64e


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_LEN = 26


def _char_to_num(ch: str) -> int:
    return ord(ch.upper()) - ord('A')

def _num_to_char(n: int, upper_like: str) -> str:
    base = ord('A') if upper_like.isupper() else ord('a')
    return chr(base + (n % 26))

def _matrix_vec_mul(mat, vec, mod: int):
    n = len(mat)
    out = [0]*n
    for r in range(n):
        acc = 0
        for c in range(n):
            acc += mat[r][c] * vec[c]
        out[r] = acc % mod
    return out

def parse_hill_key(key_text: str):
    parts = key_text.replace(",", " ").split()
    if len(parts) == 0:
        raise ValueError("Hill için anahtar boş olamaz.")
    nums = []
    for p in parts:
        if not p.lstrip("-").isdigit():
            raise ValueError("Hill anahtarındaki değerler tam sayı olmalı.")
        nums.append(int(p) % 26)
    length = len(nums)
    n = int(round(length ** 0.5))
    if n * n != length:
        raise ValueError("Hill anahtarı n^2 adet sayı olmalı (örn 4 sayı=2x2, 9 sayı=3x3).")
    mat = []
    idx = 0
    for _ in range(n):
        row = nums[idx:idx+n]
        idx += n
        mat.append(row)
    return mat

def _extract_letters_with_index(text: str):
    letters = []
    idx_map = []
    for i,ch in enumerate(text):
        if ch.isalpha():
            letters.append(ch)
            idx_map.append(i)
    return letters, idx_map

def _reinject_letters(original_text: str, new_letters, idx_map):
    out_chars = list(original_text)
    ptr = 0
    for pos in idx_map:
        out_chars[pos] = new_letters[ptr]
        ptr += 1
    return "".join(out_chars)

def hill_encrypt(text: str, key_mat):
    n = len(key_mat)
    letters, idx_map = _extract_letters_with_index(text)
    if len(letters) % n != 0:
        pad_needed = n - (len(letters) % n)
        letters += ['X'] * pad_needed
    enc_letters = []
    for i in range(0, len(letters), n):
        block = letters[i:i+n]
        nums = [_char_to_num(ch) for ch in block]
        enc_nums = _matrix_vec_mul(key_mat, nums, 26)
        enc_block = [_num_to_char(enc_nums[j], block[j]) for j in range(n)]
        enc_letters.extend(enc_block)
    original_letter_count = len(idx_map)
    reinjected = _reinject_letters(text, enc_letters[:original_letter_count], idx_map)
    if len(enc_letters) > original_letter_count:
        reinjected += "".join(enc_letters[original_letter_count:])
    return reinjected

#VERNAM

def _vernam_clean_key(key: str) -> str:
    if not key or not key.isalpha():
        raise ValueError("Vernam anahtarı sadece harflerden oluşmalı (örn: SECRETKEY).")
    return key

def vernam_encrypt(text: str, key: str) -> str:
    key = _vernam_clean_key(key)
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            if ki >= len(key):
                raise ValueError("Vernam anahtarı mesaj kadar uzun olmalı (daha uzun olabilir, ama kısa olamaz).")
            kshift = (ord(key[ki].upper()) - 65) % 26
            if ch.isupper():
                cnum = ((ord(ch) - 65) + kshift) % 26
                out.append(chr(cnum + 65))
            else:
                cnum = ((ord(ch) - 97) + kshift) % 26
                out.append(chr(cnum + 97))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)

#  RSA DOĞRUDAN
def rsa_encrypt_text(plaintext: str, n: int, e: int) -> str:
    data = plaintext.encode("utf-8")
    k = (n.bit_length() + 7) // 8
    max_block = k - 2
    if max_block < 1:
        raise ValueError("RSA modülü çok küçük.")
    out = []
    for i in range(0, len(data), max_block):
        chunk = data[i:i+max_block]
        block = bytes([len(chunk)]) + chunk
        m = int.from_bytes(block, "big")
        c = pow(m, e, n)
        out.append(str(c))
    return "|".join(out)

def rsa_decrypt_text(ciphertext: str, n: int, d: int) -> str:
    if not ciphertext.strip():
        return ""
    parts = ciphertext.split("|")
    data = bytearray()
    for p in parts:
        c = int(p)
        m = pow(c, d, n)
        block = m.to_bytes((n.bit_length() + 7) // 8, "big")
        block = block.lstrip(b"\x00")
        if not block:
            continue
        ln = block[0]
        chunk = block[1:1+ln]
        data.extend(chunk)
    return data.decode("utf-8", errors="strict")

#  AFFINE

def _affine_parse_key_client(key_text: str):
    if "," not in key_text:
        raise ValueError("Affine anahtarı 'a,b' formatında olmalı. Örn: 5,8")
    a_str, b_str = key_text.split(",", 1)
    if not a_str.strip().isdigit() or not b_str.strip().isdigit():
        raise ValueError("Affine anahtarındaki a,b sayısal olmalı. Örn: 5,8")
    a = int(a_str) % 26
    b = int(b_str) % 26
    if _math.gcd(a, 26) != 1:
        raise ValueError("Affine anahtarında 'a' ile 26 aralarında asal olmalı (gcd(a,26)=1).")
    return (a, b)

def affine_encrypt(text: str, key_tuple):
    a, b = key_tuple
    out = []
    for ch in text:
        if ch.isalpha():
            if ch.isupper():
                pval = ord(ch) - 65
                cval = (a * pval + b) % 26
                out.append(chr(cval + 65))
            else:
                pval = ord(ch) - 97
                cval = (a * pval + b) % 26
                out.append(chr(cval + 97))
        else:
            out.append(ch)
    return "".join(out)


def caesar_encrypt(text: str, shift: int) -> str:
    shift %= 26
    out = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch)-65+shift) % 26 + 65))
        elif "a" <= ch <= "z":
            out.append(chr((ord(ch)-97+shift) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)

def vigenere_encrypt(text: str, key: str) -> str:
    if not key or not key.isalpha():
        raise ValueError("Vigenère anahtarı sadece harflerden oluşmalı (örn: LEMON).")
    shifts = [(ord(c.upper())-65) % 26 for c in key]
    out = []
    j = 0
    for ch in text:
        if ch.isalpha():
            s = shifts[j % len(shifts)]
            if ch.isupper():
                out.append(chr((ord(ch)-65+s) % 26 + 65))
            else:
                out.append(chr((ord(ch)-97+s) % 26 + 97))
            j += 1
        else:
            out.append(ch)
    return "".join(out)

def _normalize_sub_key(key: str) -> str:
    k = "".join([c for c in key.upper() if c.isalpha()])
    if len(k) != 26 or len(set(k)) != 26:
        raise ValueError("Substitution anahtarı 26 HARFTEN oluşan benzersiz bir permütasyon olmalı.")
    return k

def substitution_encrypt(text: str, key: str) -> str:
    k = _normalize_sub_key(key)
    map_up = {ALPHABET[i]: k[i] for i in range(26)}
    map_lo = {ALPHABET[i].lower(): k[i].lower() for i in range(26)}
    out = []
    for ch in text:
        if ch.isupper() and ch in map_up:
            out.append(map_up[ch])
        elif ch.islower() and ch in map_lo:
            out.append(map_lo[ch])
        else:
            out.append(ch)
    return "".join(out)

def _col_key_order(key: str):
    if not key or not key.isalpha():
        raise ValueError("Columnar için anahtar sadece harflerden oluşmalı (örn: ZEBRAS).")
    K = [(c, i) for i, c in enumerate(key.upper())]
    K_sorted = sorted(K, key=lambda x: (x[0], x[1]))
    return [orig_i for (_, orig_i) in K_sorted]

def columnar_encrypt(text: str, key: str) -> str:
    order = _col_key_order(key)
    m = len(order)
    n = len(text)
    rows = math.ceil(n / m) if m > 0 else 0
    rows_buf = []
    idx = 0
    for _ in range(rows):
        row = list(text[idx:idx+m])
        idx += len(row)
        rows_buf.append(row)
    out = []
    for col in order:
        for r in range(rows):
            row = rows_buf[r]
            if col < len(row):
                out.append(row[col])
    return "".join(out)

def _pf_prepare_key(key: str):
    s = []
    seen = set()
    for c in key.upper():
        if c.isalpha():
            c = "I" if c == "J" else c
            if c not in seen:
                seen.add(c); s.append(c)
    for c in ALPHABET:
        cc = "I" if c == "J" else c
        if cc not in seen:
            seen.add(cc); s.append(cc)
    table = [c for c in s if c != "J"]
    return [table[i*5:(i+1)*5] for i in range(5)]

def _pf_pos(table):
    pos = {}
    for r in range(5):
        for c in range(5):
            pos[table[r][c]] = (r, c)
    return pos

def _pf_prepare_plain(plain: str):
    letters = []
    idx_map = []
    for i, ch in enumerate(plain):
        if ch.isalpha():
            letters.append("I" if ch.upper() == "J" else ch.upper())
            idx_map.append(i)
    digraphs = []
    i = 0
    while i < len(letters):
        a = letters[i]
        if i+1 < len(letters):
            b = letters[i+1]
            if a == b:
                digraphs.append((a, "X"))
                i += 1
            else:
                digraphs.append((a, b))
                i += 2
        else:
            digraphs.append((a, "X"))
            i += 1
    return digraphs, idx_map

def playfair_encrypt(text: str, key: str) -> str:
    if not key or not any(c.isalpha() for c in key):
        raise ValueError("Playfair anahtarı harf içermeli (örn: SECURITY).")
    table = _pf_prepare_key(key)
    pos = _pf_pos(table)
    digraphs, idx_map = _pf_prepare_plain(text)
    out = list(text)

    def enc_pair(a, b):
        ra, ca = pos[a]; rb, cb = pos[b]
        if ra == rb:
            return (table[ra][(ca+1)%5], table[rb][(cb+1)%5])
        if ca == cb:
            return (table[(ra+1)%5][ca], table[(rb+1)%5][cb])
        return (table[ra][cb], table[rb][ca])

    letter_idx = 0
    for a, b in digraphs:
        ea, eb = enc_pair(a, b)
        while letter_idx < len(idx_map) and not text[idx_map[letter_idx]].isalpha():
            letter_idx += 1
        if letter_idx < len(idx_map):
            i = idx_map[letter_idx]
            out[i] = ea if text[i].isupper() else ea.lower()
            letter_idx += 1
        while letter_idx < len(idx_map) and not text[idx_map[letter_idx]].isalpha():
            letter_idx += 1
        if letter_idx < len(idx_map):
            i = idx_map[letter_idx]
            out[i] = eb if text[i].isupper() else eb.lower()
            letter_idx += 1

    return "".join(out)

def rail_fence_encrypt(text: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rail Fence için ray sayısı en az 2 olmalı.")
    fence = [[] for _ in range(rails)]
    rail = 0
    step = 1
    for ch in text:
        fence[rail].append(ch)
        rail += step
        if rail == 0 or rail == rails-1:
            step *= -1
    return "".join("".join(row) for row in fence)

# POLYBIUS

_POLYBIUS_TABLE = [
    ['A','B','C','D','E'],
    ['F','G','H','I','K'],
    ['L','M','N','O','P'],
    ['Q','R','S','T','U'],
    ['V','W','X','Y','Z'],
]
_POLY_ENC = { _POLYBIUS_TABLE[r][c]: f"{r+1}{c+1}" for r in range(5) for c in range(5) }

def polybius_encrypt(text: str) -> str:
    out = []
    for ch in text:
        if ch.isalpha():
            cu = ch.upper()
            cu = 'I' if cu == 'J' else cu
            out.append(_POLY_ENC[cu])
        else:
            out.append(ch)
    return "".join(out)

# AES/DES KÜTÜPHANELİ hali

def _des_parse_key_client(key_text: str) -> bytes:
    key_text = key_text.strip()
    if len(key_text) == 8:
        return key_text.encode("utf-8")
    if len(key_text) == 16:
        try:
            return bytes.fromhex(key_text)
        except ValueError:
            pass
    raise ValueError("DES anahtarı 8 karakter (örn: 12345678) veya 16 haneli hex olmalı.")

def _pkcs5_pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def des_encrypt(plain: str, key: bytes) -> str:
    data = plain.encode("utf-8")
    padded = _pkcs5_pad(data, 8)
    cipher = DES.new(key, DES.MODE_ECB)
    cbytes = cipher.encrypt(padded)
    return base64.b64encode(cbytes).decode("ascii")

def _aes_parse_key_client(key_text: str) -> bytes:
    key_text = key_text.strip()
    if len(key_text) in (16, 24, 32):
        return key_text.encode("utf-8")
    if len(key_text) in (32, 48, 64):
        try:
            return bytes.fromhex(key_text)
        except:
            pass
    raise ValueError("AES anahtarı 16/24/32 karakter veya 32/48/64 hex olmalı.")

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def aes_encrypt(text: str, key: bytes) -> str:
    data = text.encode("utf-8")
    padded = _pkcs7_pad(data, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode("ascii")

def des_encrypt_manual(plain: str, key: bytes) -> str:
    return des_encrypt_text(plain, key)

def aes_encrypt_manual(text: str, key: bytes) -> str:
    return aes_encrypt_text(text, key)

# RSA KÜTÜPHANESİZ/MANUEL, ANAHTAR DAĞITIMI

def _rsa_parse_public(key_text: str):
    if "," not in key_text:
        raise ValueError("RSA (istemci) anahtarı 'n,e' formatında olmalı.")
    n_str, e_str = key_text.split(",", 1)
    n_str, e_str = n_str.strip(), e_str.strip()
    if not n_str.isdigit() or not e_str.isdigit():
        raise ValueError("RSA n ve e sayısal olmalı.")
    n = int(n_str)
    e = int(e_str)
    return n, e

def rsa_encrypt_hybrid(plain: str, n: int, e: int, log_fn=None) -> str:
    aes_key = os.urandom(16)
    aes_cipher_b64 = aes_encrypt(plain, aes_key)
    nums = [pow(b, e, n) for b in aes_key]
    key_cipher = ",".join(str(x) for x in nums)
    if log_fn:
        log_fn(f"RSA-AES modunda kullanılan AES anahtarı (hex): {aes_key.hex()}")
    return f"RSA-AES|{key_cipher}|{aes_cipher_b64}"

#PIGPEN

def pigpen_encrypt(text: str) -> str:
    tokens = []
    for ch in text:
        if ch == " ":
            tokens.append("|SPACE|")
        elif ch.isalpha():
            tokens.append(ch.lower() + ".jpg")
        else:
            tokens.append(ch)
    return " ".join(tokens)

#SOCKET

def send_message(sock, text: str):
    data = text.encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)

#GUI

METHODS = [
    "Sezar (Caesar)",
    "Vigenère",
    "Substitution",
    "Playfair",
    "Rail Fence",
    "Columnar Transposition",
    "Polybius",
    "Hill",
    "Vernam",
    "Affine",
    "Pigpen",
    "DES (Kütüphane)",
    "DES (Manuel)",
    "AES-128 (Kütüphane)",
    "AES-128 (Manuel)",
    "RSA (AES Anahtar Dağıtımı)",
    "RSA (Doğrudan)",
]

class PlaceholderEntry(ttk.Entry):
    def __init__(self, master=None, placeholder="", **kw):
        super().__init__(master, **kw)
        self.placeholder = placeholder
        self.default_fg = self.cget("foreground")
        self.placeholder_fg = "#808080"
        self._has_placeholder = False
        self._put_placeholder()
        self.bind("<FocusIn>", self._focus_in)
        self.bind("<FocusOut>", self._focus_out)

    def _put_placeholder(self):
        if not self.get():
            self.insert(0, self.placeholder)
            self.configure(foreground=self.placeholder_fg)
            self._has_placeholder = True

    def _focus_in(self, _):
        if self._has_placeholder:
            self.delete(0, "end")
            self.configure(foreground=self.default_fg)
            self._has_placeholder = False

    def _focus_out(self, _):
        self._put_placeholder()

    def value(self):
        return "" if self._has_placeholder else self.get().strip()

class ClientGUI:

    def pick_file(self):
        path = filedialog.askopenfilename(
            title="Şifrelenecek dosyayı seç",
            filetypes=[("All files", "*.*")]
        )
        if path:
            self.file_path_var.set(path)
            self.log(f"Dosya seçildi: {path}")

    def _ensure_file_method_allowed(self):
        m = self.method.get()
        allowed = {
            "DES (Kütüphane)",
            "DES (Manuel)",
            "AES-128 (Kütüphane)",
            "AES-128 (Manuel)",
            "RSA (AES Anahtar Dağıtımı)",
        }
        if m not in allowed:
            raise ValueError(
                "Dosya şifreleme için bu yöntem uygun değil. "
                "Dosyada sadece DES/AES/RSA-AES kullan."
            )

    def encrypt_file_local(self):
        path = self.file_path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Hata", "Geçerli bir dosya seç.")
            return

        try:
            self._ensure_file_method_allowed()
            with open(path, "rb") as f:
                raw = f.read()

            b64_plain = base64.b64encode(raw).decode("ascii")
            cipher_text = self._encrypt(b64_plain)

            out_path = path + ".enc.txt"
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(cipher_text)

            self.log(f"Dosya şifrelendi ve kaydedildi: {out_path}")
            messagebox.showinfo("OK", f"Şifreli çıktı:\n{out_path}")

        except Exception as e:
            messagebox.showerror("Dosya Şifreleme Hatası", str(e))

    def send_file_to_server(self):
        host = self.host_entry.value()
        port_str = self.port_entry.value()

        path = self.file_path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Hata", "Geçerli bir dosya seç.")
            return
        if not host or not port_str or not port_str.isdigit():
            messagebox.showerror("Hata", "Host/Port hatalı.")
            return

        try:
            self._ensure_file_method_allowed()
            with open(path, "rb") as f:
                raw = f.read()

            b64_plain = base64.b64encode(raw).decode("ascii")
            cipher_text = self._encrypt(b64_plain)

            filename = os.path.basename(path)
            payload = f"FILE|{filename}|{cipher_text}"

        except Exception as e:
            messagebox.showerror("Hata", str(e))
            return

        port = int(port_str)

        def do_send():
            try:
                with socket.create_connection((host, port), timeout=5) as s:
                    send_message(s, payload)
                    self.log(f"Dosya gönderildi -> {host}:{port} ({filename})")
            except Exception as e:
                self.log(f"Dosya gönderme hatası: {e}")

        threading.Thread(target=do_send, daemon=True).start()

    def __init__(self, root):
        root.title("İstemci - Mesaj Şifreleme")

        wrap = ttk.Frame(root, padding=12)
        wrap.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        wrap.columnconfigure(1, weight=1)

        r = 0
        ttk.Label(wrap, text="İstemci - Mesaj Şifreleme", font=("Segoe UI", 16, "bold")).grid(
            row=r, column=0, columnspan=2, pady=(0,8), sticky="w"
        ); r += 1

        ttk.Label(wrap, text="Sunucu Host").grid(row=r, column=0, sticky="w")
        self.host_entry = PlaceholderEntry(wrap, placeholder="127.0.0.1")
        self.host_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Sunucu Port").grid(row=r, column=0, sticky="w")
        self.port_entry = PlaceholderEntry(wrap, placeholder="5000")
        self.port_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Yöntem").grid(row=r, column=0, sticky="w")
        self.method = ttk.Combobox(wrap, values=METHODS, state="readonly")
        self.method.current(0)
        self.method.grid(row=r, column=1, sticky="ew", padx=6)
        self.method.bind("<<ComboboxSelected>>", self._on_method_change)
        r += 1

        ttk.Label(wrap, text="Anahtar / Parola").grid(row=r, column=0, sticky="w")
        self.key_entry = PlaceholderEntry(
            wrap,
            placeholder=(
                "Sezar: 3 | Vigenère: LEMON | Subst.: 26 harf | "
                "Playfair: SECURITY | Rail: 3 | Columnar: ZEBRAS | "
                "Polybius: (gerekmez) | Hill: '3 3 2 5' | Vernam: SECRETKEY | "
                "Affine: 5,8 | Pigpen: (gerekmez) | DES: 12345678 | "
                "AES: 16 char (manuel), 16/24/32 (kütüphane) | RSA istemci: n,e"
            )
        )
        self.key_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        # --- KDF UI ---
        self.use_kdf = tk.BooleanVar(value=False)
        ttk.Checkbutton(wrap, text="KDF kullan (PBKDF2) [DES/AES için]", variable=self.use_kdf).grid(
            row=r, column=1, sticky="w"
        ); r += 1

        ttk.Label(wrap, text="KDF Iter").grid(row=r, column=0, sticky="w")
        self.kdf_iter_entry = ttk.Entry(wrap)
        self.kdf_iter_entry.insert(0, "200000")
        self.kdf_iter_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Mesaj").grid(row=r, column=0, sticky="w")
        self.msg_text = scrolledtext.ScrolledText(wrap, height=4)
        self.msg_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        # --- DOSYA MODU ---
        ttk.Label(wrap, text="Dosya").grid(row=r, column=0, sticky="w")
        self.file_path_var = tk.StringVar(value="")
        self.file_entry = ttk.Entry(wrap, textvariable=self.file_path_var)
        self.file_entry.grid(row=r, column=1, sticky="ew", padx=6)
        r += 1

        file_btns = ttk.Frame(wrap)
        file_btns.grid(row=r, column=0, columnspan=2, pady=6, sticky="w")
        ttk.Button(file_btns, text="Dosya Seç", command=self.pick_file).pack(side="left", padx=4)
        ttk.Button(file_btns, text="Dosyayı Şifrele (Kaydet)", command=self.encrypt_file_local).pack(side="left", padx=4)
        ttk.Button(file_btns, text="Dosyayı Şifrele ve Sunucuya Gönder", command=self.send_file_to_server).pack(side="left", padx=4)
        r += 1

        btns = ttk.Frame(wrap)
        btns.grid(row=r, column=0, columnspan=2, pady=8, sticky="w")
        ttk.Button(btns, text="Şifrele ve Gönder", command=self.send_to_server).pack(side="left", padx=4)
        ttk.Button(btns, text="Temizle", command=lambda: self.msg_text.delete("1.0", "end")).pack(side="left", padx=4)
        r += 1

        ttk.Label(wrap, text="İstemci Log").grid(row=r, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(wrap, height=8)
        self.log_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        wrap.rowconfigure(7, weight=1)

        # ilk method placeholder
        self._on_method_change(None)

    def _on_method_change(self, _):
        m = self.method.get()
        # RSA seçilirse KDF kapat (mantıklı değil)
        if m.startswith("RSA"):
            self.use_kdf.set(False)

        ph = {
            "Sezar (Caesar)": "3",
            "Vigenère": "LEMON",
            "Substitution": "QWERTYUIOPASDFGHJKLZXCVBNM",
            "Playfair": "SECURITY",
            "Rail Fence": "3",
            "Columnar Transposition": "ZEBRAS",
            "Polybius": "(anahtar gerekmez)",
            "Hill": "Örn: '3 3 2 5' (2x2) | '6 24 1 13 16 10 20 17 15' (3x3)",
            "Vernam": "SECRETKEY",
            "Affine": "a,b örn: 5,8",
            "Pigpen": "(anahtar gerekmez)",
            "DES (Kütüphane)": "KDF kapalıysa: 8 karakter / 16 hex | KDF açıksa: parola",
            "DES (Manuel)": "KDF kapalıysa: 8 karakter / 16 hex | KDF açıksa: parola",
            "AES-128 (Kütüphane)": "KDF kapalıysa: 16/24/32 char (veya hex) | KDF açıksa: parola",
            "AES-128 (Manuel)": "KDF kapalıysa: 16 karakter veya 32 hex | KDF açıksa: parola",
            "RSA (AES Anahtar Dağıtımı)": "n,e (istemci public)",
            "RSA (Doğrudan)": "n,e (public) örn: 123...,65537",
        }[m]

        self.key_entry.placeholder = ph
        if not self.key_entry.value():
            self.key_entry.delete(0, "end")
            self.key_entry._has_placeholder = False
            self.key_entry._put_placeholder()

    def log(self, s):
        self.log_text.insert("end", s + "\n")
        self.log_text.see("end")

    def _parse_key(self):
        m = self.method.get()
        k = self.key_entry.value()

        if m == "Sezar (Caesar)":
            if not k.isdigit():
                raise ValueError("Sezar için anahtar sayısal olmalı (örn: 3).")
            return ("caesar", int(k))

        elif m == "Vigenère":
            if not k or not k.isalpha():
                raise ValueError("Vigenère için anahtar sadece harflerden oluşmalı (örn: LEMON).")
            return ("vigenere", k)

        elif m == "Substitution":
            return ("substitution", _normalize_sub_key(k))

        elif m == "Playfair":
            if not k or not any(c.isalpha() for c in k):
                raise ValueError("Playfair için anahtar harf içermeli (örn: SECURITY).")
            return ("playfair", k)

        elif m == "Rail Fence":
            if not k.isdigit() or int(k) < 2:
                raise ValueError("Rail Fence için ray sayısı ≥ 2 olmalı (örn: 3).")
            return ("railfence", int(k))

        elif m == "Columnar Transposition":
            if not k or not k.isalpha():
                raise ValueError("Columnar için anahtar sadece harflerden oluşmalı (örn: ZEBRAS).")
            return ("columnar", k)

        elif m == "Polybius":
            return ("polybius", None)

        elif m == "Hill":
            return ("hill", parse_hill_key(k))

        elif m == "Vernam":
            if not k or not k.isalpha():
                raise ValueError("Vernam için anahtar sadece harflerden oluşmalı (örn: SECRETKEY).")
            return ("vernam", k)

        elif m == "Affine":
            a_b = _affine_parse_key_client(k)
            return ("affine", a_b)

        elif m == "Pigpen":
            return ("pigpen", None)

        elif m == "DES (Kütüphane)":
            if not k:
                raise ValueError("DES için anahtar girilmeli (8 karakter veya 16 hex).")
            key_bytes = _des_parse_key_client(k)
            return ("des-lib", key_bytes)

        elif m == "DES (Manuel)":
            if not k:
                raise ValueError("DES için anahtar girilmeli (8 karakter veya 16 hex).")
            key_bytes = _des_parse_key_client(k)
            return ("des-manual", key_bytes)

        elif m == "AES-128 (Kütüphane)":
            key_bytes = _aes_parse_key_client(k)
            return ("aes-lib", key_bytes)

        elif m == "AES-128 (Manuel)":
            key_bytes = _aes_parse_key_client(k)
            if len(key_bytes) != 16:
                raise ValueError("Manuel AES için anahtar 16 byte (128 bit) olmalı.")
            return ("aes-manual", key_bytes)

        elif m == "RSA (AES Anahtar Dağıtımı)":
            n, e = _rsa_parse_public(k)
            return ("rsa-hybrid", (n, e))

        elif m == "RSA (Doğrudan)":
            n, e = _rsa_parse_public(k)
            return ("rsa-direct", (n, e))

        else:
            raise ValueError("Bilinmeyen yöntem")

    def _encrypt(self, plain: str) -> str:
        # --- KDF sadece DES/AES için ---
        use_kdf = bool(self.use_kdf.get())
        iters = int(self.kdf_iter_entry.get().strip() or "200000")
        gui_m = self.method.get()

        if use_kdf and gui_m in ("DES (Kütüphane)", "DES (Manuel)", "AES-128 (Kütüphane)", "AES-128 (Manuel)"):
            password = self.key_entry.value()
            if not password:
                raise ValueError("KDF açıkken anahtar alanına parola gir.")

            salt = make_salt()
            key_len = 8 if gui_m.startswith("DES") else 16
            derived_key = kdf_pbkdf2_sha256(password, salt, length=key_len, iters=iters)

            # Şifrele
            if gui_m == "DES (Kütüphane)":
                cipher = des_encrypt(plain, derived_key)
            elif gui_m == "DES (Manuel)":
                cipher = des_encrypt_manual(plain, derived_key)
            elif gui_m == "AES-128 (Kütüphane)":
                cipher = aes_encrypt(plain, derived_key)
            elif gui_m == "AES-128 (Manuel)":
                cipher = aes_encrypt_manual(plain, derived_key)
            else:
                raise ValueError("KDF: desteklenmeyen yöntem")

            return f"KDF|PBKDF2|{iters}|{b64e(salt)}|{cipher}"

        method, key = self._parse_key()

        if method == "caesar":
            return caesar_encrypt(plain, key)
        if method == "vigenere":
            return vigenere_encrypt(plain, key)
        if method == "substitution":
            return substitution_encrypt(plain, key)
        if method == "playfair":
            return playfair_encrypt(plain, key)
        if method == "railfence":
            return rail_fence_encrypt(plain, key)
        if method == "columnar":
            return columnar_encrypt(plain, key)
        if method == "polybius":
            return polybius_encrypt(plain)
        if method == "hill":
            return hill_encrypt(plain, key)
        if method == "vernam":
            return vernam_encrypt(plain, key)
        if method == "affine":
            return affine_encrypt(plain, key)
        if method == "pigpen":
            return pigpen_encrypt(plain)

        if method == "des-lib":
            return des_encrypt(plain, key)
        if method == "des-manual":
            return des_encrypt_manual(plain, key)
        if method == "aes-lib":
            return aes_encrypt(plain, key)
        if method == "aes-manual":
            return aes_encrypt_manual(plain, key)

        if method == "rsa-hybrid":
            n, e = key
            return rsa_encrypt_hybrid(plain, n, e, log_fn=self.log)

        if method == "rsa-direct":
            n, e = key
            return rsa_encrypt_text(plain, n, e)

        return plain

    def send_to_server(self):
        host = self.host_entry.value()
        port_str = self.port_entry.value()

        if not host or not port_str:
            messagebox.showerror("Eksik bilgi", "Host ve Port boş bırakılamaz.")
            return
        if not port_str.isdigit():
            messagebox.showerror("Hata", "Port sayısal olmalı.")
            return

        port = int(port_str)
        plain = self.msg_text.get("1.0", "end").rstrip("\n")

        if not plain:
            messagebox.showinfo("Bilgi", "Göndermek için bir mesaj yazın.")
            return

        try:
            cipher = self._encrypt(plain)
        except Exception as e:
            messagebox.showerror("Anahtar Hatası", str(e))
            return

        self.log(f"Şifrelenmiş: {cipher}")

        def do_send():
            try:
                with socket.create_connection((host, port), timeout=5) as s:
                    send_message(s, cipher)
                    self.log(f"Gönderildi -> {host}:{port}")
            except Exception as e:
                self.log(f"Gönderme hatası: {e}")

        threading.Thread(target=do_send, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()
