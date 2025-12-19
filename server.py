import socket
import threading
import struct
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import math
import math as _math  # gcd için
import os
from Crypto.Cipher import DES, AES
import base64
from manual_block_ciphers import des_decrypt_text, aes_decrypt_text
from kdf_utils import kdf_pbkdf2_sha256


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_LEN = 26


def _char_to_num(ch: str) -> int:
    return ord(ch.upper()) - ord('A')

def _num_to_char(n: int, upper_like: str) -> str:
    base = ord('A') if upper_like.isupper() else ord('a')
    return chr(base + (n % 26))

# HILL

def _matrix_vec_mul(mat, vec, mod: int):
    n = len(mat)
    out = [0]*n
    for r in range(n):
        acc = 0
        for c in range(n):
            acc += mat[r][c] * vec[c]
        out[r] = acc % mod
    return out

def _modinv(a: int, m: int) -> int:
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("Ters mod bulunamıyor (gcd(a,26)!=1).")

def _matrix_det_mod(mat, mod: int) -> int:
    n = len(mat)
    if n == 1:
        return mat[0][0] % mod
    if n == 2:
        return (mat[0][0]*mat[1][1] - mat[0][1]*mat[1][0]) % mod
    det = 0
    for c in range(n):
        sub = [row[:c] + row[c+1:] for row in mat[1:]]
        cofactor = ((-1) ** c) * mat[0][c] * _matrix_det_mod(sub, mod)
        det += cofactor
    return det % mod

def _matrix_minor(mat, r, c):
    return [row[:c] + row[c+1:] for i, row in enumerate(mat) if i != r]

def _matrix_cofactor_matrix(mat, mod: int):
    n = len(mat)
    cof = [[0]*n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            minor = _matrix_minor(mat, r, c)
            det_minor = _matrix_det_mod(minor, mod)
            cof[r][c] = ((-1) ** (r+c)) * det_minor % mod
    return cof

def _transpose(mat):
    return [list(row) for row in zip(*mat)]

def _matrix_scalar_mul(mat, scalar, mod: int):
    return [[(val * scalar) % mod for val in row] for row in mat]

def _matrix_mod(mat, mod: int):
    return [[val % mod for val in row] for row in mat]

def _matrix_inv_mod(mat, mod: int):
    n = len(mat)
    if any(len(row) != n for row in mat):
        raise ValueError("Hill anahtarı kare matris olmalı.")

    det = _matrix_det_mod(mat, mod)
    inv_det = _modinv(det, mod)

    if n == 1:
        return [[inv_det % mod]]

    cof = _matrix_cofactor_matrix(mat, mod)
    adj = _transpose(cof)
    inv_mat = _matrix_scalar_mul(adj, inv_det, mod)
    return _matrix_mod(inv_mat, mod)

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

def hill_decrypt(text: str, key_mat):
    n = len(key_mat)
    inv_mat = _matrix_inv_mod(key_mat, 26)

    letters, idx_map = _extract_letters_with_index(text)

    if len(letters) % n != 0:
        pad_needed = n - (len(letters) % n)
        letters += ['X'] * pad_needed

    dec_letters = []
    for i in range(0, len(letters), n):
        block = letters[i:i+n]
        nums = [_char_to_num(ch) for ch in block]
        dec_nums = _matrix_vec_mul(inv_mat, nums, 26)
        dec_block = [_num_to_char(dec_nums[j], block[j]) for j in range(n)]
        dec_letters.extend(dec_block)

    original_letter_count = len(idx_map)
    reinjected = _reinject_letters(text, dec_letters[:original_letter_count], idx_map)

    if len(dec_letters) > original_letter_count:
        reinjected += "".join(dec_letters[original_letter_count:])

    return reinjected


# RSA DOĞRUDAN
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


# VERNAM
def _vernam_clean_key(key: str) -> str:
    if not key or not key.isalpha():
        raise ValueError("Vernam anahtarı sadece harflerden oluşmalı (örn: SECRETKEY).")
    return key

def vernam_decrypt(cipher: str, key: str) -> str:
    key = _vernam_clean_key(key)
    out = []
    ki = 0
    for ch in cipher:
        if ch.isalpha():
            if ki >= len(key):
                raise ValueError("Vernam anahtarı şifreli metni çözmek için yeterince uzun değil.")
            kshift = (ord(key[ki].upper()) - 65) % 26
            if ch.isupper():
                pnum = ((ord(ch) - 65) - kshift) % 26
                out.append(chr(pnum + 65))
            else:
                pnum = ((ord(ch) - 97) - kshift) % 26
                out.append(chr(pnum + 97))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)

# AFFINE
def _affine_parse_key(key_text: str):
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

def affine_decrypt(cipher: str, key_tuple):
    a, b = key_tuple
    a_inv = _modinv(a, 26)
    out = []
    for ch in cipher:
        if ch.isalpha():
            if ch.isupper():
                cval = ord(ch) - 65
                pval = (a_inv * ((cval - b) % 26)) % 26
                out.append(chr(pval + 65))
            else:
                cval = ord(ch) - 97
                pval = (a_inv * ((cval - b) % 26)) % 26
                out.append(chr(pval + 97))
        else:
            out.append(ch)
    return "".join(out)

#PIGPEN
def pigpen_decrypt(cipher_token_stream: str) -> str:
    tokens = cipher_token_stream.split()
    out_chars = []
    for t in tokens:
        base = os.path.basename(t)
        if base.lower().endswith(".jpg"):
            letter = base[:-4]
            if len(letter) == 1 and letter.isalpha():
                out_chars.append(letter.upper())
            else:
                out_chars.append("?")
        else:
            if base == "|SPACE|":
                out_chars.append(" ")
            else:
                out_chars.append("?")
    return "".join(out_chars)


def caesar_decrypt(text: str, shift: int) -> str:
    shift %= 26
    out = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch)-65-shift) % 26 + 65))
        elif "a" <= ch <= "z":
            out.append(chr((ord(ch)-97-shift) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)

def vigenere_decrypt(text: str, key: str) -> str:
    if not key or not key.isalpha():
        raise ValueError("Vigenère anahtarı sadece harflerden oluşmalı (örn: LEMON).")
    shifts = [(ord(c.upper())-65) % 26 for c in key]
    out = []
    j = 0
    for ch in text:
        if ch.isalpha():
            s = shifts[j % len(shifts)]
            if ch.isupper():
                out.append(chr((ord(ch)-65-s) % 26 + 65))
            else:
                out.append(chr((ord(ch)-97-s) % 26 + 97))
            j += 1
        else:
            out.append(ch)
    return "".join(out)

def _normalize_sub_key(key: str) -> str:
    k = "".join([c for c in key.upper() if c.isalpha()])
    if len(k) != 26 or len(set(k)) != 26:
        raise ValueError("Substitution anahtarı 26 HARFTEN oluşan benzersiz bir permütasyon olmalı.")
    return k

def substitution_decrypt(text: str, key: str) -> str:
    k = _normalize_sub_key(key)
    map_up = {k[i]: ALPHABET[i] for i in range(26)}
    map_lo = {k[i].lower(): ALPHABET[i].lower() for i in range(26)}
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

def columnar_decrypt(cipher: str, key: str) -> str:
    order = _col_key_order(key)
    m = len(order)
    n = len(cipher)
    if m == 0:
        return cipher
    rows = math.ceil(n / m)
    rem = n % m
    col_lengths = [(rows if (rem == 0 or i < rem) else (rows - 1)) for i in range(m)]

    cols_data = [""] * m
    idx = 0
    for orig_col in order:
        L = col_lengths[orig_col]
        cols_data[orig_col] = cipher[idx:idx+L]
        idx += L

    out = []
    for r in range(rows):
        for c in range(m):
            if r < len(cols_data[c]):
                out.append(cols_data[c][r])
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

def _pf_extract_cipher_letters(text: str):
    letters = []
    idx_map = []
    for i, ch in enumerate(text):
        if ch.isalpha():
            letters.append("I" if ch.upper()=="J" else ch.upper())
            idx_map.append(i)
    if len(letters) % 2 == 1:
        letters.append("X")
        idx_map.append(None)
    pairs = []
    for i in range(0, len(letters), 2):
        pairs.append((letters[i], letters[i+1]))
    return pairs, idx_map

def playfair_decrypt(text: str, key: str) -> str:
    if not key or not any(c.isalpha() for c in key):
        raise ValueError("Playfair anahtarı harf içermeli (örn: SECURITY).")
    table = _pf_prepare_key(key)
    pos = _pf_pos(table)
    pairs, idx_map = _pf_extract_cipher_letters(text)
    out = list(text)

    def dec_pair(a, b):
        ra, ca = pos[a]; rb, cb = pos[b]
        if ra == rb:
            return (table[ra][(ca-1)%5], table[rb][(cb-1)%5])
        if ca == cb:
            return (table[(ra-1)%5][ca], table[(rb-1)%5][cb])
        return (table[ra][cb], table[rb][ca])

    letter_ptr = 0
    for a, b in pairs:
        da, db = dec_pair(a, b)
        while letter_ptr < len(idx_map) and (idx_map[letter_ptr] is None or not text[idx_map[letter_ptr]].isalpha()):
            letter_ptr += 1
        if letter_ptr < len(idx_map) and idx_map[letter_ptr] is not None:
            i = idx_map[letter_ptr]
            out[i] = da if text[i].isupper() else da.lower()
            letter_ptr += 1
        while letter_ptr < len(idx_map) and (idx_map[letter_ptr] is None or not text[idx_map[letter_ptr]].isalpha()):
            letter_ptr += 1
        if letter_ptr < len(idx_map) and idx_map[letter_ptr] is not None:
            i = idx_map[letter_ptr]
            out[i] = db if text[i].isupper() else db.lower()
            letter_ptr += 1

    return "".join(out)

def rail_fence_decrypt(cipher: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rail Fence için ray sayısı en az 2 olmalı.")
    n = len(cipher)
    pattern = [0]*n
    rail = 0
    step = 1
    for i in range(n):
        pattern[i] = rail
        rail += step
        if rail == 0 or rail == rails-1:
            step *= -1
    counts = [pattern.count(r) for r in range(rails)]
    idx = 0
    rails_str = []
    for c in counts:
        rails_str.append(list(cipher[idx:idx+c]))
        idx += c
    res = []
    rail_ptrs = [0]*rails
    for r in pattern:
        res.append(rails_str[r][rail_ptrs[r]])
        rail_ptrs[r] += 1
    return "".join(res)

#POLYBIUS
_POLYBIUS_TABLE = [
    ['A','B','C','D','E'],
    ['F','G','H','I','K'],
    ['L','M','N','O','P'],
    ['Q','R','S','T','U'],
    ['V','W','X','Y','Z'],
]
_POLY_DEC = {(r+1, c+1): _POLYBIUS_TABLE[r][c] for r in range(5) for c in range(5)}

def polybius_decrypt(text: str) -> str:
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "12345" and i+1 < len(text) and text[i+1] in "12345":
            r = int(text[i]); c = int(text[i+1])
            out.append(_POLY_DEC[(r, c)])
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)

# AES/DES kütüphaneli
def _des_parse_key(key_text: str) -> bytes:
    key_text = key_text.strip()
    if len(key_text) == 8:
        return key_text.encode("utf-8")
    if len(key_text) == 16:
        try:
            return bytes.fromhex(key_text)
        except ValueError:
            pass
    raise ValueError("DES anahtarı 8 karakter (örn: 12345678) veya 16 haneli hex olmalı.")

def _pkcs5_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Boş veri, padding çözülemedi.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Geçersiz padding.")
    return data[:-pad_len]

def des_decrypt(cipher_b64: str, key: bytes) -> str:
    try:
        cipher_bytes = base64.b64decode(cipher_b64)
    except Exception:
        raise ValueError("DES için beklenen formatta (Base64) şifre yok.")
    cipher = DES.new(key, DES.MODE_ECB)
    padded = cipher.decrypt(cipher_bytes)
    plain_bytes = _pkcs5_unpad(padded)
    return plain_bytes.decode("utf-8", errors="replace")

def _aes_parse_key(key_text: str) -> bytes:
    key_text = key_text.strip()
    if len(key_text) in (16, 24, 32):
        return key_text.encode("utf-8")
    if len(key_text) in (32, 48, 64):
        try:
            return bytes.fromhex(key_text)
        except:
            pass
    raise ValueError("AES anahtarı 16/24/32 karakter veya 32/48/64 hex olmalı.")

def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Boş veri, padding çıkarılamıyor.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Geçersiz padding.")
    return data[:-pad_len]

def aes_decrypt(cipher_b64: str, key: bytes) -> str:
    try:
        cipher_bytes = base64.b64decode(cipher_b64)
    except:
        raise ValueError("AES için geçersiz Base64 şifre.")
    cipher = AES.new(key, AES.MODE_ECB)
    padded = cipher.decrypt(cipher_bytes)
    plain_bytes = _pkcs7_unpad(padded)
    return plain_bytes.decode("utf-8", errors="replace")

def des_decrypt_manual(cipher_b64: str, key: bytes) -> str:
    return des_decrypt_text(cipher_b64, key, strict_padding=False)

def aes_decrypt_manual(cipher_b64: str, key: bytes) -> str:
    return aes_decrypt_text(cipher_b64, key)

#RSA (KÜTÜPHANESİZ / MANUEL, ANAHTAR DAĞITIMI)
def _rsa_parse_private(key_text: str):
    if "," not in key_text:
        raise ValueError("RSA (sunucu) anahtarı 'n,d' formatında olmalı.")
    n_str, d_str = key_text.split(",", 1)
    n_str, d_str = n_str.strip(), d_str.strip()
    if not n_str.isdigit() or not d_str.isdigit():
        raise ValueError("RSA n ve d sayısal olmalı.")
    n = int(n_str)
    d = int(d_str)
    return n, d

def rsa_decrypt_hybrid(payload: str, n: int, d: int) -> str:
    try:
        prefix, key_cipher, aes_cipher_b64 = payload.split("|", 3)
    except ValueError:
        raise ValueError("RSA hibrit formatı bekleniyordu: RSA-AES|...")

    if prefix != "RSA-AES":
        raise ValueError("Bilinmeyen RSA hibrit prefix (RSA-AES bekleniyordu).")

    nums = [int(x) for x in key_cipher.split(",") if x.strip()]
    key_bytes = bytes(pow(c, d, n) for c in nums)
    return aes_decrypt(aes_cipher_b64, key_bytes)


def send_message(conn, text: str):
    data = text.encode("utf-8")
    conn.sendall(struct.pack(">I", len(data)) + data)

def recv_message(conn):
    hdr = conn.recv(4)
    if not hdr:
        return None
    (n,) = struct.unpack(">I", hdr)
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data.decode("utf-8")


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
    "RSA (Doğrudan)"
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

class ClientHandler(threading.Thread):
    def __init__(self, conn, addr, key_getter, method_getter, log_fn, push_fn):
        super().__init__(daemon=True)
        self.conn, self.addr = conn, addr
        self.key_getter = key_getter
        self.method_getter = method_getter
        self.log = log_fn
        self.push = push_fn

    def _method_and_key_from_gui_or_kdf(self, kdf_active: bool, kdf_salt: bytes | None, kdf_iters: int | None):
        gui_m = self.method_getter()

        if kdf_active and gui_m in ("DES (Kütüphane)", "DES (Manuel)", "AES-128 (Kütüphane)", "AES-128 (Manuel)"):
            password = self.key_getter()
            if not password:
                raise ValueError("KDF aktif: Sunucu tarafında parola girilmemiş.")

            if gui_m == "DES (Kütüphane)":
                method = "des-lib"
                key_len = 8
            elif gui_m == "DES (Manuel)":
                method = "des-manual"
                key_len = 8
            elif gui_m == "AES-128 (Kütüphane)":
                method = "aes-lib"
                key_len = 16
            else:
                method = "aes-manual"
                key_len = 16

            derived_key = kdf_pbkdf2_sha256(password, kdf_salt, length=key_len, iters=kdf_iters)
            return method, derived_key


        return self._parse_key_method()

    def run(self):
        self.log(f"Bağlandı: {self.addr}")
        try:
            while True:
                msg = recv_message(self.conn)
                if msg is None:
                    self.log(f"Bağlantı kapandı: {self.addr}")
                    break

                self.log(f"Gelen şifreli: {msg}")


                kdf_active = False
                kdf_name = None
                kdf_iters = None
                kdf_salt = None

                if msg.startswith("KDF|"):
                    kdf_active = True
                    try:
                        _, kdf_name, iters_s, salt_b64, msg = msg.split("|", 4)
                        kdf_iters = int(iters_s)
                        kdf_salt = base64.b64decode(salt_b64.encode("ascii"))
                    except Exception:
                        raise ValueError("KDF paketi bozuk (KDF|PBKDF2|iters|salt|cipher)")

                if msg.startswith("FILE|"):
                    try:
                        _, filename, cipher_part = msg.split("|", 2)

                        method, parsed = self._method_and_key_from_gui_or_kdf(
                            kdf_active=kdf_active,
                            kdf_salt=kdf_salt,
                            kdf_iters=kdf_iters
                        )

                        allowed = {"des-lib", "des-manual", "aes-lib", "aes-manual", "rsa-hybrid"}
                        if method not in allowed:
                            raise ValueError("Sunucu: Dosya için bu yöntem kabul edilmiyor (DES/AES/RSA-AES).")

                        if method == "des-lib":
                            b64_plain = des_decrypt(cipher_part, parsed)
                        elif method == "des-manual":
                            b64_plain = des_decrypt_manual(cipher_part, parsed)
                        elif method == "aes-lib":
                            b64_plain = aes_decrypt(cipher_part, parsed)
                        elif method == "aes-manual":
                            b64_plain = aes_decrypt_manual(cipher_part, parsed)
                        elif method == "rsa-hybrid":
                            n, d = parsed
                            b64_plain = rsa_decrypt_hybrid(cipher_part, n, d)
                        else:
                            raise ValueError("Bilinmeyen yöntem")

                        raw = base64.b64decode(b64_plain.encode("ascii"))
                        os.makedirs("received_files", exist_ok=True)
                        out_path = os.path.join("received_files", filename)
                        with open(out_path, "wb") as f:
                            f.write(raw)

                        self.log(f"Dosya çözüldü ve kaydedildi: {out_path}")
                        self.push(msg, f"[DOSYA KAYDEDİLDİ] {out_path}", method)
                    except Exception as e:
                        self.log(f"Dosya alma/çözme hatası: {e}")
                    continue


                try:
                    method, parsed = self._method_and_key_from_gui_or_kdf(
                        kdf_active=kdf_active,
                        kdf_salt=kdf_salt,
                        kdf_iters=kdf_iters
                    )

                    if method == "caesar":
                        plain = caesar_decrypt(msg, parsed)
                    elif method == "vigenere":
                        plain = vigenere_decrypt(msg, parsed)
                    elif method == "substitution":
                        plain = substitution_decrypt(msg, parsed)
                    elif method == "playfair":
                        plain = playfair_decrypt(msg, parsed)
                    elif method == "railfence":
                        plain = rail_fence_decrypt(msg, parsed)
                    elif method == "columnar":
                        plain = columnar_decrypt(msg, parsed)
                    elif method == "polybius":
                        plain = polybius_decrypt(msg)
                    elif method == "hill":
                        plain = hill_decrypt(msg, parsed)
                    elif method == "vernam":
                        plain = vernam_decrypt(msg, parsed)
                    elif method == "affine":
                        plain = affine_decrypt(msg, parsed)
                    elif method == "pigpen":
                        plain = pigpen_decrypt(msg)
                    elif method == "des-lib":
                        plain = des_decrypt(msg, parsed)
                    elif method == "des-manual":
                        plain = des_decrypt_manual(msg, parsed)
                    elif method == "aes-lib":
                        plain = aes_decrypt(msg, parsed)
                    elif method == "aes-manual":
                        plain = aes_decrypt_manual(msg, parsed)
                    elif method == "rsa-hybrid":
                        n, d = parsed
                        plain = rsa_decrypt_hybrid(msg, n, d)
                    elif method == "rsa-direct":
                        n, d = parsed
                        plain = rsa_decrypt_text(msg, n, d)
                    else:
                        plain = msg

                    self.push(msg, plain, method)
                except Exception as e:
                    self.log(f"Anahtar/Yöntem hatası: {e}")
        except Exception as e:
            self.log(f"Hata ({self.addr}): {e}")
        finally:
            try:
                self.conn.close()
            except:
                pass

    def _parse_key_method(self):
        m = self.method_getter()
        k = self.key_getter()

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
            a_b = _affine_parse_key(k)
            return ("affine", a_b)

        elif m == "Pigpen":
            return ("pigpen", None)

        elif m == "DES (Kütüphane)":
            if not k:
                raise ValueError("DES için anahtar girilmeli (8 karakter veya 16 hex).")
            key_bytes = _des_parse_key(k)
            return ("des-lib", key_bytes)

        elif m == "DES (Manuel)":
            if not k:
                raise ValueError("DES için anahtar girilmeli (8 karakter veya 16 hex).")
            key_bytes = _des_parse_key(k)
            return ("des-manual", key_bytes)

        elif m == "AES-128 (Kütüphane)":
            key_bytes = _aes_parse_key(k)
            return ("aes-lib", key_bytes)

        elif m == "AES-128 (Manuel)":
            key_bytes = _aes_parse_key(k)
            if len(key_bytes) != 16:
                raise ValueError("Manuel AES için anahtar 16 byte (128 bit) olmalı.")
            return ("aes-manual", key_bytes)

        elif m == "RSA (AES Anahtar Dağıtımı)":
            n, d = _rsa_parse_private(k)
            return ("rsa-hybrid", (n, d))

        elif m == "RSA (Doğrudan)":
            n, d = _rsa_parse_private(k)
            return ("rsa-direct", (n, d))

        else:
            raise ValueError("Bilinmeyen yöntem")

class TCPServer(threading.Thread):
    def __init__(self, host, port, key_getter, method_getter, log_fn, push_fn):
        super().__init__(daemon=True)
        self.host, self.port = host, port
        self.key_getter, self.method_getter = key_getter, method_getter
        self.log, self.push = log_fn, push_fn
        self._stop = threading.Event()
        self.sock = None

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(8)
            self.log(f"Dinlemede: {self.host}:{self.port}")
            while not self._stop.is_set():
                self.sock.settimeout(1.0)
                try:
                    conn, addr = self.sock.accept()
                except socket.timeout:
                    continue
                ClientHandler(conn, addr, self.key_getter, self.method_getter, self.log, self.push).start()
        except Exception as e:
            self.log(f"Sunucu hatası: {e}")
        finally:
            if self.sock:
                self.sock.close()
            self.log("Sunucu durdu.")

    def stop(self):
        self._stop.set()

class ServerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Sunucu - Mesaj Deşifreleme")

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except:
            pass

        wrap = ttk.Frame(root, padding=12)
        wrap.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        wrap.columnconfigure(1, weight=1)

        r = 0
        ttk.Label(wrap, text="Sunucu - Mesaj Deşifreleme", font=("Segoe UI", 16, "bold")).grid(
            row=r, column=0, columnspan=2, pady=(0,8), sticky="w"
        ); r += 1

        ttk.Label(wrap, text="Host").grid(row=r, column=0, sticky="w")
        self.host_entry = PlaceholderEntry(wrap, placeholder="127.0.0.1")
        self.host_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Port").grid(row=r, column=0, sticky="w")
        self.port_entry = PlaceholderEntry(wrap, placeholder="5000")
        self.port_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Deşifreleme Yöntemi").grid(row=r, column=0, sticky="w")
        self.method = ttk.Combobox(wrap, values=METHODS, state="readonly")
        self.method.current(0)
        self.method.grid(row=r, column=1, sticky="ew", padx=6)
        self.method.bind("<<ComboboxSelected>>", self._on_method_change)
        r += 1

        ttk.Label(wrap, text="Anahtar").grid(row=r, column=0, sticky="w")
        self.key_entry = PlaceholderEntry(
            wrap,
            placeholder=(
                "Sezar: 3 | Vigenère: LEMON | Subst.: 26 harf | "
                "Playfair: SECURITY | Rail: 3 | Columnar: ZEBRAS | "
                "Polybius: (gerekmez) | Hill: '3 3 2 5' | Vernam: SECRETKEY | "
                "Affine: 5,8 | Pigpen: (gerekmez) | DES: 12345678 | "
                "AES: 16/24/32 char | RSA sunucu: n,d | KDF açıksa: parola"
            )
        )
        self.key_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Gelen Şifreli (Ham)").grid(row=r, column=0, sticky="w")
        self.in_text = scrolledtext.ScrolledText(wrap, height=4)
        self.in_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        ttk.Label(wrap, text="Deşifrelenmiş").grid(row=r, column=0, sticky="w")
        self.out_text = scrolledtext.ScrolledText(wrap, height=4)
        self.out_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        btns = ttk.Frame(wrap)
        btns.grid(row=r, column=0, columnspan=2, pady=8, sticky="w")
        self.start_btn = ttk.Button(btns, text="Sunucuyu Başlat", command=self.start_server)
        self.stop_btn  = ttk.Button(btns, text="Sunucuyu Durdur", command=self.stop_server, state="disabled")
        self.clear_btn = ttk.Button(btns, text="Temizle", command=self.clear_all)
        self.start_btn.pack(side="left", padx=4)
        self.stop_btn.pack(side="left", padx=4)
        self.clear_btn.pack(side="left", padx=4)
        r += 1

        ttk.Label(wrap, text="Log").grid(row=r, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(wrap, height=8)
        self.log_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        self.status = ttk.Label(wrap, text="Hazır", relief="sunken", anchor="w")
        self.status.grid(row=r, column=0, columnspan=2, sticky="ew", pady=(6,0))

        wrap.rowconfigure(5, weight=1)
        wrap.rowconfigure(6, weight=1)
        wrap.rowconfigure(8, weight=1)

        self.server = None

    def _on_method_change(self, _):
        m = self.method.get()
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
            "DES (Kütüphane)": "8 karakter / 16 hex | KDF ise: parola",
            "DES (Manuel)": "8 karakter / 16 hex | KDF ise: parola",
            "AES-128 (Kütüphane)": "16/24/32 karakter (veya 32/48/64 hex) | KDF ise: parola",
            "AES-128 (Manuel)": "16 karakter veya 32 hex | KDF ise: parola",
            "RSA (AES Anahtar Dağıtımı)": "n,d (sunucu private)",
            "RSA (Doğrudan)": "n,d (sunucu private)"
        }[m]
        self.key_entry.placeholder = ph
        if not self.key_entry.value():
            self.key_entry.delete(0, "end")
            self.key_entry._has_placeholder=False
            self.key_entry._put_placeholder()

    def log(self, s):
        self.log_text.insert("end", s + "\n")
        self.log_text.see("end")
        self.status.config(text=s)

    def _get_host_port(self):
        host = self.host_entry.value()
        port_str = self.port_entry.value()
        if not host or not port_str:
            messagebox.showerror("Eksik bilgi", "Host ve Port boş bırakılamaz.")
            return None
        if not port_str.isdigit():
            messagebox.showerror("Hata", "Port sayısal olmalı.")
            return None
        return host, int(port_str)

    def start_server(self):
        if self.server:
            messagebox.showinfo("Bilgi", "Sunucu zaten çalışıyor.")
            return
        hp = self._get_host_port()
        if not hp:
            return
        host, port = hp
        self.server = TCPServer(
            host, port,
            key_getter=lambda: self.key_entry.value(),
            method_getter=lambda: self.method.get(),
            log_fn=lambda s: self.root.after(0, self.log, s),
            push_fn=lambda c, p, meth: self.root.after(0, self.push_to_gui, c, p, meth)
        )
        self.server.start()
        self.start_btn["state"] = "disabled"
        self.stop_btn["state"] = "normal"
        self.log(f"Sunucu başlatıldı: {host}:{port}")

    def stop_server(self):
        if self.server:
            self.server.stop()
            self.server = None
            self.start_btn["state"] = "normal"
            self.stop_btn["state"] = "disabled"
            self.log("Sunucu durduruldu.")

    def push_to_gui(self, cipher, plain, method_name):
        self.in_text.insert("end", cipher + "\n")
        self.in_text.see("end")
        self.out_text.insert("end", plain + "\n")
        self.out_text.see("end")

    def clear_all(self):
        self.in_text.delete("1.0", "end")
        self.out_text.delete("1.0", "end")
        self.log_text.delete("1.0", "end")
        self.status.config(text="Temizlendi")

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.stop_server(), root.destroy()))
    root.mainloop()
