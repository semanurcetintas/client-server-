# client.py
import socket
import struct
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_LEN = 26

def send_message(sock, text: str):
    data = text.encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


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


def _pf_prepare_key(key: str):

    s = []
    seen = set()
    for c in key.upper():
        if c.isalpha():
            c = "I" if c == "J" else c
            if c not in seen:
                seen.add(c)
                s.append(c)
    for c in ALPHABET:
        cc = "I" if c == "J" else c
        if cc not in seen:
            seen.add(cc)
            s.append(cc)

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
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            return (table[ra][(ca+1)%5], table[rb][(cb+1)%5])
        if ca == cb:
            return (table[(ra+1)%5][ca], table[(rb+1)%5][cb])
        return (table[ra][cb], table[rb][ca])

    letter_idx = 0
    for a, b in digraphs:
        ea, eb = enc_pair(a, b)
        # place ea
        while letter_idx < len(idx_map) and not text[idx_map[letter_idx]].isalpha():
            letter_idx += 1
        if letter_idx < len(idx_map):
            i = idx_map[letter_idx]
            out[i] = ea if text[i].isupper() else ea.lower()
            letter_idx += 1
        # place eb
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


METHODS = [
    "Sezar (Caesar)",
    "Vigenère",
    "Substitution",
    "Playfair",
    "Rail Fence"
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
            self.delete(0, "end"); self.configure(foreground=self.default_fg); self._has_placeholder = False

    def _focus_out(self, _):
        self._put_placeholder()

    def value(self):
        return "" if self._has_placeholder else self.get().strip()

class ClientGUI:
    def __init__(self, root):
        root.title("İstemci - Mesaj Şifreleme")
        wrap = ttk.Frame(root, padding=12)
        wrap.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        wrap.columnconfigure(1, weight=1)

        r = 0
        ttk.Label(wrap, text="İstemci - Mesaj Şifreleme", font=("Segoe UI", 16, "bold")).grid(row=r, column=0, columnspan=2, pady=(0,8), sticky="w"); r += 1

        ttk.Label(wrap, text="Sunucu Host").grid(row=r, column=0, sticky="w")
        self.host_entry = PlaceholderEntry(wrap, placeholder="localhost")
        self.host_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Sunucu Port").grid(row=r, column=0, sticky="w")
        self.port_entry = PlaceholderEntry(wrap, placeholder="3000")
        self.port_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Yöntem").grid(row=r, column=0, sticky="w")
        self.method = ttk.Combobox(wrap, values=METHODS, state="readonly")
        self.method.current(0)
        self.method.grid(row=r, column=1, sticky="ew", padx=6)
        self.method.bind("<<ComboboxSelected>>", self._on_method_change)
        r += 1

        ttk.Label(wrap, text="Anahtar").grid(row=r, column=0, sticky="w")
        self.key_entry = PlaceholderEntry(wrap, placeholder="Sezar: 3 | Vigenère: LEMON | Subst.: 26 harf | Playfair: SECURITY | Rail: 3")
        self.key_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Mesaj").grid(row=r, column=0, sticky="w")
        self.msg_text = scrolledtext.ScrolledText(wrap, height=6)
        self.msg_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        btns = ttk.Frame(wrap); btns.grid(row=r, column=0, columnspan=2, pady=8, sticky="w")
        ttk.Button(btns, text="Şifrele ve Gönder", command=self.send_to_server).pack(side="left", padx=4)
        ttk.Button(btns, text="Temizle", command=lambda: self.msg_text.delete("1.0", "end")).pack(side="left", padx=4); r += 1

        ttk.Label(wrap, text="İstemci Log").grid(row=r, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(wrap, height=8)
        self.log_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        wrap.rowconfigure(6, weight=1)

    def _on_method_change(self, _):
        m = self.method.get()
        ph = {
            "Sezar (Caesar)": "3",
            "Vigenère": "LEMON",
            "Substitution": "QWERTYUIOPASDFGHJKLZXCVBNM",
            "Playfair": "SECURITY",
            "Rail Fence": "3"
        }[m]
        self.key_entry.placeholder = ph
        if not self.key_entry.value():
            self.key_entry.delete(0, "end"); self.key_entry._has_placeholder=False; self.key_entry._put_placeholder()

    def log(self, s):
        self.log_text.insert("end", s + "\n"); self.log_text.see("end")

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
        else:  # Rail Fence
            if not k.isdigit() or int(k) < 2:
                raise ValueError("Rail Fence için ray sayısı ≥ 2 olmalı (örn: 3).")
            return ("railfence", int(k))

    def _encrypt(self, plain: str):
        method, key = self._parse_key()
        if method == "caesar":
            return caesar_encrypt(plain, key)
        if method == "vigenere":
            return vigenere_encrypt(plain, key)
        if method == "substitution":
            return substitution_encrypt(plain, key)
        if method == "playfair":
            return playfair_encrypt(plain, key)
        return rail_fence_encrypt(plain, key)

    def send_to_server(self):
        host = self.host_entry.value()
        port_str = self.port_entry.value()
        if not host or not port_str:
            messagebox.showerror("Eksik bilgi", "Host ve Port boş bırakılamaz."); return
        if not port_str.isdigit():
            messagebox.showerror("Hata", "Port sayısal olmalı."); return
        port = int(port_str)

        plain = self.msg_text.get("1.0", "end").rstrip("\n")
        if not plain:
            messagebox.showinfo("Bilgi", "Göndermek için bir mesaj yazın."); return

        try:
            cipher = self._encrypt(plain)
        except Exception as e:
            messagebox.showerror("Anahtar Hatası", str(e)); return

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
