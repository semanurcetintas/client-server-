# client.py
import socket
import struct
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

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
        # *** DÜZELTME ***
        return "" if self._has_placeholder else self.get().strip()

def send_message(sock, text: str):
    data = text.encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)

def caesar_encrypt(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch)-65+shift) % 26 + 65))
        elif "a" <= ch <= "z":
            out.append(chr((ord(ch)-97+shift) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)

class ClientGUI:
    def __init__(self, root):
        root.title("İstemci - Mesaj Şifreleme (Caesar)")
        wrap = ttk.Frame(root, padding=12)
        wrap.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        wrap.columnconfigure(1, weight=1)

        r = 0
        ttk.Label(wrap, text="İstemci - Mesaj Şifreleme", font=("Segoe UI", 16, "bold")).grid(row=r, column=0, columnspan=2, pady=(0,8), sticky="w"); r += 1

        ttk.Label(wrap, text="Sunucu Host (örn: localhost)").grid(row=r, column=0, sticky="w")
        self.host_entry = PlaceholderEntry(wrap, placeholder="localhost")
        self.host_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Sunucu Port (örn: 3000)").grid(row=r, column=0, sticky="w")
        self.port_entry = PlaceholderEntry(wrap, placeholder="3000")
        self.port_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Şifreleme Yöntemi").grid(row=r, column=0, sticky="w")
        self.method = ttk.Combobox(wrap, values=["Caesar Cipher (Kaydırma)"], state="readonly")
        self.method.current(0)
        self.method.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Anahtar (örn: 3)").grid(row=r, column=0, sticky="w")
        self.key_entry = PlaceholderEntry(wrap, placeholder="3")
        self.key_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Gönderilecek Mesaj").grid(row=r, column=0, sticky="w")
        self.msg_text = scrolledtext.ScrolledText(wrap, height=6)
        self.msg_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        btns = ttk.Frame(wrap); btns.grid(row=r, column=0, columnspan=2, pady=8, sticky="w")
        ttk.Button(btns, text="Şifrele ve Gönder", command=self.send_to_server).pack(side="left", padx=4)
        ttk.Button(btns, text="Temizle", command=lambda: self.msg_text.delete("1.0", "end")).pack(side="left", padx=4); r += 1

        ttk.Label(wrap, text="İstemci Log").grid(row=r, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(wrap, height=8)
        self.log_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        wrap.rowconfigure(6, weight=1)

    def log(self, s):
        self.log_text.insert("end", s + "\n")
        self.log_text.see("end")

    def send_to_server(self):
        host = self.host_entry.value()
        port_str = self.port_entry.value()
        key_str  = self.key_entry.value()

        if not host or not port_str or not key_str:
            messagebox.showerror("Eksik bilgi", "Host, Port ve Anahtar boş bırakılamaz.")
            return
        if not port_str.isdigit() or not key_str.isdigit():
            messagebox.showerror("Hata", "Port ve Anahtar sayısal olmalı.")
            return
        port, shift = int(port_str), int(key_str)

        plain = self.msg_text.get("1.0", "end").rstrip("\n")
        if not plain:
            messagebox.showinfo("Bilgi", "Göndermek için bir mesaj yazın.")
            return

        cipher = caesar_encrypt(plain, shift)
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
