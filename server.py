# server.py
import socket
import threading
import struct
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ---------- Placeholder'lı Entry ----------
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
        # *** DÜZELTME: Artık sadece gerçekten placeholder modundaysa boş sayar. ***
        return "" if self._has_placeholder else self.get().strip()

# ---------- Length-prefixed protokol ----------
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

# ---------- Caesar ----------
def caesar_decrypt(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch)-65-shift) % 26 + 65))
        elif "a" <= ch <= "z":
            out.append(chr((ord(ch)-97-shift) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)

# ---------- Client handler thread ----------
class ClientHandler(threading.Thread):
    def __init__(self, conn, addr, key_getter, log_fn, push_fn):
        super().__init__(daemon=True)
        self.conn, self.addr = conn, addr
        self.key_getter = key_getter
        self.log = log_fn
        self.push = push_fn

    def run(self):
        self.log(f"Bağlandı: {self.addr}")
        try:
            while True:
                msg = recv_message(self.conn)
                if msg is None:
                    self.log(f"Bağlantı kapandı: {self.addr}")
                    break
                self.log(f"Gelen şifreli: {msg}")
                try:
                    shift = int(self.key_getter())
                except Exception:
                    self.log("Anahtar geçersiz! (sayısal değil)")
                    continue
                plain = caesar_decrypt(msg, shift)
                self.push(msg, plain)
        except Exception as e:
            self.log(f"Hata ({self.addr}): {e}")
        finally:
            try:
                self.conn.close()
            except:
                pass

# ---------- Accept loop ----------
class TCPServer(threading.Thread):
    def __init__(self, host, port, key_getter, log_fn, push_fn):
        super().__init__(daemon=True)
        self.host, self.port = host, port
        self.key_getter, self.log, self.push = key_getter, log_fn, push_fn
        self._stop = threading.Event()
        self.sock = None

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(8)  # çoklu istemci
            self.log(f"Dinlemede: {self.host}:{self.port}")
            while not self._stop.is_set():
                self.sock.settimeout(1.0)
                try:
                    conn, addr = self.sock.accept()
                except socket.timeout:
                    continue
                ClientHandler(conn, addr, self.key_getter, self.log, self.push).start()
        except Exception as e:
            self.log(f"Sunucu hatası: {e}")
        finally:
            if self.sock:
                self.sock.close()
            self.log("Sunucu durdu.")

    def stop(self):
        self._stop.set()

# ---------- GUI ----------
class ServerGUI:
    def __init__(self, root):
        self.root = root  # *** DÜZELTME: after() için gerekli ***
        root.title("Sunucu - Mesaj Deşifreleme (Caesar)")
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
        ttk.Label(wrap, text="Sunucu - Mesaj Deşifreleme", font=("Segoe UI", 16, "bold")).grid(row=r, column=0, columnspan=2, pady=(0,8), sticky="w")
        r += 1

        ttk.Label(wrap, text="Host (örn: localhost)").grid(row=r, column=0, sticky="w")
        self.host_entry = PlaceholderEntry(wrap, placeholder="localhost")
        self.host_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Port (örn: 3000)").grid(row=r, column=0, sticky="w")
        self.port_entry = PlaceholderEntry(wrap, placeholder="3000")
        self.port_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Deşifreleme Yöntemi").grid(row=r, column=0, sticky="w")
        self.method = ttk.Combobox(wrap, values=["Caesar Cipher (Kaydırma)"], state="readonly")
        self.method.current(0)
        self.method.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Anahtar (örn: 3)").grid(row=r, column=0, sticky="w")
        self.key_entry = PlaceholderEntry(wrap, placeholder="3")
        self.key_entry.grid(row=r, column=1, sticky="ew", padx=6); r += 1

        ttk.Label(wrap, text="Gelen Şifreli").grid(row=r, column=0, sticky="w")
        self.in_text = scrolledtext.ScrolledText(wrap, height=6)
        self.in_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        ttk.Label(wrap, text="Deşifrelenmiş").grid(row=r, column=0, sticky="w")
        self.out_text = scrolledtext.ScrolledText(wrap, height=6)
        self.out_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        btns = ttk.Frame(wrap)
        btns.grid(row=r, column=0, columnspan=2, pady=8, sticky="w")
        self.start_btn = ttk.Button(btns, text="Sunucuyu Başlat", command=self.start_server)
        self.stop_btn  = ttk.Button(btns, text="Sunucuyu Durdur", command=self.stop_server, state="disabled")
        self.clear_btn = ttk.Button(btns, text="Temizle", command=self.clear_all)
        self.start_btn.pack(side="left", padx=4)
        self.stop_btn.pack(side="left", padx=4)
        self.clear_btn.pack(side="left", padx=4); r += 1

        ttk.Label(wrap, text="Log").grid(row=r, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(wrap, height=8)
        self.log_text.grid(row=r, column=1, sticky="nsew", padx=6); r += 1

        self.status = ttk.Label(wrap, text="Hazır", relief="sunken", anchor="w")
        self.status.grid(row=r, column=0, columnspan=2, sticky="ew", pady=(6,0))

        wrap.rowconfigure(5, weight=1)
        wrap.rowconfigure(7, weight=1)

        self.server = None

    def log(self, s):
        self.log_text.insert("end", s + "\n"); self.log_text.see("end")
        self.status.config(text=s)

    def _get_host_port_key(self):
        host = self.host_entry.value()
        port_str = self.port_entry.value()
        key_str  = self.key_entry.value()

        if not host or not port_str or not key_str:
            messagebox.showerror("Eksik bilgi", "Host, Port ve Anahtar boş bırakılamaz.")
            return None
        if not port_str.isdigit():
            messagebox.showerror("Hata", "Port sayısal olmalı.")
            return None
        if not key_str.isdigit():
            messagebox.showerror("Hata", "Anahtar sayısal olmalı.")
            return None
        return host, int(port_str), int(key_str)

    def start_server(self):
        if self.server:
            messagebox.showinfo("Bilgi", "Sunucu zaten çalışıyor.")
            return
        hpk = self._get_host_port_key()
        if not hpk:
            return
        host, port, _ = hpk
        self.server = TCPServer(
            host, port,
            key_getter=lambda: self.key_entry.value(),  # *** varsayılan yok ***
            log_fn=lambda s: self.root.after(0, self.log, s),
            push_fn=lambda c, p: self.root.after(0, self.push_to_gui, c, p)
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

    def push_to_gui(self, cipher, plain):
        self.in_text.insert("end", cipher + "\n"); self.in_text.see("end")
        self.out_text.insert("end", plain + "\n"); self.out_text.see("end")

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
