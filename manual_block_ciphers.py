import base64

S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INV_S_BOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

RCON = (
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
)

def _clean_b64(s: str) -> str:
    # copy/paste sırasında gelen whitespace ve satır sonlarını temizle
    return "".join((s or "").strip().split())

def _b64decode_strict(cipher_b64: str) -> bytes:
    s = _clean_b64(cipher_b64)
    if not s:
        raise ValueError("Boş Base64 şifre metni.")
    try:
        # validate=True => Base64 değilse patlasın, sessizce çöp üretmesin
        return base64.b64decode(s, validate=True)
    except Exception:
        # bazen URL-safe base64 geliyor; onu da dene
        try:
            return base64.urlsafe_b64decode(s + "===")  # padding tamamla
        except Exception:
            raise ValueError("Geçersiz Base64/URL-safe Base64 şifre metni.")

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def _pkcs7_unpad(data: bytes, block_size: int = 16, *, strict: bool = True) -> bytes:
    if not data:
        raise ValueError("Boş veri, padding çıkarılamıyor.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        if strict:
            raise ValueError("Geçersiz padding (pad_len aralık dışı).")
        return data
    tail = data[-pad_len:]
    if tail != bytes([pad_len]) * pad_len:
        if strict:
            raise ValueError("Geçersiz padding (padding baytları uyuşmuyor).")
        return data
    return data[:-pad_len]

def _pkcs5_pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def _pkcs5_unpad(data: bytes, *, strict: bool = True) -> bytes:
    if not data:
        raise ValueError("Boş veri, padding çözülemedi.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        if strict:
            raise ValueError("Geçersiz padding (PKCS5).")
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        if strict:
            raise ValueError("Geçersiz padding (PKCS5).")
        return data
    return data[:-pad_len]

def _gmul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return res

def _sub_bytes(state):
    for i in range(16):
        state[i] = S_BOX[state[i]]

def _inv_sub_bytes(state):
    for i in range(16):
        state[i] = INV_S_BOX[state[i]]

def _shift_rows(state):
    s = state
    s[1], s[5], s[9], s[13]   = s[5], s[9], s[13], s[1]
    s[2], s[6], s[10], s[14]  = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15]  = s[15], s[3], s[7], s[11]

def _inv_shift_rows(state):
    s = state
    s[1], s[5], s[9], s[13]   = s[13], s[1], s[5], s[9]
    s[2], s[6], s[10], s[14]  = s[10], s[14], s[2], s[6]   # 2 adım sağ = 2 adım sol
    s[3], s[7], s[11], s[15]  = s[7], s[11], s[15], s[3]   # sağ 3 = sol 1

def _mix_columns(state):
    for c in range(4):
        i = 4*c
        a0, a1, a2, a3 = state[i:i+4]
        state[i+0] = _gmul(a0,2) ^ _gmul(a1,3) ^ a2 ^ a3
        state[i+1] = a0 ^ _gmul(a1,2) ^ _gmul(a2,3) ^ a3
        state[i+2] = a0 ^ a1 ^ _gmul(a2,2) ^ _gmul(a3,3)
        state[i+3] = _gmul(a0,3) ^ a1 ^ a2 ^ _gmul(a3,2)

def _inv_mix_columns(state):
    for c in range(4):
        i = 4*c
        a0, a1, a2, a3 = state[i:i+4]
        state[i+0] = _gmul(a0,14) ^ _gmul(a1,11) ^ _gmul(a2,13) ^ _gmul(a3,9)
        state[i+1] = _gmul(a0,9)  ^ _gmul(a1,14) ^ _gmul(a2,11) ^ _gmul(a3,13)
        state[i+2] = _gmul(a0,13) ^ _gmul(a1,9)  ^ _gmul(a2,14) ^ _gmul(a3,11)
        state[i+3] = _gmul(a0,11) ^ _gmul(a1,13) ^ _gmul(a2,9)  ^ _gmul(a3,14)

def _add_round_key(state, round_key):
    for i in range(16):
        state[i] ^= round_key[i]

def _key_expansion_128(key: bytes):
    if len(key) != 16:
        raise ValueError("Bu manuel AES sadece 128 bit (16 byte) anahtar destekliyor.")
    Nk = 4
    Nr = 10
    words = [0]*44
    for i in range(Nk):
        words[i] = int.from_bytes(key[4*i:4*i+4], "big")
    for i in range(Nk, 4*(Nr+1)):
        temp = words[i-1]
        if i % Nk == 0:
            temp = ((temp << 8) & 0xFFFFFFFF) | (temp >> 24)
            b0 = S_BOX[(temp >> 24) & 0xFF]
            b1 = S_BOX[(temp >> 16) & 0xFF]
            b2 = S_BOX[(temp >>  8) & 0xFF]
            b3 = S_BOX[(temp      ) & 0xFF]
            temp = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
            temp ^= (RCON[(i//Nk)-1] << 24)
        words[i] = words[i-Nk] ^ temp
    round_keys = []
    for r in range(Nr+1):
        k = bytearray(16)
        for c in range(4):
            w = words[4*r + c]
            k[4*c+0] = (w >> 24) & 0xFF
            k[4*c+1] = (w >> 16) & 0xFF
            k[4*c+2] = (w >>  8) & 0xFF
            k[4*c+3] = (w      ) & 0xFF
        round_keys.append(bytes(k))
    return round_keys

def _aes_encrypt_block(block16: bytes, round_keys):
    if len(block16) != 16:
        raise ValueError("AES blok boyu 16 byte olmalı.")
    state = bytearray(block16)
    _add_round_key(state, round_keys[0])
    for r in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    return bytes(state)

def _aes_decrypt_block(block16: bytes, round_keys):
    if len(block16) != 16:
        raise ValueError("AES blok boyu 16 byte olmalı.")
    state = bytearray(block16)
    _add_round_key(state, round_keys[10])
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    for r in range(9, 0, -1):
        _add_round_key(state, round_keys[r])
        _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return bytes(state)

def aes_encrypt_text(plain: str, key: bytes) -> str:
    data = plain.encode("utf-8")
    data = _pkcs7_pad(data, 16)
    rks = _key_expansion_128(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out.extend(_aes_encrypt_block(data[i:i+16], rks))
    return base64.b64encode(bytes(out)).decode("ascii")

def aes_decrypt_text(cipher_b64: str, key: bytes, *, strict_padding: bool = True) -> str:
    data = _b64decode_strict(cipher_b64)

    if len(data) == 0 or (len(data) % 16) != 0:
        raise ValueError("AES şifreli veri uzunluğu 16'nın katı olmalı (Base64 bozuk/kırpılmış olabilir).")

    rks = _key_expansion_128(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out.extend(_aes_decrypt_block(data[i:i+16], rks))

    out_bytes = _pkcs7_unpad(bytes(out), 16, strict=strict_padding)
    return out_bytes.decode("utf-8", errors="replace")

def _feistel_f(right4: bytes, subkey4: bytes) -> bytes:
    out = bytearray(4)
    for i in range(4):
        x = right4[i] ^ subkey4[i]
        out[i] = S_BOX[x]
    return bytes(out)

def _des_key_schedule(key8: bytes, rounds: int = 16):
    if len(key8) != 8:
        raise ValueError("Bu manuel DES benzeri şifre 8 byte key bekler.")
    k = bytearray(key8)
    subkeys = []
    for _ in range(rounds):
        k = k[1:] + k[:1]
        subkeys.append(bytes(k[:4]))
    return subkeys

def _des_encrypt_block(block8: bytes, key8: bytes) -> bytes:
    if len(block8) != 8:
        raise ValueError("DES-blok 8 byte olmalı.")
    L = bytearray(block8[:4])
    R = bytearray(block8[4:])
    subkeys = _des_key_schedule(key8, 16)
    for sk in subkeys:
        f_out = _feistel_f(bytes(R), sk)
        newL = bytes(R)
        newR = bytes(a ^ b for a, b in zip(L, f_out))
        L, R = bytearray(newL), bytearray(newR)
    return bytes(R + L)

def _des_decrypt_block(block8: bytes, key8: bytes) -> bytes:
    if len(block8) != 8:
        raise ValueError("DES-blok 8 byte olmalı.")
    L = bytearray(block8[:4])
    R = bytearray(block8[4:])
    subkeys = _des_key_schedule(key8, 16)
    for sk in reversed(subkeys):
        f_out = _feistel_f(bytes(L), sk)
        newR = bytes(L)
        newL = bytes(a ^ b for a, b in zip(R, f_out))
        L, R = bytearray(newL), bytearray(newR)
    return bytes(R + L)

def des_encrypt_text(plain: str, key8: bytes) -> str:
    data = plain.encode("utf-8")
    data = _pkcs5_pad(data, 8)
    out = bytearray()
    for i in range(0, len(data), 8):
        out.extend(_des_encrypt_block(data[i:i+8], key8))
    return base64.b64encode(bytes(out)).decode("ascii")

def des_decrypt_text(cipher_b64: str, key8: bytes, *, strict_padding: bool = True) -> str:
    data = _b64decode_strict(cipher_b64)

    if len(data) == 0 or (len(data) % 8) != 0:
        raise ValueError("DES şifreli veri uzunluğu 8'in katı olmalı (Base64 bozuk/kırpılmış olabilir).")

    out = bytearray()
    for i in range(0, len(data), 8):
        out.extend(_des_decrypt_block(data[i:i+8], key8))

    out_bytes = _pkcs5_unpad(bytes(out), strict=strict_padding)
    return out_bytes.decode("utf-8", errors="replace")
