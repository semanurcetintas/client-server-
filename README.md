# Client–Server Mesaj Şifreleme (Python + Tkinter)

Bu proje, **TCP socket** üzerinden çalışan bir **İstemci–Sunucu** uygulamasıdır. İstemci tarafında girilen mesaj/dosya çeşitli kriptografik yöntemlerle **şifrelenir**, sunucu tarafında seçilen yöntemle **deşifre edilir** ve arayüzde gösterilir.

> Amaç: Eğitim amaçlı bir “kriptografi laboratuvarı” gibi, klasik şifreler + blok şifreler + RSA hibrit mantığını tek projede göstermek.

---

## Özellikler

- **GUI (Tkinter)** ile kullanım
  - İstemci: mesaj/dosya seç, yöntem seç, anahtar/parola gir, şifrele ve gönder.
  - Sunucu: gelen şifreli veriyi logla, seçilen yönteme göre çöz, sonucu göster.
- **TCP Socket** haberleşme (uzunluk başlıklı paketleme)
- **KDF (PBKDF2-SHA256)** desteği (DES/AES için parola → anahtar türetme)
- **Dosya şifreleme** (Base64 üzerinden) ve sunucuya gönderim

---

## Desteklenen Şifreleme Yöntemleri

### Klasik / Tarihsel Şifreler
- Sezar (Caesar)
- Vigenère
- Substitution (monoalphabetic)
- Playfair
- Rail Fence
- Columnar Transposition
- Polybius
- Hill (n×n matris anahtar)
- Vernam
- Affine
- Pigpen (token/isimlendirme mantığıyla)

### Blok Şifreler
- DES (Kütüphane) — ECB + Base64
- DES (Manuel) — manuel implementasyon (eğitim amaçlı)
- AES-128 (Kütüphane) — ECB + Base64
- AES-128 (Manuel) — manuel implementasyon (eğitim amaçlı)

### RSA
- RSA (Doğrudan) — metin bloklama ile (padding yok, demo)
- RSA (AES Anahtar Dağıtımı) — **hibrit**: AES anahtarı RSA ile şifrelenir, mesaj AES ile şifrelenir.

---

## Kurulum

### Gereksinimler
- Python 3.10+ (öneri)
- pip

### Kütüphaneler
```bash
pip install pycryptodome pillow
