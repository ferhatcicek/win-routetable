# Windows Route Table Monitor

Windows 10 / 11 üzerinde `Get-NetRoute` yönlendirme tablosunu (routing table) gerçek zamanlı, arama yapılabilir ve filtreli modern bir web arayüzünde (ve alternatif masaüstü arayüzünde) görselleştiren Python uygulaması.

---

## 🚀 Öne Çıkan Özellikler

- **IPv4 ve IPv6 Desteği:** Tek tıkla protokoller arası geçiş.
- **Canlı Tablo ve Dondurulmuş (Sticky) Başlık:** Dikey ve yatay kaydırmada başlıklar sabit kalır.
- **Hızlı Arama & Filtreleme:** Hedef prefix, gateway/nexthop, arayüz adı, protokol veya metrik bazında anlık arama.
- **Otomatik & Manuel Yenileme:** Ayarlanabilir aralıklarla (2s, 5s, 10s, 30s, 60s) otomatik arka plan yenilemesi.
- **Reverse DNS (PTR) Çözümleme:** Çok iş parçacıklı (multithreaded) paralel DNS sorgulama ve bellek içi önbellek (cache) ile IP adreslerinin alan adlarını hızlıca çözümleme.
- **PowerShell Enum Açıklamaları:** Windows'un sayısal döndürdüğü yönlendirme protokollerini okunabilir metne dönüştürür (örn. `2 (NetMgmt)`, `3 (Icmp)`, `8 (Rip)`, `12 (Ospf)`, `13 (Bgp)`).
- **Format Düzeltmeleri:** `ValidLifetime` ve `PreferredLifetime` TimeSpan nesneleri düzgün biçimlendirilmiş metin olarak sunulur.
- **Düşük Kaynak Tüketimi:** Hash tabanlı durum kontrolü ile gereksiz DOM güncellemelerini engeller.
- **Alternatif Masaüstü GUI:** İstenirse Tkinter tabanlı masaüstü uygulaması (`windows_route_gui.py`) ile de çalıştırılabilir.

---

## 📂 Proje Yapısı

```text
├── app.py                  # Flask tabanlı web sunucusu ve tek sayfa web arayüzü
├── windows_route_gui.py    # Alternatif Tkinter masaüstü arayüzü
├── install.bat             # Otomatik sanal ortam kurulum scripti (.venv)
├── run.bat                 # Web uygulamasını başlatan script
├── requirements.txt        # Gerekli Python kütüphaneleri (Flask)
├── .gitignore              # Git tarafından yoksayılacak dosyalar
├── LICENSE                 # MIT Lisansı
└── README.md               # Dokümantasyon
```

---

## 🛠️ Gereksinimler

- **İşletim Sistemi:** Windows 10 veya Windows 11
- **PowerShell:** 5.1 veya üzeri (Windows ile yerleşik gelir)
- **Python:** 3.8 veya üzeri

---

## ⚡ Hızlı Başlangıç

### Yöntem 1: Hazır Betikler ile (Önerilen)

1. Kurulumu yapın (sanal ortam oluşturur ve bağımlılıkları yükler):
   ```cmd
   install.bat
   ```

2. Uygulamayı başlatın:
   ```cmd
   # Standart port (5000) ile çalıştırmak için:
   run.bat

   # Farklı bir port (örn: 8080) ile çalıştırmak için:
   run.bat 8080
   # veya
   run.bat --port 8080
   ```
   *Tarayıcınız otomatik olarak belirtilen portta (varsayılan: `http://127.0.0.1:5000`) açılacaktır.*

---

### Yöntem 2: Manuel Kurulum

```powershell
# 1. Sanal ortamı oluşturun ve aktifleştirin
python -m venv .venv
.venv\Scripts\activate

# 2. Bağımlılıkları yükleyin
pip install -r requirements.txt

# 3. Web uygulamasını çalıştırın (varsayılan 5000 portu)
python app.py

# Farklı bir port ile çalıştırmak için:
python app.py 8080
# veya
python app.py -p 8080
# veya
python app.py --port 8080
```

Tarayıcınızda açın:
```text
http://127.0.0.1:5000 (veya belirlediğiniz port)
```

---

### 🖥️ Alternatif Masaüstü GUI Kullanımı

Web arayüzü yerine bağımsız masaüstü penceresi kullanmak isterseniz:

```powershell
python windows_route_gui.py
```

---

## 📄 Lisans

Bu proje [MIT](LICENSE) lisansı ile lisanslanmıştır.
