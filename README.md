# ReconScope

**Comprehensive Reconnaissance and Security Scanning Tool**

ReconScope, domain ve IP adreslerinden başlayarak kapsamlı güvenlik taraması yapan profesyonel bir keşif aracıdır. Port taraması, SSL sertifika analizi, DNS kayıt sorgulama, subdomain keşfi ve canlı servis testi gibi gelişmiş özellikler sunar.

## 📋 Proje Bilgileri

- **Proje Adı**: ReconScope
- **Versiyon**: 1.0.0
- **Geliştirici**: bsekercioglu
- **Repository**: https://github.com/bsekercioglu/reconscope
- **Lisans**: Açık kaynak (Open Source)

## 🚀 Özellikler

### Temel Özellikler

- **Domain/IP Çözümleme**: Domain'den IP adreslerini çözümler
- **Port Taraması**: 1-10000 arası portları tarayabilir (varsayılan)
- **SSL/TLS Analizi**: SSL sertifikalarından detaylı bilgi toplar
  - Sertifika süresi (başlangıç/bitiş tarihleri)
  - Issuer ve Subject bilgileri
  - SAN (Subject Alternative Names) listesi
  - Protokol ve cipher bilgileri
  - Sertifika süresi kalan gün sayısı
- **DNS Kayıt Sorgulama**: A, AAAA, NS, MX, TXT, SPF, CNAME, PTR kayıtları
- **Banner Grabbing**: Açık portlardan servis banner bilgileri
- **Reverse DNS**: IP adresinden domain bulma

### Gelişmiş Özellikler

- **IP'den Domain Keşfi**: Bir IP adresinde yayın yapan tüm domainleri bulur
  - Reverse DNS (PTR kayıtları)
  - SSL sertifikalarından domain çıkarma (CN ve SAN)
  - HTTP Host header analizi
  - Certificate Transparency Logs (crt.sh)
  - İteratif SNI (Server Name Indication) denemeleri
- **Subdomain Keşfi**: Subdomain enumeration (subfinder + amass alternatifi)
  - Certificate Transparency Logs (crt.sh)
  - DNS Zone Transfer denemeleri
  - DNS Brute Force (wordlist ile)
  - SSL sertifikalarından subdomain çıkarma
- **Canlı Subdomain Testi**: Bulunan subdomainlerin canlı olup olmadığını test eder (httpx alternatifi)
  - HTTP/HTTPS yanıt kontrolü
  - Port taraması
  - Status code, Server header, Title bilgisi

## 📋 Gereksinimler

- Python 3.7+
- İnternet bağlantısı

## 🔧 Kurulum

1. Projeyi klonlayın:
```bash
git clone https://github.com/bsekercioglu/reconscope.git
cd reconscope
```

2. Gerekli kütüphaneleri yükleyin:
```bash
pip install -r requirements.txt
```

### Gerekli Kütüphaneler

- `cryptography` - SSL sertifika analizi için
- `dnspython>=2.0.0` - DNS sorguları için

## 📖 Kullanım

### Temel Kullanım

```bash
# Domain taraması (varsayılan: 1-10000 port)
python reconscope.py example.com

# IP adresi taraması
python reconscope.py 192.168.1.1

# Belirli portları tara
python reconscope.py example.com --ports 80 443 8080

# SSL kontrolü olmadan tarama
python reconscope.py example.com --no-ssl
```

### Port Taraması

```bash
# İlk 10000 portu tara (varsayılan)
python reconscope.py example.com

# Belirli portları tara
python reconscope.py example.com --ports 22 80 443 3306 5432

# Timeout süresini ayarla (saniye)
python reconscope.py example.com --timeout 5.0

# Thread sayısını artır (daha hızlı tarama)
python reconscope.py example.com --workers 100
```

### IP'den Domain Keşfi

```bash
# IP adresindeki tüm domainleri bul ve tara
python reconscope.py 31.145.154.82

# Reverse DNS ile domain bulma
python reconscope.py 192.168.1.1 --reverse-dns
```

### Subdomain Keşfi

```bash
# Passive subdomain keşfi (crt.sh, SSL sertifikaları)
python reconscope.py example.com --subdomains

# Passive + Active (DNS brute force dahil)
python reconscope.py example.com --subdomains --active

# Wordlist ile aktif tarama
python reconscope.py example.com --subdomains --active --wordlist wordlist.txt

# Subdomain listesini dosyaya kaydet
python reconscope.py example.com --subdomains --subdomain-output subdomains.txt
```

### Canlı Subdomain Testi

```bash
# Subdomain keşfi + canlı test
python reconscope.py example.com --subdomains --check-live

# Tam işlem: Keşif + Canlı test + Dosyaya kaydet
python reconscope.py example.com --subdomains --check-live \
  --subdomain-output sub.txt \
  --live-output live.txt
```

### Rapor Çıktısı

```bash
# JSON formatında rapor
python reconscope.py example.com --format json --output rapor.json

# Text formatında rapor (varsayılan)
python reconscope.py example.com --format text --output rapor.txt
```

## 📝 Komut Satırı Argümanları

### Temel Argümanlar

| Argüman | Kısayol | Açıklama |
|---------|---------|----------|
| `target` | - | Taranacak domain adı veya IP adresi (zorunlu) |
| `--ports` | `-p` | Taranacak port listesi (varsayılan: 1-10000) |
| `--timeout` | `-t` | Port bağlantı timeout süresi (saniye, varsayılan: 3.0) |
| `--format` | `-f` | Rapor formatı: `json` veya `text` (varsayılan: text) |
| `--output` | `-o` | Rapor çıktı dosyası (varsayılan: konsol) |
| `--no-ssl` | - | SSL bilgilerini kontrol etme |
| `--workers` | - | Eşzamanlı port tarama thread sayısı (varsayılan: 50) |
| `--reverse-dns` | `-r` | IP adresi verildiğinde reverse DNS ile domainleri bul |

### Subdomain Keşfi Argümanları

| Argüman | Kısayol | Açıklama |
|---------|---------|----------|
| `--subdomains` | `-s` | Subdomain keşfi yap |
| `--passive` | - | Passive enumeration (varsayılan: True) |
| `--active` | - | Active enumeration (DNS brute force dahil) |
| `--wordlist` | - | Subdomain wordlist dosyası |
| `--check-live` | `-l` | Bulunan subdomainlerin canlı olup olmadığını test et |
| `--subdomain-output` | - | Subdomain listesi çıktı dosyası |
| `--live-output` | - | Canlı subdomain listesi çıktı dosyası |

## 📊 Çıktı Formatı

### Text Formatı

```
============================================================
DOMAIN PORT SSL TARAMA RAPORU
============================================================

Domain: example.com
Tarih: 2024-01-15T10:30:00
IP Adresleri: 93.184.216.34

============================================================
DNS KAYITLARI
------------------------------------------------------------

A Kayıtları (IPv4):
  • 93.184.216.34

NS Kayıtları (Name Server):
  • ns1.example.com
  • ns2.example.com

MX Kayıtları (Mail Exchange):
  • mail.example.com (Öncelik: 10)

============================================================
PORT TARAMA SONUÇLARI
------------------------------------------------------------

IP: 93.184.216.34
  Port 80 (HTTP): Açık
    Banner: Apache/2.4.41
  Port 443 (HTTPS): Açık
    Banner: Apache/2.4.41
    SSL Sertifikası:
      Common Name: example.com
      Issuer: Let's Encrypt
      Geçerlilik: 2024-01-01 - 2024-04-01
      Kalan Gün: 75
```

### JSON Formatı

```json
{
  "domain": "example.com",
  "timestamp": "2024-01-15T10:30:00",
  "ip_addresses": ["93.184.216.34"],
  "dns_records": {
    "A": ["93.184.216.34"],
    "NS": ["ns1.example.com", "ns2.example.com"]
  },
  "scan_results": [
    {
      "ip": "93.184.216.34",
      "ports": [
        {
          "port": 80,
          "service": "HTTP",
          "status": "Açık",
          "banner": "Apache/2.4.41"
        },
        {
          "port": 443,
          "service": "HTTPS",
          "status": "Açık",
          "ssl_info": {
            "commonName": "example.com",
            "issuer": "Let's Encrypt",
            "notBefore": "2024-01-01T00:00:00Z",
            "notAfter": "2024-04-01T00:00:00Z",
            "expiresInDays": 75
          }
        }
      ]
    }
  ]
}
```

## 🔍 Özellik Detayları

### Port Taraması

- **Varsayılan Aralık**: 1-10000 port
- **Paralel Tarama**: ThreadPoolExecutor ile eşzamanlı tarama
- **İlerleme Göstergesi**: 100+ port taramasında ilerleme yüzdesi
- **Banner Grabbing**: Açık portlardan servis bilgileri

### SSL/TLS Analizi

- **Sertifika Bilgileri**:
  - Common Name (CN)
  - Organization, Country, OU bilgileri
  - Issuer detayları
  - Geçerlilik tarihleri
  - Kalan gün sayısı
- **SAN (Subject Alternative Names)**: Sertifikadaki tüm domainler
- **Protokol ve Cipher**: Kullanılan TLS/SSL versiyonu ve cipher suite

### IP'den Domain Keşfi

1. **Reverse DNS (PTR)**: IP adresinden domain çözümleme
2. **SSL Sertifikaları**: 
   - CN (Common Name) ve SAN'dan domain çıkarma
   - İteratif SNI denemeleri
   - Agresif SNI (domain varyasyonları)
3. **HTTP Host Header**: Virtual hosting tespiti
4. **Certificate Transparency**: crt.sh API ile domain bulma

### Subdomain Keşfi

1. **Passive Enumeration**:
   - Certificate Transparency Logs (crt.sh)
   - DNS Zone Transfer denemeleri
   - SSL sertifikalarından subdomain çıkarma
2. **Active Enumeration**:
   - DNS Brute Force (wordlist ile)
   - Varsayılan wordlist: 100+ yaygın subdomain

### Canlı Subdomain Testi

- DNS çözümleme kontrolü
- Port taraması (80, 443)
- HTTP/HTTPS yanıt kontrolü
- Status code, Server header, Title bilgisi

## ⚙️ Yapılandırma

### Timeout Ayarları

Varsayılan timeout 3.0 saniyedir. Büyük port taramaları için timeout'u düşürebilirsiniz:

```bash
python reconscope.py example.com --timeout 1.0
```

### Thread Sayısı

Varsayılan thread sayısı 50'dir. Daha hızlı tarama için artırabilirsiniz:

```bash
python reconscope.py example.com --workers 100
```

**Not**: Çok yüksek thread sayıları sistem kaynaklarını aşırı kullanabilir.

## 📁 Dosya Yapısı

```
reconscope/
├── reconscope.py        # Ana uygulama dosyası
├── requirements.txt     # Python bağımlılıkları
└── README.md           # Bu dosya
```

## 🛠️ Geliştirme

### Kod Yapısı

- `DomainPortSSLScanner`: Ana tarama sınıfı
  - `resolve_domain()`: Domain'den IP çözümleme
  - `reverse_dns_lookup()`: Reverse DNS sorgusu
  - `scan_ports()`: Port taraması
  - `get_ssl_info()`: SSL sertifika bilgileri
  - `get_dns_records()`: DNS kayıt sorgulama
  - `find_all_domains_for_ip()`: IP'den domain keşfi
  - `discover_subdomains()`: Subdomain keşfi
  - `check_live_subdomains()`: Canlı subdomain testi

## ⚠️ Uyarılar ve Sınırlamalar

1. **Yasal Kullanım**: Bu araç yalnızca kendi sistemlerinizde veya yazılı izniniz olan sistemlerde kullanılmalıdır. Yetkisiz tarama yasalara aykırıdır.

2. **Rate Limiting**: Bazı DNS sunucuları ve API'ler rate limiting uygulayabilir. Çok fazla sorgu göndermekten kaçının.

3. **Timeout**: Büyük port taramaları uzun sürebilir. Timeout değerlerini uygun şekilde ayarlayın.

4. **crt.sh API**: Certificate Transparency API'si bazen yavaş yanıt verebilir veya rate limiting uygulayabilir.

5. **DNS Zone Transfer**: Çoğu sunucu DNS zone transfer'i engeller. Bu yöntem nadiren başarılı olur.

## 🤝 Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## 📄 Lisans

Bu proje açık kaynaklıdır. Kendi sorumluluğunuzda kullanın.

## 🐛 Bilinen Sorunlar

- Bazı SSL sertifikaları düzgün parse edilemeyebilir
- crt.sh API bazen timeout verebilir
- DNS Zone Transfer çoğu sunucuda engellenmiştir

## 📞 Destek

Sorunlar için issue açabilir veya pull request gönderebilirsiniz.

## 🔗 İlgili Araçlar

Bu araç şu popüler araçların alternatifidir:
- **nmap**: Port tarama
- **subfinder**: Subdomain keşfi
- **amass**: Subdomain enumeration
- **httpx**: Canlı subdomain testi
- **sslscan**: SSL analizi

## 📈 Performans İpuçları

1. **Büyük Port Taramaları**: 10000 port taraması uzun sürebilir. Belirli portları hedefleyin:
   ```bash
   python reconscope.py example.com --ports 80 443 8080 8443
   ```

2. **Thread Sayısı**: Sistem kaynaklarınıza göre thread sayısını ayarlayın.

3. **Timeout**: Hızlı tarama için timeout'u düşürün, ancak false negative'leri artırabilir.

4. **Subdomain Keşfi**: Passive enumeration daha hızlıdır. Active enumeration wordlist boyutuna bağlı olarak uzun sürebilir.

## 🎯 Kullanım Senaryoları

### Senaryo 1: Web Sunucusu Güvenlik Kontrolü
```bash
python reconscope.py example.com --ports 80 443 8080 8443
```

### Senaryo 2: IP Adresindeki Tüm Domainleri Bulma
```bash
python reconscope.py 31.145.154.82
```

### Senaryo 3: Subdomain Keşfi ve Canlı Test
```bash
python reconscope.py example.com --subdomains --check-live \
  --subdomain-output sub.txt --live-output live.txt
```

### Senaryo 4: Kapsamlı Güvenlik Raporu
```bash
python reconscope.py example.com --format json --output security-report.json
```

---

**Not**: Bu araç eğitim ve yasal güvenlik testleri için tasarlanmıştır. Yetkisiz kullanım yasaktır.

## 👤 Proje Sahibi

**bsekercioglu**

- GitHub: [@bsekercioglu](https://github.com/bsekercioglu)
- Repository: [reconscope](https://github.com/bsekercioglu/reconscope)
