#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconScope - Comprehensive Reconnaissance and Security Scanning Tool
Kapsamlı keşif ve güvenlik tarama aracı.
"""

import socket
import ssl
import json
import argparse
import re
import sys
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import concurrent.futures
import time

# ANSI renk kodları
class Colors:
    """ANSI renk kodları"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'

def print_banner():
    """ReconScope banner'ını yazdırır"""
    # Windows uyumluluğu için encoding kontrolü
    try:
        import sys
        if sys.platform == 'win32':
            import io
            if hasattr(sys.stdout, 'buffer'):
                sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except:
        pass
    
    # ASCII-only banner (Windows uyumlu)
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║     ██████╗ ███████╗ ██████╗  ██████╗ ███╗   ██╗                     ║
║     ██╔══██╗██╔════╝██╔═══██╗██╔═══██╗████╗  ██║                     ║
║     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║                      ║
║     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║                      ║
║     ██║  ██║███████╗╚██████╔╝╚██████╔╝██║ ╚████║                     ║
║     ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝                     ║
║                                                                      ║
║     ███████╗ ██████╗  ██████╗ ██████╗ ███████╗                       ║
║     ██╔════╝██╔═══██╗██╔═══██╗██╔══██╗██╔════╝                       ║
║     ███████╗██║     ██║   ██║██████╔╝█████╗                          ║
║     ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝                          ║
║     ███████║╚██████╔╝╚██████╔╝██║     ███████╗                       ║
║     ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝                       ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.YELLOW}{Colors.BOLD}        Comprehensive Reconnaissance & Security Scanner{Colors.RESET}
{Colors.GRAY}        Version 1.0.0 | Professional Security Tool{Colors.RESET}
{Colors.GRAY}        Developed by: bsekercioglu{Colors.RESET}
{Colors.GRAY}        Repository: https://github.com/bsekercioglu/reconscope{Colors.RESET}
{Colors.CYAN}{'=' * 70}{Colors.RESET}
"""
    try:
        print(banner)
    except (UnicodeEncodeError, AttributeError):
        # Fallback: ASCII-only banner (renk kodları olmadan)
        banner_ascii = """
======================================================================
                                                                      
                    R E C O N S C O P E                              
                                                                      
======================================================================
        Comprehensive Reconnaissance & Security Scanner
        Version 1.0.0 | Professional Security Tool
        Developed by: bsekercioglu
        Repository: https://github.com/bsekercioglu/reconscope
======================================================================
"""
        print(banner_ascii)

# Cryptography kütüphanesi için try-except
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# DNS kütüphanesi için try-except
try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    import dns.zone
    import dns.query
    import dns.rdatatype
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DomainPortSSLScanner:
    """Domain, port tarama ve SSL bilgisi toplama sınıfı"""
    
    # Yaygın portlar ve servis isimleri
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        465: 'SMTPS',
        587: 'SMTP (Submission)',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        8888: 'HTTP-Alt',
        9000: 'SonarQube',
        9200: 'Elasticsearch',
        27017: 'MongoDB',
    }
    
    # SSL/TLS portları
    SSL_PORTS = [443, 465, 993, 995, 8443]
    
    def __init__(self, timeout: float = 3.0, max_workers: int = 50):
        """
        Args:
            timeout: Port bağlantı timeout süresi (saniye)
            max_workers: Eşzamanlı port tarama thread sayısı
        """
        self.timeout = timeout
        self.max_workers = max_workers
    
    def resolve_domain(self, domain: str) -> List[str]:
        """
        Domain'den IP adreslerini çözümler
        
        Args:
            domain: Çözümlenecek domain adı
            
        Returns:
            IP adresleri listesi
        """
        try:
            # IPv4 adreslerini al
            ipv4_addresses = []
            addrinfo = socket.getaddrinfo(domain, None, socket.AF_INET)
            for info in addrinfo:
                ip = info[4][0]
                if ip not in ipv4_addresses:
                    ipv4_addresses.append(ip)
            
            if not ipv4_addresses:
                # Alternatif yöntem
                ip = socket.gethostbyname(domain)
                ipv4_addresses = [ip]
            
            return ipv4_addresses
        except socket.gaierror as e:
            print(f"[-] Domain cozumleme hatasi: {e}")
            return []
        except Exception as e:
            print(f"[-] Beklenmeyen hata (domain cozumleme): {e}")
            return []
    
    def reverse_dns_lookup(self, ip: str) -> List[str]:
        """
        IP adresinden reverse DNS lookup yaparak domain(ler)i bulur
        
        Args:
            ip: IP adresi
            
        Returns:
            Bulunan domain listesi
        """
        domains = []
        
        if not DNS_AVAILABLE:
            return domains
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            # Reverse DNS lookup
            reverse_name = dns.reversename.from_address(ip)
            answers = resolver.resolve(reverse_name, 'PTR')
            
            for rdata in answers:
                domain = str(rdata.target).rstrip('.')
                # .in-addr.arpa formatındaki kayıtları filtrele
                if domain and '.in-addr.arpa' not in domain and domain not in domains:
                    domains.append(domain)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass
        except Exception as e:
            pass
        
        # Eğer domain bulunamazsa, SSL sertifikasından domain bulmayı dene
        if not domains:
            try:
                # Port 443'ten SSL sertifikası al ve domain'i çıkar
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((ip, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            if CRYPTOGRAPHY_AVAILABLE:
                                try:
                                    cert_der = ssock.getpeercert(binary_form=True)
                                    if cert_der:
                                        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                                        # Subject'ten CN al
                                        for attr in cert_obj.subject:
                                            if hasattr(attr.oid, '_name') and attr.oid._name == 'commonName':
                                                cn = attr.value
                                                if cn and cn not in domains:
                                                    domains.append(cn)
                                                break
                                except:
                                    pass
            except:
                pass
        
        return domains
    
    def find_all_domains_for_ip(self, ip: str) -> List[str]:
        """
        Bir IP adresi için tüm domainleri bulur (reverse DNS + SSL sertifikaları + HTTP)
        
        Args:
            ip: IP adresi
            
        Returns:
            Bulunan domain listesi
        """
        domains = []
        
        # 1. Reverse DNS lookup
        rDNS_domains = self.reverse_dns_lookup(ip)
        domains.extend(rDNS_domains)
        print(f"[+] Reverse DNS: {len(rDNS_domains)} domain")
        
        # 2. SSL sertifikalarından domain bulma (SAN - Subject Alternative Names)
        # Önce SSL'den bul, sonra bulunan domainlerle SNI denemesi yap
        print(f"[*] SSL sertifikalarindan domainler araniyor...")
        # İteratif olarak domain bulma - bulunan domainlerle SNI denemesi yap
        ssl_domains = []
        current_known = rDNS_domains.copy()
        all_found_domains = set()  # Tüm bulunan domainleri takip et
        
        # İlk tur: IP ile ve bilinen domainlerle
        print(f"   [*] 1. Tur: IP ve bilinen domainlerle SSL sertifikalari taranıyor...")
        new_domains = self.find_domains_from_ssl_certificates(ip, known_domains=current_known)
        ssl_domains.extend(new_domains)
        all_found_domains.update(new_domains)
        current_known.extend(new_domains)
        print(f"      [+] {len(new_domains)} domain bulundu")
        
        # İteratif SNI denemesi - bulunan her domain ile tekrar dene
        max_iterations = 10  # Daha fazla iterasyon (30+ domain için)
        for iteration in range(max_iterations):
            if not new_domains:
                break
            print(f"   [*] Iterasyon {iteration + 2}: Bulunan {len(new_domains)} domain ile SNI denemesi...")
            iteration_domains = self.find_domains_from_ssl_certificates(ip, known_domains=current_known)
            # Sadece yeni domainleri ekle
            truly_new = [d for d in iteration_domains if d not in all_found_domains]
            if truly_new:
                ssl_domains.extend(truly_new)
                all_found_domains.update(truly_new)
                current_known.extend(truly_new)
                new_domains = truly_new
                print(f"      [+] {len(truly_new)} yeni domain bulundu (Toplam: {len(all_found_domains)})")
            else:
                print(f"      [-] Yeni domain bulunamadi")
                # Yeni domain bulunamadıysa, agresif SNI'ye geç
                break
        
        # Agresif SNI denemesi - domain varyasyonlarını dene
        if all_found_domains:
            print(f"   [*] Agresif SNI: Domain varyasyonlari deneniyor (www, subdomainler)...")
            aggressive_domains = self.find_domains_aggressive_sni(ip, list(all_found_domains))
            truly_new_aggressive = [d for d in aggressive_domains if d not in all_found_domains]
            if truly_new_aggressive:
                ssl_domains.extend(truly_new_aggressive)
                all_found_domains.update(truly_new_aggressive)
                current_known.extend(truly_new_aggressive)
                print(f"      [+] {len(truly_new_aggressive)} yeni domain (varyasyonlardan) bulundu")
                
                # Agresif SNI'den bulunan domainlerle tekrar iteratif deneme
                if truly_new_aggressive:
                    print(f"   [*] Agresif SNI sonrasi iteratif deneme...")
                    for iteration in range(5):  # Daha fazla iterasyon
                        iteration_domains = self.find_domains_from_ssl_certificates(ip, known_domains=current_known)
                        truly_new = [d for d in iteration_domains if d not in all_found_domains]
                        if truly_new:
                            ssl_domains.extend(truly_new)
                            all_found_domains.update(truly_new)
                            current_known.extend(truly_new)
                            print(f"      [+] {len(truly_new)} yeni domain bulundu (Toplam: {len(all_found_domains)})")
                        else:
                            break
        
        # crt.sh API'sini bulunan domainler için kullan (IP yerine domain ile)
        if all_found_domains:
            print(f"   [*] crt.sh API ile bulunan domainlerin sertifikalari kontrol ediliyor...")
            ct_domains = []
            import urllib.request
            import urllib.parse
            
            for domain in list(all_found_domains)[:20]:  # İlk 20 domain
                try:
                    # Domain'in kök domain'ini al (subdomain'leri kaldır)
                    root_domain = domain
                    if '.' in domain:
                        parts = domain.split('.')
                        if len(parts) >= 2:
                            root_domain = '.'.join(parts[-2:])  # Son 2 kısım (örn: example.com)
                    
                    # crt.sh'de domain için sorgu yap
                    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(root_domain)}&output=json"
                    req = urllib.request.Request(url)
                    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
                    
                    with urllib.request.urlopen(req, timeout=5.0) as response:
                        data = response.read().decode('utf-8')
                        try:
                            entries = json.loads(data)
                            if isinstance(entries, list):
                                for entry in entries:
                                    name_value = entry.get('name_value', '')
                                    if name_value:
                                        for separator in ['\n', ',', ' ', ';']:
                                            if separator in name_value:
                                                for d in name_value.split(separator):
                                                    d = d.strip()
                                                    if d and not self.is_ip_address(d):
                                                        if d.startswith('*.'):
                                                            d = d[2:]
                                                        if '.' in d and not d.startswith('.'):
                                                            # A kaydını kontrol et - aynı IP'ye işaret ediyor mu?
                                                            try:
                                                                answers = dns.resolver.resolve(d, 'A')
                                                                for rdata in answers:
                                                                    if str(rdata) == ip:
                                                                        if d not in ct_domains and d not in all_found_domains:
                                                                            ct_domains.append(d)
                                                                        break
                                                            except:
                                                                pass
                                                break
                        except:
                            pass
                except:
                    pass
            
            if ct_domains:
                ssl_domains.extend(ct_domains)
                all_found_domains.update(ct_domains)
                print(f"      [+] crt.sh'den {len(ct_domains)} yeni domain bulundu (aynı IP'ye isaret eden)")
        
        domains.extend(ssl_domains)
        print(f"[+] SSL sertifikalari: {len(all_found_domains)} benzersiz domain bulundu")
        
        # 3. Certificate Transparency Logs'dan domain bulma
        # Not: crt.sh IP adresi için çalışmıyor, bu yüzden atlanıyor
        # print(f"[*] Certificate Transparency Logs'dan domainler araniyor...")
        # ct_domains = self.find_domains_from_certificate_transparency(ip)
        # domains.extend(ct_domains)
        
        # 4. HTTP Host header ile domain bulma (virtual hosting) - bilinen domainlerin varyasyonları ile
        if domains:
            print(f"[*] HTTP Host header ile domainler araniyor (bilinen domainlerin varyasyonlari ile)...")
            http_domains = self.find_domains_from_http(ip, known_domains=list(set(domains)))
            if http_domains:
                # Sadece yeni domainleri ekle
                new_http_domains = [d for d in http_domains if d not in domains]
                if new_http_domains:
                    domains.extend(new_http_domains)
                    print(f"[+] HTTP Host header: {len(new_http_domains)} yeni domain bulundu")
                else:
                    print(f"[+] HTTP Host header: Yeni domain bulunamadi")
            else:
                print(f"[+] HTTP Host header: Domain bulunamadi")
        
        # Tekrarları kaldır ve temizle
        unique_domains = []
        seen = set()
        for domain in domains:
            # Geçersiz domainleri filtrele
            if domain and not domain.startswith('.') and '.' in domain:
                # IP adresi formatını filtrele
                if not self.is_ip_address(domain):
                    # Normalize et (küçük harfe çevir)
                    domain_lower = domain.lower().strip()
                    if domain_lower and domain_lower not in seen:
                        seen.add(domain_lower)
                        unique_domains.append(domain_lower)
        
        print(f"[+] Toplam {len(unique_domains)} benzersiz domain bulundu")
        if len(unique_domains) > 0:
            print(f"[*] Domainler: {', '.join(unique_domains[:20])}")
            if len(unique_domains) > 20:
                print(f"[*] ... ve {len(unique_domains) - 20} domain daha")
        
        return unique_domains
    
    def is_ip_address(self, address: str) -> bool:
        """Bir string'in IP adresi olup olmadığını kontrol eder"""
        try:
            parts = address.split('.')
            if len(parts) == 4:
                return all(0 <= int(part) <= 255 for part in parts if part.isdigit())
        except:
            pass
        return False
    
    def find_domains_from_ssl_certificates(self, ip: str, known_domains: List[str] = None) -> List[str]:
        """
        IP adresindeki SSL sertifikalarından domainleri bulur (SAN listesi)
        Farklı SNI (Server Name Indication) değerleri ile deneme yapar
        
        Args:
            ip: IP adresi
            known_domains: Bilinen domainler (SNI denemesi için)
            
        Returns:
            Bulunan domain listesi
        """
        domains = []
        # Daha fazla SSL portu tara (virtual hosting için)
        ssl_ports = [443, 8443, 465, 993, 995, 636, 989, 990, 992, 994, 2083, 2087, 2096, 3443, 5061, 8080, 8081, 8443, 9443]
        
        # Debug: Bulunan domainleri göster
        print(f"   [*] {len(ssl_ports)} SSL portu taranacak")
        
        if known_domains is None:
            known_domains = []
        
        for port in ssl_ports:
            try:
                # Önce portun açık olup olmadığını kontrol et
                sock_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_test.settimeout(1.0)
                result = sock_test.connect_ex((ip, port))
                sock_test.close()
                
                if result != 0:
                    continue  # Port kapalı, atla
                
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Önce IP ile dene (default sertifika)
                try:
                    with socket.create_connection((ip, port), timeout=2.0) as sock:
                        with context.wrap_socket(sock, server_hostname=ip) as ssock:
                            old_count = len(domains)
                            self._extract_domains_from_cert(ssock, domains)
                            new_count = len(domains)
                            if new_count > old_count:
                                print(f"      Port {port}: {new_count - old_count} yeni domain bulundu")
                except:
                    pass
                
                # Eğer bilinen domainler varsa, onlarla SNI denemesi yap
                # SNI ile farklı sertifikalar alınabilir (virtual hosting)
                if known_domains:
                    for sni_domain in known_domains[:20]:  # İlk 20 domain ile dene (daha fazla)
                        try:
                            with socket.create_connection((ip, port), timeout=2.0) as sock:
                                with context.wrap_socket(sock, server_hostname=sni_domain) as ssock:
                                    old_count = len(domains)
                                    self._extract_domains_from_cert(ssock, domains)
                                    # Yeni domain bulunduysa sessiz geç (çok fazla çıktı olmasın)
                        except:
                            continue
                
                # Bulunan domainlerle tekrar SNI denemesi yap (iteratif)
                # Her yeni bulunan domain ile tekrar dene - daha fazla iterasyon
                max_iterations = 3
                for iteration in range(max_iterations):
                    new_domains = [d for d in domains if d not in (known_domains + list(set(domains[:len(domains)-10])))]
                    if not new_domains:
                        break
                    for sni_domain in new_domains[:10]:  # Her iterasyonda 10 yeni domain ile dene
                        try:
                            with socket.create_connection((ip, port), timeout=2.0) as sock:
                                with context.wrap_socket(sock, server_hostname=sni_domain) as ssock:
                                    self._extract_domains_from_cert(ssock, domains)
                        except:
                            continue
            except:
                continue  # Port taraması hatası
        
        return domains
    
    def _extract_domains_from_cert(self, ssock, domains: List[str]):
        """SSL socket'ten domainleri çıkarır"""
        try:
            # Subject Alternative Names (SAN) listesini al
            if CRYPTOGRAPHY_AVAILABLE:
                try:
                    cert_der = ssock.getpeercert(binary_form=True)
                    if cert_der:
                        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                        
                        # Subject'ten CN al
                        for attr in cert_obj.subject:
                            oid_name = attr.oid._name if hasattr(attr.oid, '_name') else None
                            if oid_name == 'commonName':
                                cn = attr.value
                                if cn and cn not in domains and not self.is_ip_address(cn):
                                    domains.append(cn)
                        
                        # SAN (Subject Alternative Names) listesini al
                        try:
                            san_ext = cert_obj.extensions.get_extension_for_oid(
                                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                            )
                            for name in san_ext.value:
                                if isinstance(name, x509.DNSName):
                                    dns_name = name.value
                                    if dns_name and dns_name not in domains and not self.is_ip_address(dns_name):
                                        # Wildcard domainleri temizle
                                        if dns_name.startswith('*.'):
                                            dns_name = dns_name[2:]
                                        domains.append(dns_name)
                        except x509.ExtensionNotFound:
                            pass
                except Exception:
                    pass
            else:
                # Cryptography yoksa, getpeercert'ten SAN al
                try:
                    cert = ssock.getpeercert()
                    if cert:
                        san_list = cert.get('subjectAltName', [])
                        for san_type, san_value in san_list:
                            if san_type == 'DNS' and san_value not in domains and not self.is_ip_address(san_value):
                                # Wildcard domainleri temizle
                                if san_value.startswith('*.'):
                                    san_value = san_value[2:]
                                domains.append(san_value)
                        
                        # Subject'ten CN al
                        subject = cert.get('subject', [])
                        for item in subject:
                            if isinstance(item, tuple) and len(item) >= 2:
                                if item[0] == 'commonName' or item[0] == 'CN':
                                    cn = item[1]
                                    if cn and cn not in domains and not self.is_ip_address(cn):
                                        if cn.startswith('*.'):
                                            cn = cn[2:]
                                        domains.append(cn)
                except:
                    pass
        except:
            pass
        
        return domains
    
    def find_domains_from_http(self, ip: str, known_domains: List[str] = None) -> List[str]:
        """
        HTTP Host header ile domainleri bulur (virtual hosting tespiti)
        Bilinen domainlerin varyasyonlarını HTTP'de dener
        
        Args:
            ip: IP adresi
            known_domains: Bilinen domain listesi (varyasyonlar denenir)
            
        Returns:
            Bulunan domain listesi
        """
        domains = []
        
        if known_domains is None:
            known_domains = []
        
        # HTTP portları
        http_ports = [80, 8080, 8000, 8888]
        
        # Bilinen domainlerin varyasyonlarını dene
        test_domains = set(known_domains)
        for domain in known_domains[:50]:  # İlk 50 domain
            # www ve non-www varyasyonları
            if domain.startswith('www.'):
                test_domains.add(domain[4:])
            else:
                test_domains.add(f"www.{domain}")
        
        # Her domain için HTTP isteği gönder
        for domain in list(test_domains)[:100]:  # İlk 100 domain
            for port in http_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.5)
                    sock.connect((ip, port))
                    
                    # Host header ile istek gönder
                    request = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
                    sock.send(request.encode())
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
                    
                    # Başarılı yanıt alındıysa (200, 301, 302, etc.)
                    if response.startswith('HTTP/'):
                        status_code = response.split()[1] if len(response.split()) > 1 else ''
                        # Başarılı yanıtlar
                        if status_code.startswith('2') or status_code.startswith('3'):
                            if domain not in domains:
                                domains.append(domain)
                    
                    sock.close()
                except:
                    pass
        
        return domains
    
    def find_domains_from_certificate_transparency(self, ip: str) -> List[str]:
        """
        Certificate Transparency Logs'dan domainleri bulur (harici API kullanır)
        
        Args:
            ip: IP adresi
            
        Returns:
            Bulunan domain listesi
        """
        domains = []
        
        # Certificate Transparency Logs için crt.sh API kullan
        try:
            import urllib.request
            import urllib.parse
            
            # crt.sh API endpoint - IP adresi için sertifikaları bul
            # crt.sh'de IP adresi için doğru format: IP adresini hex'e çevir veya direkt kullan
            # Alternatif: IP adresine bağlı sertifikaları bulmak için farklı yöntemler
            urls = [
                f"https://crt.sh/?q=ip:{urllib.parse.quote(ip)}&output=json",  # ip: formatı
                f"https://crt.sh/?q={urllib.parse.quote(ip)}&output=json",  # Direkt IP
                f"https://crt.sh/?q=%25.{urllib.parse.quote(ip)}&output=json",  # Wildcard
            ]
            
            for url in urls:
                print(f"   [*] crt.sh API sorgulaniyor: {url}")
            
                try:
                    # User-Agent header ekle
                    req = urllib.request.Request(url)
                    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
                    
                    with urllib.request.urlopen(req, timeout=10.0) as response:
                        data = response.read().decode('utf-8')
                        
                        # JSON parse et
                        try:
                            entries = json.loads(data)
                        except json.JSONDecodeError:
                            # Eğer JSON değilse, text formatında olabilir
                            entries = []
                        
                        if isinstance(entries, list):
                            for entry in entries:
                                # name_value alanından domainleri al
                                name_value = entry.get('name_value', '')
                                common_name = entry.get('common_name', '')
                                
                                # name_value'den domainleri çıkar
                                if name_value:
                                    # Birden fazla domain olabilir (satır sonu, virgül veya boşluk ile ayrılmış)
                                    for separator in ['\n', ',', ' ', ';']:
                                        if separator in name_value:
                                            for domain in name_value.split(separator):
                                                domain = domain.strip()
                                                if domain and domain not in domains and not self.is_ip_address(domain):
                                                    # Wildcard domainleri temizle
                                                    if domain.startswith('*.'):
                                                        domain = domain[2:]
                                                    # Geçersiz karakterleri temizle
                                                    if '.' in domain and not domain.startswith('.'):
                                                        domains.append(domain)
                                            break
                                    else:
                                        # Tek domain
                                        domain = name_value.strip()
                                        if domain and domain not in domains and not self.is_ip_address(domain):
                                            if domain.startswith('*.'):
                                                domain = domain[2:]
                                            if '.' in domain and not domain.startswith('.'):
                                                domains.append(domain)
                                
                                # common_name'den domain al
                                if common_name:
                                    domain = common_name.strip()
                                    if domain and domain not in domains and not self.is_ip_address(domain):
                                        if domain.startswith('*.'):
                                            domain = domain[2:]
                                        if '.' in domain and not domain.startswith('.'):
                                            domains.append(domain)
                            
                            if len(domains) > 0:
                                print(f"   [+] crt.sh'den {len(domains)} domain bulundu")
                                break  # Başarılı oldu, diğer URL'leri deneme
                        else:
                            print(f"   [-] crt.sh'den veri alinamadi (bu URL)")
                            continue  # Bir sonraki URL'yi dene
                        
                except urllib.error.HTTPError as e:
                    print(f"   [-] crt.sh API hatasi (HTTP {e.code}): Bu URL calismadi")
                    continue  # Bir sonraki URL'yi dene
                except urllib.error.URLError as e:
                    print(f"   [-] crt.sh API baglanti hatasi: {e.reason}")
                    continue  # Bir sonraki URL'yi dene
                except Exception as e:
                    print(f"   [-] crt.sh API hatasi: {str(e)}")
                    continue  # Bir sonraki URL'yi dene
                    
            if len(domains) == 0:
                print(f"   [-] Tum URL'ler denendi, domain bulunamadi")
        except ImportError:
            print(f"   [-] urllib modulu bulunamadi")
        except Exception as e:
            print(f"   [-] Beklenmeyen hata: {str(e)}")
        
        return domains
    
    def find_domains_aggressive_sni(self, ip: str, initial_domains: List[str]) -> List[str]:
        """
        Agresif SNI denemesi ile domainleri bulur
        Bulunan domainlerin varyasyonlarını (www, non-www, subdomainler) dener
        
        Args:
            ip: IP adresi
            initial_domains: Başlangıç domain listesi
            
        Returns:
            Bulunan domain listesi
        """
        domains = list(initial_domains)
        tested_domains = set(initial_domains)
        ssl_ports = [443, 8443]  # Sadece yaygın portlar
        
        # Domain varyasyonlarını oluştur
        def get_domain_variations(domain: str) -> List[str]:
            """Domain'in varyasyonlarını oluşturur"""
            variations = []
            if domain.startswith('www.'):
                variations.append(domain[4:])  # www'siz
            else:
                variations.append(f"www.{domain}")  # www'li
            
            # Subdomain denemeleri (yaygın subdomainler - daha kapsamlı liste)
            common_subdomains = [
                'mail', 'webmail', 'email', 'smtp', 'pop', 'imap', 'pop3', 'imap4',
                'ftp', 'sftp', 'admin', 'administrator', 'panel', 'cpanel', 'whm', 'plesk',
                'web', 'www', 'blog', 'shop', 'store', 'ecommerce', 'api', 'app', 'apps',
                'mobile', 'm', 'old', 'new', 'test', 'testing', 'dev', 'development',
                'staging', 'stage', 'preview', 'demo', 'demo2', 'demo3',
                'ns1', 'ns2', 'dns', 'ns', 'ns3', 'ns4',
                'cdn', 'static', 'assets', 'media', 'images', 'img', 'files', 'file',
                'secure', 'ssl', 'vpn', 'remote', 'access',
                'db', 'database', 'mysql', 'postgres', 'mongo',
                'backup', 'backups', 'archive', 'old-site', 'legacy'
            ]
            for subdomain in common_subdomains:
                variations.append(f"{subdomain}.{domain}")
            
            return variations
        
        # Her domain için varyasyonları dene
        for domain in initial_domains[:100]:  # İlk 100 domain ile dene (daha fazla)
            variations = get_domain_variations(domain)
            for variation in variations:
                if variation in tested_domains:
                    continue
                tested_domains.add(variation)
                
                # SNI ile sertifika al
                for port in ssl_ports:
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        with socket.create_connection((ip, port), timeout=1.5) as sock:
                            with context.wrap_socket(sock, server_hostname=variation) as ssock:
                                self._extract_domains_from_cert(ssock, domains)
                    except:
                        continue
        
        # Yeni bulunan domainleri döndür
        new_domains = [d for d in domains if d not in initial_domains]
        return new_domains
    
    def get_dns_records(self, domain: str) -> Dict:
        """
        Domain için DNS kayıtlarını toplar (NS, A, AAAA, MX, TXT, SPF, CNAME, PTR)
        
        Args:
            domain: Sorgulanacak domain adı
            
        Returns:
            DNS kayıtları dictionary'si
        """
        dns_records = {
            'A': [],
            'AAAA': [],
            'NS': [],
            'MX': [],
            'TXT': [],
            'CNAME': [],
            'SPF': [],
            'PTR': []
        }
        
        if not DNS_AVAILABLE:
            return {'error': 'dnspython kutuphanesi yuklu degil. "pip install dnspython" ile yukleyin.'}
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            # A kayıtları (IPv4)
            try:
                answers = resolver.resolve(domain, 'A')
                dns_records['A'] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass
            
            # AAAA kayıtları (IPv6)
            try:
                answers = resolver.resolve(domain, 'AAAA')
                dns_records['AAAA'] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass
            
            # NS kayıtları (Name Server)
            try:
                answers = resolver.resolve(domain, 'NS')
                dns_records['NS'] = [str(rdata.target) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass
            
            # MX kayıtları (Mail Exchange)
            try:
                answers = resolver.resolve(domain, 'MX')
                mx_records = []
                for rdata in answers:
                    mx_records.append({
                        'priority': rdata.preference,
                        'host': str(rdata.exchange)
                    })
                dns_records['MX'] = mx_records
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass
            
            # TXT kayıtları
            try:
                answers = resolver.resolve(domain, 'TXT')
                txt_records = []
                for rdata in answers:
                    # TXT kayıtları byte string olabilir, decode et
                    txt_string = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                    txt_records.append(txt_string)
                    
                    # SPF kaydı kontrolü
                    if txt_string.startswith('v=spf1') or 'spf' in txt_string.lower():
                        dns_records['SPF'].append(txt_string)
                dns_records['TXT'] = txt_records
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass
            
            # CNAME kayıtları
            try:
                answers = resolver.resolve(domain, 'CNAME')
                dns_records['CNAME'] = [str(rdata.target) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass
            
            # PTR kayıtları (Reverse DNS) - A kayıtlarından IP'ler için
            if dns_records['A']:
                for ip in dns_records['A']:
                    try:
                        reverse_name = dns.reversename.from_address(ip)
                        ptr_answers = resolver.resolve(reverse_name, 'PTR')
                        ptr_records = [str(rdata.target) for rdata in ptr_answers]
                        if ptr_records:
                            dns_records['PTR'].append({
                                'ip': ip,
                                'hostname': ptr_records[0] if ptr_records else None
                            })
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                        pass
            
        except Exception as e:
            return {'error': f'DNS sorgulama hatasi: {str(e)}'}
        
        return dns_records
    
    def check_port(self, ip: str, port: int) -> Tuple[bool, Optional[str]]:
        """
        Belirli bir IP ve port kombinasyonunu kontrol eder
        
        Args:
            ip: IP adresi
            port: Port numarası
            
        Returns:
            (açık_mı, hata_mesajı) tuple'ı
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                return True, None
            else:
                return False, None
        except socket.timeout:
            return False, "Timeout"
        except Exception as e:
            return False, str(e)
    
    def get_banner(self, ip: str, port: int, service_name: str) -> Optional[str]:
        """
        Port üzerinde çalışan servisin banner/version bilgisini alır
        
        Args:
            ip: IP adresi
            port: Port numarası
            service_name: Servis adı (HTTP, FTP, SSH, vb.)
            
        Returns:
            Banner/version bilgisi veya None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            banner = None
            
            if service_name == 'HTTP' or port == 80:
                # HTTP Server header'ını al
                try:
                    sock.settimeout(2.0)
                    request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                    sock.send(request.encode())
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
                    headers = {}
                    for line in response.split('\r\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.lower().strip()] = value.strip()
                    
                    server = headers.get('server', '')
                    if server:
                        banner = f"Server: {server}"
                    # X-Powered-By gibi diğer header'ları da ekle
                    powered_by = headers.get('x-powered-by', '')
                    if powered_by:
                        if banner:
                            banner += f", X-Powered-By: {powered_by}"
                        else:
                            banner = f"X-Powered-By: {powered_by}"
                except:
                    pass
            
            elif service_name == 'FTP' or port == 21:
                # FTP banner
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if len(banner) > 200:
                        banner = banner[:200] + "..."
                except:
                    pass
            
            elif service_name == 'SSH' or port == 22:
                # SSH version
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if len(banner) > 200:
                        banner = banner[:200] + "..."
                except:
                    pass
            
            elif service_name == 'SMTP' or port in [25, 587]:
                # SMTP banner
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if len(banner) > 200:
                        banner = banner[:200] + "..."
                except:
                    pass
            
            elif service_name == 'POP3' or port == 110:
                # POP3 banner
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if len(banner) > 200:
                        banner = banner[:200] + "..."
                except:
                    pass
            
            elif service_name == 'IMAP' or port == 143:
                # IMAP banner
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if len(banner) > 200:
                        banner = banner[:200] + "..."
                except:
                    pass
            
            elif service_name in ['MySQL', 'MSSQL', 'PostgreSQL'] or port in [3306, 1433, 5432]:
                # Database banner (genellikle ilk paket)
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if not banner:
                        # Binary protocol, hex göster
                        sock.settimeout(0.5)
                        data = sock.recv(64)
                        if data:
                            banner = f"Binary protocol detected ({len(data)} bytes)"
                except:
                    pass
            
            else:
                # Genel banner grabbing
                try:
                    sock.settimeout(1.0)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if len(banner) > 200:
                        banner = banner[:200] + "..."
                    if not banner:
                        banner = None
                except:
                    pass
            
            sock.close()
            return banner
            
        except socket.timeout:
            return None
        except Exception:
            return None
    
    def get_ssl_info(self, domain: str, ip: str, port: int) -> Optional[Dict]:
        """
        SSL/TLS sertifika bilgilerini toplar
        
        Args:
            domain: Domain adı
            ip: IP adresi
            port: Port numarası
            
        Returns:
            SSL bilgileri dictionary'si veya None
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Önce getpeercert() ile dene
                    cert = ssock.getpeercert()
                    
                    # Eğer cert boş dict veya None ise, binary formattan al
                    if not cert or (isinstance(cert, dict) and not cert):
                        if CRYPTOGRAPHY_AVAILABLE:
                            try:
                                cert_der = ssock.getpeercert(binary_form=True)
                                if cert_der:
                                    # Binary formattan parse et
                                    cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                                    # Cert objesinden bilgileri çıkar
                                    subject_dict = {}
                                    issuer_dict = {}
                                    
                                    # Subject bilgileri
                                    for attr in cert_obj.subject:
                                        key = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid)
                                        value = attr.value
                                        subject_dict[key] = value
                                    
                                    # Issuer bilgileri
                                    for attr in cert_obj.issuer:
                                        key = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid)
                                        value = attr.value
                                        issuer_dict[key] = value
                                    
                                    # Tarih bilgileri (UTC kullan)
                                    not_before = cert_obj.not_valid_before_utc
                                    not_after = cert_obj.not_valid_after_utc
                                    
                                    ssl_info = {
                                        'subject': subject_dict,
                                        'issuer': issuer_dict,
                                        'notBefore': not_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                        'notAfter': not_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                        'notBefore_parsed': not_before.strftime('%Y-%m-%d %H:%M:%S'),
                                        'notAfter_parsed': not_after.strftime('%Y-%m-%d %H:%M:%S'),
                                        'protocol': ssock.version(),
                                        'cipher': ssock.cipher(),
                                    }
                                    
                                    # Kalan gün hesapla (UTC datetime kullan)
                                    from datetime import timezone
                                    now_utc = datetime.now(timezone.utc)
                                    expires_in_days = (not_after - now_utc).days
                                    ssl_info['expires_in_days'] = expires_in_days
                                    ssl_info['is_expired'] = now_utc > not_after
                                    
                                    return ssl_info
                            except Exception as e:
                                return {'error': f'Cryptography ile parse edilemedi: {str(e)}'}
                        else:
                            return {'error': 'Sertifika bilgisi alınamadı (cryptography kütüphanesi gerekli)'}
                    
                    # Eğer cert dict ise ve doluysa, normal parsing yap
                    if not isinstance(cert, dict):
                        return {'error': 'Sertifika formatı beklenmeyen tip'}
                    
                    # Sertifika bilgilerini parse et - daha güvenilir yöntem
                    def parse_cert_field(field_data):
                        """Sertifika alanını parse eder - Python ssl modülü formatı için"""
                        result = {}
                        if not field_data:
                            return result
                        
                        def find_key_value(t, depth=0):
                            """Tuple içinde key-value çiftini bulur (recursive)"""
                            if depth > 20:  # Infinite loop koruması
                                return None, None
                            
                            if not isinstance(t, tuple):
                                return None, None
                            
                            # Eğer tuple'ın uzunluğu 2 ve ilk eleman string ise, bu key-value çiftidir
                            if len(t) == 2:
                                key, value = t[0], t[1]
                                if isinstance(key, (str, bytes)):
                                    try:
                                        key_str = key.decode() if isinstance(key, bytes) else str(key)
                                        value_str = value.decode() if isinstance(value, bytes) else str(value)
                                        return key_str, value_str
                                    except:
                                        pass
                            
                            # Eğer tuple'ın uzunluğu 1 ise, içindeki tuple'a bak
                            if len(t) == 1 and isinstance(t[0], tuple):
                                return find_key_value(t[0], depth + 1)
                            
                            # Eğer tuple'ın uzunluğu 2'den fazla ise, ilk iki elemana bak
                            if len(t) >= 2:
                                return find_key_value((t[0], t[1]), depth + 1)
                            
                            return None, None
                        
                        try:
                            # field_data bir liste olmalı
                            if isinstance(field_data, (list, tuple)):
                                for item in field_data:
                                    if isinstance(item, tuple):
                                        key, value = find_key_value(item)
                                        if key and value:
                                            # Aynı key birden fazla olabilir
                                            if key in result:
                                                if isinstance(result[key], list):
                                                    result[key].append(value)
                                                else:
                                                    result[key] = [result[key], value]
                                            else:
                                                result[key] = value
                        except Exception as e:
                            # Hata durumunda boş dict döndür
                            pass
                        
                        return result
                    
                    subject_dict = parse_cert_field(cert.get('subject'))
                    issuer_dict = parse_cert_field(cert.get('issuer'))
                    
                    # Eğer hala boşsa, alternatif parsing dene
                    if not subject_dict and cert.get('subject'):
                        # Raw veriyi string'e çevir ve parse et
                        try:
                            subject_str = str(cert.get('subject'))
                            # Farklı pattern'leri dene
                            patterns = [
                                r"\(\(\(('.*?'),\s*('.*?')\)",  # ((('key', 'value')
                                r"\('(.*?)',\s*'(.*?)'\)",      # ('key', 'value')
                                r"\(('.*?'),\s*('.*?')\)",      # ('key', 'value')
                            ]
                            for pattern in patterns:
                                matches = re.findall(pattern, subject_str)
                                for match in matches:
                                    if len(match) >= 2:
                                        key = match[0].strip("'\"")
                                        value = match[1].strip("'\"")
                                        if key and value:
                                            subject_dict[key] = value
                                if subject_dict:
                                    break
                        except:
                            pass
                    
                    # Aynı şeyi issuer için de yap
                    if not issuer_dict and cert.get('issuer'):
                        try:
                            issuer_str = str(cert.get('issuer'))
                            patterns = [
                                r"\(\(\(('.*?'),\s*('.*?')\)",
                                r"\('(.*?)',\s*'(.*?)'\)",
                                r"\(('.*?'),\s*('.*?')\)",
                            ]
                            for pattern in patterns:
                                matches = re.findall(pattern, issuer_str)
                                for match in matches:
                                    if len(match) >= 2:
                                        key = match[0].strip("'\"")
                                        value = match[1].strip("'\"")
                                        if key and value:
                                            issuer_dict[key] = value
                                if issuer_dict:
                                    break
                        except:
                            pass
                    
                    ssl_info = {
                        'subject': subject_dict,
                        'issuer': issuer_dict,
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': cert.get('subjectAltName', []),
                        'protocol': ssock.version(),
                        'cipher': ssock.cipher(),
                    }
                    
                    # Tarih kontrolü ve parsing
                    def parse_cert_date(date_str):
                        """Sertifika tarihini parse eder"""
                        if not date_str or not isinstance(date_str, str):
                            return None
                        
                        # Farklı tarih formatlarını dene
                        date_formats = [
                            '%b %d %H:%M:%S %Y %Z',      # Jan 15 12:00:00 2024 GMT
                            '%b %d %H:%M:%S %Y GMT',     # Jan 15 12:00:00 2024 GMT
                            '%b %d %H:%M:%S %Y',         # Jan 15 12:00:00 2024
                            '%Y%m%d%H%M%S%z',            # 20240115120000+0000
                            '%Y-%m-%d %H:%M:%S',         # 2024-01-15 12:00:00
                        ]
                        
                        for fmt in date_formats:
                            try:
                                return datetime.strptime(date_str, fmt)
                            except ValueError:
                                continue
                        
                        return None
                    
                    not_after_str = cert.get('notAfter')
                    not_before_str = cert.get('notBefore')
                    
                    not_after = parse_cert_date(not_after_str) if not_after_str else None
                    not_before = parse_cert_date(not_before_str) if not_before_str else None
                    
                    if not_after:
                        ssl_info['expires_in_days'] = (not_after - datetime.now()).days
                        ssl_info['is_expired'] = datetime.now() > not_after
                        ssl_info['notAfter_parsed'] = not_after.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        ssl_info['expires_in_days'] = None
                        ssl_info['is_expired'] = None
                        ssl_info['notAfter_parsed'] = None
                    
                    if not_before:
                        ssl_info['notBefore_parsed'] = not_before.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        ssl_info['notBefore_parsed'] = None
                    
                    return ssl_info
        except ssl.SSLError as e:
            return {'error': f'SSL Hatası: {str(e)}'}
        except socket.timeout:
            return {'error': 'Bağlantı timeout'}
        except Exception as e:
            return {'error': f'Hata: {str(e)}'}
    
    def scan_ports(self, ip: str, ports: List[int] = None) -> List[Dict]:
        """
        Belirli bir IP adresindeki portları tarar
        
        Args:
            ip: IP adresi
            ports: Taranacak port listesi (None ise 1-10000 arası portlar taranır)
            
        Returns:
            Açık portlar ve servis bilgileri listesi
        """
        if ports is None:
            # İlk 10000 portu tara (1-10000)
            ports = list(range(1, 10001))
        
        open_ports = []
        
        # İlerleme bilgisi için
        total_ports = len(ports)
        if total_ports > 100:
            print(f"[*] {total_ports} port taranıyor... (bu işlem biraz zaman alabilir)")
        
        # Eşzamanlı port tarama
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self.check_port, ip, port): port for port in ports}
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1
                
                # İlerleme göster (her 1000 portta bir veya %10'da bir)
                if total_ports > 100 and (completed % max(1000, total_ports // 10) == 0):
                    progress = (completed / total_ports) * 100
                    print(f"[*] İlerleme: {completed}/{total_ports} port tarandı ({progress:.1f}%)")
                
                try:
                    is_open, error = future.result()
                    if is_open:
                        service_name = self.COMMON_PORTS.get(port, 'Bilinmeyen')
                        # Banner bilgisini al
                        banner = self.get_banner(ip, port, service_name)
                        port_info = {
                            'port': port,
                            'service': service_name,
                            'status': 'Açık'
                        }
                        if banner:
                            port_info['banner'] = banner
                        open_ports.append(port_info)
                        print(f"[+] Açık port bulundu: {port} ({service_name})")
                except Exception as e:
                    pass
        
        print(f"[+] Tarama tamamlandı: {len(open_ports)} açık port bulundu")
        return sorted(open_ports, key=lambda x: x['port'])
    
    def scan_from_ip(self, ip: str, ports: List[int] = None, check_ssl: bool = True) -> Dict:
        """
        IP adresinden başlayarak reverse DNS ile domainleri bulur ve tarar
        
        Args:
            ip: IP adresi
            ports: Taranacak port listesi (None ise yaygın portlar)
            check_ssl: SSL bilgilerini kontrol et
            
        Returns:
            Tüm tarama sonuçları dictionary'si
        """
        print(f"\n[*] IP adresinden domainler bulunuyor: {ip}")
        print("=" * 60)
        
        # Tüm domainleri bul (Reverse DNS + SSL sertifikaları + HTTP)
        print(f"\n[*] IP adresindeki tum domainler araniyor...")
        print(f"[*] Yontemler: Reverse DNS, SSL sertifikalari (SAN), HTTP Host header")
        domains = self.find_all_domains_for_ip(ip)
        
        if not domains:
            print(f"[-] Domain bulunamadi")
            print(f"[*] IP adresi direkt kullanilacak: {ip}")
            # IP'yi domain olarak kullanma, direkt IP ile tarama yap
            domains = []  # Boş bırak, aşağıda direkt IP ile tarama yapacağız
        else:
            print(f"[+] Bulunan domainler ({len(domains)} adet): {', '.join(domains)}")
        
        results = {
            'ip': ip,
            'domains_found': domains,
            'scan_results': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Eğer domain bulunamadıysa, direkt IP ile tarama yap
        if not domains:
            print(f"\n{'=' * 60}")
            print(f"[*] IP adresi direkt taranıyor: {ip}")
            print("=" * 60)
            
            ip_result = {
                'domain': None,
                'ip': ip,
                'dns_records': {},
                'open_ports': [],
                'ssl_info': {}
            }
            
            # Port tarama
            print(f"[*] Portlar taranıyor...")
            open_ports = self.scan_ports(ip, ports)
            ip_result['open_ports'] = open_ports
            
            if open_ports:
                print(f"[+] {len(open_ports)} acik port bulundu:")
                for port_info in open_ports:
                    banner_text = ""
                    if 'banner' in port_info:
                        banner_text = f" - {port_info['banner']}"
                    print(f"   - Port {port_info['port']} ({port_info['service']}){banner_text}")
            else:
                print("[-] Acik port bulunamadi")
            
            # SSL bilgilerini topla
            if check_ssl:
                print(f"\n[*] SSL bilgileri kontrol ediliyor...")
                for port_info in open_ports:
                    port = port_info['port']
                    if port in self.SSL_PORTS or port_info['service'] in ['HTTPS', 'HTTPS-Alt', 'SMTPS', 'IMAPS', 'POP3S']:
                        print(f"   Port {port} icin SSL bilgileri aliniyor...")
                        # IP için SSL bilgisi alırken domain olarak IP'yi kullan
                        ssl_info = self.get_ssl_info(ip, ip, port)
                        if ssl_info:
                            ip_result['ssl_info'][port] = ssl_info
                            
                            if 'error' not in ssl_info:
                                print(f"   [+] SSL sertifikasi bulundu")
                                
                                # Subject bilgileri
                                subject = ssl_info.get('subject', {})
                                cn = subject.get('commonName') or subject.get('CN') or 'N/A'
                                print(f"      Konu (CN): {cn}")
                                
                                # Issuer (Otorite) bilgileri
                                issuer = ssl_info.get('issuer', {})
                                org = (issuer.get('organizationName') or issuer.get('O') or 
                                      issuer.get('2.5.4.10') or 'N/A')
                                org_unit = (issuer.get('organizationalUnitName') or issuer.get('OU') or 
                                           issuer.get('2.5.4.11') or '')
                                country = (issuer.get('countryName') or issuer.get('C') or 
                                          issuer.get('2.5.4.6') or '')
                                common_name = (issuer.get('commonName') or issuer.get('CN') or 
                                              issuer.get('2.5.4.3') or '')
                                
                                issuer_text = org
                                if org_unit:
                                    issuer_text += f" ({org_unit})"
                                if common_name and common_name != org:
                                    issuer_text += f" - {common_name}"
                                if country:
                                    issuer_text += f" [{country}]"
                                print(f"      Otorite (Issuer): {issuer_text}")
                                
                                # Tarih bilgileri
                                not_after_parsed = ssl_info.get('notAfter_parsed') or ssl_info.get('notAfter') or 'N/A'
                                expires_days = ssl_info.get('expires_in_days')
                                is_expired = ssl_info.get('is_expired', False)
                                
                                print(f"      Bitis Tarihi: {not_after_parsed}")
                                if expires_days is not None:
                                    if is_expired:
                                        print(f"      [!] SERTIFIKA SURESI DOLMUS!")
                                    else:
                                        print(f"      Kalan Gun: {expires_days} gun")
                                
                                # Protokol bilgisi
                                protocol = ssl_info.get('protocol', 'N/A')
                                print(f"      Protokol: {protocol}")
                            else:
                                print(f"   [!] SSL hatasi: {ssl_info.get('error')}")
            
            results['scan_results'].append(ip_result)
            return results
        
        # Her domain için tarama yap
        for domain in domains:
            print(f"\n{'=' * 60}")
            print(f"[*] Domain taranıyor: {domain}")
            print("=" * 60)
            
            # Domain için DNS kayıtlarını topla
            print(f"\n[*] DNS kayitlari sorgulaniyor...")
            dns_records = self.get_dns_records(domain)
            
            if 'error' in dns_records:
                print(f"[-] DNS sorgulama hatasi: {dns_records['error']}")
            else:
                if dns_records.get('A'):
                    print(f"[+] A kayitlari: {', '.join(dns_records['A'])}")
                if dns_records.get('NS'):
                    print(f"[+] NS kayitlari: {', '.join(dns_records['NS'])}")
            
            # IP adreslerini al (DNS'den veya direkt IP kullan)
            # ÖNEMLİ: DNS'den gelen IP'ler verilen IP ile eşleşmeli
            dns_ips = dns_records.get('A', []) if dns_records.get('A') else []
            
            # DNS'den gelen IP'ler verilen IP ile eşleşiyor mu kontrol et
            if dns_ips and ip in dns_ips:
                # DNS'den gelen IP'ler doğru, kullan
                ip_addresses = dns_ips
            elif dns_ips:
                # DNS'den farklı IP'ler geldi, verilen IP'yi kullan
                print(f"[!] DNS'den farkli IP'ler geldi: {', '.join(dns_ips)}")
                print(f"[!] Verilen IP kullaniliyor: {ip}")
                ip_addresses = [ip]
            else:
                # DNS'den IP gelmedi, verilen IP'yi kullan
                ip_addresses = [ip]
            
            # Her IP için port tarama
            for scan_ip in ip_addresses:
                print(f"\n[*] IP adresi taranıyor: {scan_ip}")
                print("-" * 60)
                
                ip_result = {
                    'domain': domain,
                    'ip': scan_ip,
                    'dns_records': dns_records,
                    'open_ports': [],
                    'ssl_info': {}
                }
                
                # Port tarama
                print(f"[*] Portlar taranıyor...")
                open_ports = self.scan_ports(scan_ip, ports)
                ip_result['open_ports'] = open_ports
                
                if open_ports:
                    print(f"[+] {len(open_ports)} acik port bulundu:")
                    for port_info in open_ports:
                        banner_text = ""
                        if 'banner' in port_info:
                            banner_text = f" - {port_info['banner']}"
                        print(f"   - Port {port_info['port']} ({port_info['service']}){banner_text}")
                else:
                    print("[-] Acik port bulunamadi")
                
                # SSL bilgilerini topla
                if check_ssl:
                    print(f"\n[*] SSL bilgileri kontrol ediliyor...")
                    for port_info in open_ports:
                        port = port_info['port']
                        if port in self.SSL_PORTS or port_info['service'] in ['HTTPS', 'HTTPS-Alt', 'SMTPS', 'IMAPS', 'POP3S']:
                            print(f"   Port {port} icin SSL bilgileri aliniyor...")
                            ssl_info = self.get_ssl_info(domain, scan_ip, port)
                            if ssl_info:
                                ip_result['ssl_info'][port] = ssl_info
                                
                                if 'error' not in ssl_info:
                                    print(f"   [+] SSL sertifikasi bulundu")
                                    
                                    # Subject bilgileri
                                    subject = ssl_info.get('subject', {})
                                    cn = subject.get('commonName') or subject.get('CN') or 'N/A'
                                    print(f"      Konu (CN): {cn}")
                                    
                                    # Issuer (Otorite) bilgileri
                                    issuer = ssl_info.get('issuer', {})
                                    org = (issuer.get('organizationName') or issuer.get('O') or 
                                          issuer.get('2.5.4.10') or 'N/A')
                                    org_unit = (issuer.get('organizationalUnitName') or issuer.get('OU') or 
                                               issuer.get('2.5.4.11') or '')
                                    country = (issuer.get('countryName') or issuer.get('C') or 
                                              issuer.get('2.5.4.6') or '')
                                    common_name = (issuer.get('commonName') or issuer.get('CN') or 
                                                  issuer.get('2.5.4.3') or '')
                                    
                                    issuer_text = org
                                    if org_unit:
                                        issuer_text += f" ({org_unit})"
                                    if common_name and common_name != org:
                                        issuer_text += f" - {common_name}"
                                    if country:
                                        issuer_text += f" [{country}]"
                                    print(f"      Otorite (Issuer): {issuer_text}")
                                    
                                    # Tarih bilgileri
                                    not_after_parsed = ssl_info.get('notAfter_parsed') or ssl_info.get('notAfter') or 'N/A'
                                    expires_days = ssl_info.get('expires_in_days')
                                    is_expired = ssl_info.get('is_expired', False)
                                    
                                    print(f"      Bitis Tarihi: {not_after_parsed}")
                                    if expires_days is not None:
                                        if is_expired:
                                            print(f"      [!] SERTIFIKA SURESI DOLMUS!")
                                        else:
                                            print(f"      Kalan Gun: {expires_days} gun")
                                    
                                    # Protokol bilgisi
                                    protocol = ssl_info.get('protocol', 'N/A')
                                    print(f"      Protokol: {protocol}")
                                else:
                                    print(f"   [!] SSL hatasi: {ssl_info.get('error')}")
                
                results['scan_results'].append(ip_result)
        
        return results
    
    def scan_domain(self, domain: str, ports: List[int] = None, check_ssl: bool = True) -> Dict:
        """
        Domain'i tarar, IP'leri bulur, portları tarar ve SSL bilgilerini toplar
        
        Args:
            domain: Taranacak domain
            ports: Taranacak port listesi (None ise yaygın portlar)
            check_ssl: SSL bilgilerini kontrol et
            
        Returns:
            Tüm tarama sonuçları dictionary'si
        """
        print(f"\n[*] Domain taranıyor: {domain}")
        print("=" * 60)
        
        # Domain'den IP çözümleme
        print(f"\n[*] IP adresleri cozumleniyor...")
        ip_addresses = self.resolve_domain(domain)
        
        if not ip_addresses:
            return {
                'domain': domain,
                'error': 'Domain cozumlenemedi',
                'timestamp': datetime.now().isoformat()
            }
        
        print(f"[+] Bulunan IP adresleri: {', '.join(ip_addresses)}")
        
        # DNS kayıtlarını topla
        print(f"\n[*] DNS kayitlari sorgulaniyor...")
        dns_records = self.get_dns_records(domain)
        
        if 'error' in dns_records:
            print(f"[-] DNS sorgulama hatasi: {dns_records['error']}")
        else:
            if dns_records.get('A'):
                print(f"[+] A kayitlari: {', '.join(dns_records['A'])}")
            if dns_records.get('AAAA'):
                print(f"[+] AAAA kayitlari: {', '.join(dns_records['AAAA'])}")
            if dns_records.get('NS'):
                print(f"[+] NS kayitlari: {', '.join(dns_records['NS'])}")
            if dns_records.get('MX'):
                mx_list = [f"{mx['host']} (pri:{mx['priority']})" for mx in dns_records['MX']]
                print(f"[+] MX kayitlari: {', '.join(mx_list)}")
            if dns_records.get('TXT'):
                print(f"[+] TXT kayitlari: {len(dns_records['TXT'])} adet")
            if dns_records.get('SPF'):
                print(f"[+] SPF kayitlari: {len(dns_records['SPF'])} adet")
            if dns_records.get('CNAME'):
                print(f"[+] CNAME kayitlari: {', '.join(dns_records['CNAME'])}")
            if dns_records.get('PTR'):
                print(f"[+] PTR kayitlari: {len(dns_records['PTR'])} adet")
        
        results = {
            'domain': domain,
            'ip_addresses': ip_addresses,
            'dns_records': dns_records,
            'scan_results': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Her IP için port tarama
        for ip in ip_addresses:
            print(f"\n[*] IP adresi taranıyor: {ip}")
            print("-" * 60)
            
            ip_result = {
                'ip': ip,
                'open_ports': [],
                'ssl_info': {}
            }
            
            # Port tarama
            print(f"[*] Portlar taranıyor...")
            open_ports = self.scan_ports(ip, ports)
            ip_result['open_ports'] = open_ports
            
            if open_ports:
                print(f"[+] {len(open_ports)} acik port bulundu:")
                for port_info in open_ports:
                    banner_text = ""
                    if 'banner' in port_info:
                        banner_text = f" - {port_info['banner']}"
                    print(f"   - Port {port_info['port']} ({port_info['service']}){banner_text}")
            else:
                print("[-] Acik port bulunamadi")
            
            # SSL bilgilerini topla
            if check_ssl:
                print(f"\n[*] SSL bilgileri kontrol ediliyor...")
                for port_info in open_ports:
                    port = port_info['port']
                    if port in self.SSL_PORTS or port_info['service'] in ['HTTPS', 'HTTPS-Alt', 'SMTPS', 'IMAPS', 'POP3S']:
                        print(f"   Port {port} icin SSL bilgileri aliniyor...")
                        ssl_info = self.get_ssl_info(domain, ip, port)
                        if ssl_info:
                            ip_result['ssl_info'][port] = ssl_info
                            
                            if 'error' not in ssl_info:
                                print(f"   [+] SSL sertifikasi bulundu")
                                
                                # Subject bilgileri
                                subject = ssl_info.get('subject', {})
                                cn = subject.get('commonName') or subject.get('CN') or 'N/A'
                                print(f"      Konu (CN): {cn}")
                                
                                # Issuer (Otorite) bilgileri
                                issuer = ssl_info.get('issuer', {})
                                # Farklı OID isimlerini kontrol et
                                org = (issuer.get('organizationName') or issuer.get('O') or 
                                      issuer.get('2.5.4.10') or 'N/A')
                                org_unit = (issuer.get('organizationalUnitName') or issuer.get('OU') or 
                                           issuer.get('2.5.4.11') or '')
                                country = (issuer.get('countryName') or issuer.get('C') or 
                                          issuer.get('2.5.4.6') or '')
                                common_name = (issuer.get('commonName') or issuer.get('CN') or 
                                              issuer.get('2.5.4.3') or '')
                                
                                issuer_text = org
                                if org_unit:
                                    issuer_text += f" ({org_unit})"
                                if common_name and common_name != org:
                                    issuer_text += f" - {common_name}"
                                if country:
                                    issuer_text += f" [{country}]"
                                print(f"      Otorite (Issuer): {issuer_text}")
                                
                                # Tarih bilgileri
                                not_after_parsed = ssl_info.get('notAfter_parsed') or ssl_info.get('notAfter') or 'N/A'
                                expires_days = ssl_info.get('expires_in_days')
                                is_expired = ssl_info.get('is_expired', False)
                                
                                print(f"      Bitis Tarihi: {not_after_parsed}")
                                if expires_days is not None:
                                    if is_expired:
                                        print(f"      [!] SERTIFIKA SURESI DOLMUS!")
                                    else:
                                        print(f"      Kalan Gun: {expires_days} gun")
                                
                                # Protokol bilgisi
                                protocol = ssl_info.get('protocol', 'N/A')
                                print(f"      Protokol: {protocol}")
                            else:
                                print(f"   [!] SSL hatasi: {ssl_info.get('error')}")
            
            results['scan_results'].append(ip_result)
        
        return results
    
    def discover_subdomains(self, domain: str, wordlist: List[str] = None, passive: bool = True) -> List[str]:
        """
        Subdomain keşfi yapar (subfinder + amass alternatifi)
        
        Args:
            domain: Ana domain (örn: example.com)
            wordlist: Subdomain wordlist (None ise varsayılan wordlist kullanılır)
            passive: Passive enumeration yapılsın mı (True: sadece passive, False: DNS brute force da yap)
            
        Returns:
            Bulunan subdomain listesi
        """
        print(f"\n[*] Subdomain keşfi başlatılıyor: {domain}")
        print("=" * 60)
        
        subdomains = set()
        
        # 1. Certificate Transparency Logs (crt.sh) - Passive
        if passive:
            print(f"[*] Certificate Transparency Logs taranıyor (crt.sh)...")
            ct_subdomains = self._get_subdomains_from_ct(domain)
            subdomains.update(ct_subdomains)
            print(f"[+] crt.sh: {len(ct_subdomains)} subdomain bulundu")
        
        # 2. DNS Zone Transfer denemesi - Passive
        if passive:
            print(f"[*] DNS Zone Transfer deneniyor...")
            axfr_subdomains = self._try_dns_zone_transfer(domain)
            if axfr_subdomains:
                subdomains.update(axfr_subdomains)
                print(f"[+] DNS Zone Transfer: {len(axfr_subdomains)} subdomain bulundu")
        
        # 3. DNS Brute Force (wordlist ile) - Active
        if not passive and wordlist:
            print(f"[*] DNS Brute Force başlatılıyor ({len(wordlist)} kelime)...")
            brute_subdomains = self._dns_brute_force(domain, wordlist)
            subdomains.update(brute_subdomains)
            print(f"[+] DNS Brute Force: {len(brute_subdomains)} subdomain bulundu")
        elif not passive:
            # Varsayılan wordlist kullan
            default_wordlist = self._get_default_subdomain_wordlist()
            print(f"[*] DNS Brute Force başlatılıyor (varsayılan wordlist: {len(default_wordlist)} kelime)...")
            brute_subdomains = self._dns_brute_force(domain, default_wordlist)
            subdomains.update(brute_subdomains)
            print(f"[+] DNS Brute Force: {len(brute_subdomains)} subdomain bulundu")
        
        # 4. SSL Certificate SAN parsing - Passive
        if passive:
            print(f"[*] SSL sertifikalarından subdomainler aranıyor...")
            ssl_subdomains = self._get_subdomains_from_ssl(domain)
            subdomains.update(ssl_subdomains)
            print(f"[+] SSL sertifikaları: {len(ssl_subdomains)} subdomain bulundu")
        
        # 5. Search Engine queries (Google, Bing) - Passive
        if passive:
            print(f"[*] Arama motorlarından subdomainler aranıyor...")
            search_subdomains = self._get_subdomains_from_search_engines(domain)
            subdomains.update(search_subdomains)
            print(f"[+] Arama motorları: {len(search_subdomains)} subdomain bulundu")
        
        # Tekrarları kaldır ve sırala
        unique_subdomains = sorted(list(subdomains))
        print(f"\n[+] Toplam {len(unique_subdomains)} benzersiz subdomain bulundu")
        
        return unique_subdomains
    
    def _get_subdomains_from_ct(self, domain: str) -> List[str]:
        """Certificate Transparency Logs'dan subdomainleri bulur"""
        subdomains = []
        try:
            import urllib.request
            import urllib.parse
            
            # crt.sh API
            url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
            
            with urllib.request.urlopen(req, timeout=10.0) as response:
                data = response.read().decode('utf-8')
                try:
                    entries = json.loads(data)
                    if isinstance(entries, list):
                        for entry in entries:
                            name_value = entry.get('name_value', '')
                            common_name = entry.get('common_name', '')
                            
                            # name_value'den subdomainleri çıkar
                            if name_value:
                                for separator in ['\n', ',', ' ', ';']:
                                    if separator in name_value:
                                        for d in name_value.split(separator):
                                            d = d.strip()
                                            if d and d.endswith(f'.{domain}') and d != domain:
                                                if d.startswith('*.'):
                                                    d = d[2:]
                                                if d not in subdomains:
                                                    subdomains.append(d)
                                        break
                                else:
                                    d = name_value.strip()
                                    if d and d.endswith(f'.{domain}') and d != domain:
                                        if d.startswith('*.'):
                                            d = d[2:]
                                        if d not in subdomains:
                                            subdomains.append(d)
                            
                            # common_name'den subdomain al
                            if common_name and common_name.endswith(f'.{domain}') and common_name != domain:
                                if common_name.startswith('*.'):
                                    common_name = common_name[2:]
                                if common_name not in subdomains:
                                    subdomains.append(common_name)
                except:
                    pass
        except:
            pass
        
        return subdomains
    
    def _try_dns_zone_transfer(self, domain: str) -> List[str]:
        """DNS Zone Transfer denemesi yapar"""
        subdomains = []
        if not DNS_AVAILABLE:
            return subdomains
        
        try:
            # NS kayıtlarını al
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns_record in ns_records:
                ns_server = str(ns_record).rstrip('.')
                try:
                    # Zone transfer dene
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
                    for name, node in zone.nodes.items():
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            if rdataset.rdtype == dns.rdatatype.A or rdataset.rdtype == dns.rdatatype.AAAA:
                                subdomain = str(name) + '.' + domain if name else domain
                                if subdomain not in subdomains:
                                    subdomains.append(subdomain)
                except:
                    pass
        except:
            pass
        
        return subdomains
    
    def _dns_brute_force(self, domain: str, wordlist: List[str]) -> List[str]:
        """DNS brute force ile subdomainleri bulur"""
        subdomains = []
        if not DNS_AVAILABLE:
            return subdomains
        
        def check_subdomain(subdomain: str) -> Optional[str]:
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                if answers:
                    return subdomain
            except:
                pass
            return None
        
        # ThreadPoolExecutor ile paralel DNS sorguları
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for word in wordlist:
                subdomain = f"{word}.{domain}"
                futures.append(executor.submit(check_subdomain, subdomain))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subdomains.append(result)
        
        return subdomains
    
    def _get_subdomains_from_ssl(self, domain: str) -> List[str]:
        """SSL sertifikalarından subdomainleri bulur"""
        subdomains = []
        if not DNS_AVAILABLE:
            return subdomains
        
        try:
            # Domain'in IP'sini al
            ip_addresses = self.resolve_domain(domain)
            if not ip_addresses:
                return subdomains
            
            ip = ip_addresses[0]
            
            # SSL portlarında sertifikaları kontrol et
            ssl_ports = [443, 8443]
            for port in ssl_ports:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((ip, port), timeout=2.0) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert(binary_form=True)
                            if cert:
                                cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                                
                                # SAN'dan subdomainleri al
                                try:
                                    san_ext = cert_obj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                    for name in san_ext.value:
                                        if isinstance(name, x509.DNSName):
                                            d = name.value
                                            if d.endswith(f'.{domain}') and d != domain:
                                                if d.startswith('*.'):
                                                    d = d[2:]
                                                if d not in subdomains:
                                                    subdomains.append(d)
                                except:
                                    pass
                                
                                # CN'den subdomain al
                                try:
                                    cn = cert_obj.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
                                    if cn.endswith(f'.{domain}') and cn != domain:
                                        if cn.startswith('*.'):
                                            cn = cn[2:]
                                        if cn not in subdomains:
                                            subdomains.append(cn)
                                except:
                                    pass
                except:
                    pass
        except:
            pass
        
        return subdomains
    
    def _get_subdomains_from_search_engines(self, domain: str) -> List[str]:
        """Arama motorlarından subdomainleri bulur (Google, Bing)"""
        subdomains = []
        # Not: Arama motorları API'si gerektirir veya scraping yapılması gerekir
        # Bu özellik şimdilik basit bir implementasyon
        # Gerçek implementasyon için API key'ler veya scraping gerekir
        return subdomains
    
    def _get_default_subdomain_wordlist(self) -> List[str]:
        """Varsayılan subdomain wordlist'i döndürür"""
        return [
            'www', 'mail', 'webmail', 'email', 'smtp', 'pop', 'imap', 'pop3', 'imap4',
            'ftp', 'sftp', 'admin', 'administrator', 'panel', 'cpanel', 'whm', 'plesk',
            'web', 'blog', 'shop', 'store', 'ecommerce', 'api', 'app', 'apps',
            'mobile', 'm', 'old', 'new', 'test', 'testing', 'dev', 'development',
            'staging', 'stage', 'preview', 'demo', 'demo2', 'demo3',
            'ns1', 'ns2', 'dns', 'ns', 'ns3', 'ns4',
            'cdn', 'static', 'assets', 'media', 'images', 'img', 'files', 'file',
            'secure', 'ssl', 'vpn', 'remote', 'access',
            'db', 'database', 'mysql', 'postgres', 'mongo',
            'backup', 'backups', 'archive', 'old-site', 'legacy',
            'www2', 'www3', 'www4', 'www5', 'www6',
            'mail2', 'mail3', 'webmail2', 'webmail3',
            'api2', 'api3', 'app2', 'app3',
            'test2', 'test3', 'dev2', 'dev3',
            'staging2', 'staging3', 'preview2', 'preview3',
            'admin2', 'admin3', 'panel2', 'panel3',
            'web2', 'web3', 'blog2', 'blog3',
            'shop2', 'shop3', 'store2', 'store3',
            'secure2', 'secure3', 'ssl2', 'ssl3',
            'cdn2', 'cdn3', 'static2', 'static3',
            'backup2', 'backup3', 'archive2', 'archive3'
        ]
    
    def check_live_subdomains(self, subdomains: List[str], ports: List[int] = None, timeout: float = 3.0) -> List[Dict]:
        """
        Canlı subdomainleri test eder (httpx alternatifi)
        
        Args:
            subdomains: Test edilecek subdomain listesi
            ports: Test edilecek portlar (None ise [80, 443])
            timeout: Timeout süresi
            
        Returns:
            Canlı subdomainler ve detayları
        """
        if ports is None:
            ports = [80, 443]
        
        print(f"\n[*] Canlı subdomainler test ediliyor ({len(subdomains)} subdomain, {len(ports)} port)...")
        print("=" * 60)
        
        live_subdomains = []
        
        def check_subdomain(subdomain: str) -> Optional[Dict]:
            """Bir subdomain'i test eder"""
            result = {
                'subdomain': subdomain,
                'status': 'dead',
                'ports': [],
                'status_codes': {},
                'title': None,
                'server': None
            }
            
            # DNS çözümleme
            try:
                if DNS_AVAILABLE:
                    answers = dns.resolver.resolve(subdomain, 'A')
                    ips = [str(rdata) for rdata in answers]
                    result['ips'] = ips
                else:
                    # DNS kütüphanesi yoksa socket ile dene
                    ip = socket.gethostbyname(subdomain)
                    result['ips'] = [ip]
            except:
                return None  # DNS çözümlenemiyorsa ölü
            
            # Portları test et
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result_code = sock.connect_ex((result['ips'][0], port))
                    sock.close()
                    
                    if result_code == 0:
                        result['ports'].append(port)
                        result['status'] = 'alive'
                        
                        # HTTP/HTTPS yanıtını al
                        if port in [80, 443]:
                            try:
                                protocol = 'https' if port == 443 else 'http'
                                url = f"{protocol}://{subdomain}"
                                
                                import urllib.request
                                req = urllib.request.Request(url)
                                req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
                                
                                with urllib.request.urlopen(req, timeout=timeout) as response:
                                    result['status_codes'][port] = response.getcode()
                                    
                                    # Server header
                                    server = response.headers.get('Server', '')
                                    if server:
                                        result['server'] = server
                                    
                                    # Title (basit parsing)
                                    try:
                                        html = response.read().decode('utf-8', errors='ignore')
                                        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                                        if title_match:
                                            result['title'] = title_match.group(1).strip()[:100]
                                    except:
                                        pass
                            except:
                                pass
                except:
                    pass
            
            if result['status'] == 'alive':
                return result
            return None
        
        # Paralel test
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in subdomains}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    live_subdomains.append(result)
                    print(f"[+] {result['subdomain']} - Portlar: {', '.join(map(str, result['ports']))} - IP: {', '.join(result['ips'])}")
        
        print(f"\n[+] Toplam {len(live_subdomains)} canlı subdomain bulundu")
        
        return live_subdomains
    
    def generate_report(self, results: Dict, output_format: str = 'json', output_file: str = None):
        """
        Tarama sonuçlarını rapor olarak oluşturur
        
        Args:
            results: Tarama sonuçları
            output_format: Çıktı formatı ('json', 'text')
            output_file: Çıktı dosyası (None ise konsola yazdır)
        """
        if output_format == 'json':
            report = json.dumps(results, indent=2, ensure_ascii=False)
        else:  # text format
            report_lines = []
            report_lines.append("=" * 60)
            report_lines.append("DOMAIN PORT SSL TARAMA RAPORU")
            report_lines.append("=" * 60)
            
            # IP'den başlayan tarama mı domain'den mi kontrol et
            if 'ip' in results:
                # IP'den başlayan tarama
                report_lines.append(f"\nIP Adresi: {results['ip']}")
                report_lines.append(f"Tarih: {results['timestamp']}")
                if results.get('domains_found'):
                    report_lines.append(f"Bulunan Domainler: {', '.join(results['domains_found'])}")
            else:
                # Domain'den başlayan tarama
                report_lines.append(f"\nDomain: {results.get('domain', 'N/A')}")
                report_lines.append(f"Tarih: {results['timestamp']}")
                report_lines.append(f"IP Adresleri: {', '.join(results.get('ip_addresses', []))}")
            
            # DNS kayıtları
            dns_records = results.get('dns_records', {})
            if dns_records and 'error' not in dns_records:
                report_lines.append(f"\n{'=' * 60}")
                report_lines.append("DNS KAYITLARI")
                report_lines.append(f"{'-' * 60}")
                
                # A kayıtları
                if dns_records.get('A'):
                    report_lines.append(f"\nA Kayıtları (IPv4):")
                    for a_record in dns_records['A']:
                        report_lines.append(f"  • {a_record}")
                
                # AAAA kayıtları
                if dns_records.get('AAAA'):
                    report_lines.append(f"\nAAAA Kayıtları (IPv6):")
                    for aaaa_record in dns_records['AAAA']:
                        report_lines.append(f"  • {aaaa_record}")
                
                # NS kayıtları
                if dns_records.get('NS'):
                    report_lines.append(f"\nNS Kayıtları (Name Server):")
                    for ns_record in dns_records['NS']:
                        report_lines.append(f"  • {ns_record}")
                
                # MX kayıtları
                if dns_records.get('MX'):
                    report_lines.append(f"\nMX Kayıtları (Mail Exchange):")
                    for mx_record in dns_records['MX']:
                        report_lines.append(f"  • {mx_record['host']} (Öncelik: {mx_record['priority']})")
                
                # TXT kayıtları
                if dns_records.get('TXT'):
                    report_lines.append(f"\nTXT Kayıtları:")
                    for txt_record in dns_records['TXT']:
                        # Uzun TXT kayıtlarını kısalt
                        txt_display = txt_record[:200] + "..." if len(txt_record) > 200 else txt_record
                        report_lines.append(f"  • {txt_display}")
                
                # SPF kayıtları
                if dns_records.get('SPF'):
                    report_lines.append(f"\nSPF Kayıtları:")
                    for spf_record in dns_records['SPF']:
                        spf_display = spf_record[:200] + "..." if len(spf_record) > 200 else spf_record
                        report_lines.append(f"  • {spf_display}")
                
                # CNAME kayıtları
                if dns_records.get('CNAME'):
                    report_lines.append(f"\nCNAME Kayıtları:")
                    for cname_record in dns_records['CNAME']:
                        report_lines.append(f"  • {cname_record}")
                
                # PTR kayıtları
                if dns_records.get('PTR'):
                    report_lines.append(f"\nPTR Kayıtları (Reverse DNS):")
                    for ptr_record in dns_records['PTR']:
                        report_lines.append(f"  • {ptr_record['ip']} -> {ptr_record.get('hostname', 'N/A')}")
            elif dns_records and 'error' in dns_records:
                report_lines.append(f"\nDNS Sorgulama Hatası: {dns_records['error']}")
            
            if 'error' in results:
                report_lines.append(f"\n[-] Hata: {results['error']}")
            else:
                for ip_result in results.get('scan_results', []):
                    report_lines.append(f"\n{'=' * 60}")
                    report_lines.append(f"IP Adresi: {ip_result['ip']}")
                    report_lines.append(f"{'-' * 60}")
                    
                    # Açık portlar
                    if ip_result['open_ports']:
                        report_lines.append(f"\nAçık Portlar ({len(ip_result['open_ports'])}):")
                        for port_info in ip_result['open_ports']:
                            banner_text = ""
                            if 'banner' in port_info:
                                banner_text = f" - {port_info['banner']}"
                            report_lines.append(f"  • Port {port_info['port']}: {port_info['service']}{banner_text}")
                    else:
                        report_lines.append("\nAçık port bulunamadı")
                    
                    # SSL bilgileri
                    if ip_result.get('ssl_info'):
                        report_lines.append(f"\nSSL Bilgileri:")
                        for port, ssl_info in ip_result['ssl_info'].items():
                            report_lines.append(f"\n  Port {port}:")
                            if 'error' in ssl_info:
                                report_lines.append(f"    [-] Hata: {ssl_info['error']}")
                            else:
                                # Subject bilgileri
                                subject = ssl_info.get('subject', {})
                                cn = subject.get('commonName') or subject.get('CN') or 'N/A'
                                report_lines.append(f"    Konu (CN): {cn}")
                                
                                # Issuer (Otorite) bilgileri
                                issuer = ssl_info.get('issuer', {})
                                # Farklı OID isimlerini kontrol et
                                org = (issuer.get('organizationName') or issuer.get('O') or 
                                      issuer.get('2.5.4.10') or 'N/A')
                                org_unit = (issuer.get('organizationalUnitName') or issuer.get('OU') or 
                                           issuer.get('2.5.4.11') or '')
                                country = (issuer.get('countryName') or issuer.get('C') or 
                                          issuer.get('2.5.4.6') or '')
                                common_name = (issuer.get('commonName') or issuer.get('CN') or 
                                              issuer.get('2.5.4.3') or '')
                                
                                issuer_text = org
                                if org_unit:
                                    issuer_text += f" ({org_unit})"
                                if common_name and common_name != org:
                                    issuer_text += f" - {common_name}"
                                if country:
                                    issuer_text += f" [{country}]"
                                report_lines.append(f"    Otorite (Issuer): {issuer_text}")
                                
                                # Tarih bilgileri
                                not_before = ssl_info.get('notBefore_parsed') or ssl_info.get('notBefore') or 'N/A'
                                not_after = ssl_info.get('notAfter_parsed') or ssl_info.get('notAfter') or 'N/A'
                                expires_days = ssl_info.get('expires_in_days')
                                is_expired = ssl_info.get('is_expired', False)
                                
                                report_lines.append(f"    Başlangıç: {not_before}")
                                report_lines.append(f"    Bitiş: {not_after}")
                                if expires_days is not None:
                                    if is_expired:
                                        report_lines.append(f"    [!] SERTIFIKA SURESI DOLMUS!")
                                    else:
                                        report_lines.append(f"    Kalan Gün: {expires_days} gün")
                                
                                # Protokol ve cipher bilgisi
                                protocol = ssl_info.get('protocol', 'N/A')
                                cipher = ssl_info.get('cipher')
                                report_lines.append(f"    Protokol: {protocol}")
                                if cipher:
                                    report_lines.append(f"    Cipher: {cipher[0]} ({cipher[1]})")
            
            report = '\n'.join(report_lines)
        
        # Çıktı
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n[+] Rapor kaydedildi: {output_file}")
        else:
            print("\n" + "=" * 60)
            print("RAPOR")
            print("=" * 60)
            print(report)


def main():
    """Ana fonksiyon"""
    # Banner'ı göster
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='ReconScope - Comprehensive Reconnaissance and Security Scanning Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Örnekler:{Colors.RESET}
  {Colors.GREEN}# Normal tarama{Colors.RESET}
  python reconscope.py example.com
  python reconscope.py 192.168.1.1
  python reconscope.py example.com --ports 80 443 8080
  python reconscope.py 192.168.1.1 --ports 80 443
  python reconscope.py example.com --format text --output rapor.txt
  python reconscope.py example.com --no-ssl
  python reconscope.py 192.168.1.1 --reverse-dns
  
  {Colors.GREEN}# Subdomain keşfi (subfinder + amass alternatifi){Colors.RESET}
  python reconscope.py example.com --subdomains
  python reconscope.py example.com --subdomains --passive
  python reconscope.py example.com --subdomains --active --wordlist wordlist.txt
  python reconscope.py example.com --subdomains --subdomain-output subdomains.txt
  
  {Colors.GREEN}# Subdomain keşfi + canlı test (httpx alternatifi){Colors.RESET}
  python reconscope.py example.com --subdomains --check-live
  python reconscope.py example.com --subdomains --check-live --subdomain-output sub.txt --live-output live.txt
        """
    )
    
    parser.add_argument('target', help='Taranacak domain adı veya IP adresi')
    parser.add_argument('--ports', '-p', nargs='+', type=int, 
                       help='Taranacak port listesi (varsayılan: 1-10000 arası tüm portlar)')
    parser.add_argument('--timeout', '-t', type=float, default=3.0,
                       help='Port bağlantı timeout süresi (saniye, varsayılan: 3.0)')
    parser.add_argument('--format', '-f', choices=['json', 'text'], default='text',
                       help='Rapor formatı (varsayılan: text)')
    parser.add_argument('--output', '-o', type=str,
                       help='Rapor çıktı dosyası (varsayılan: konsol)')
    parser.add_argument('--no-ssl', action='store_true',
                       help='SSL bilgilerini kontrol etme')
    parser.add_argument('--workers', type=int, default=50,
                       help='Eşzamanlı port tarama thread sayısı (varsayılan: 50)')
    parser.add_argument('--reverse-dns', '-r', action='store_true',
                       help='IP adresi verildiğinde reverse DNS ile domainleri bul ve tara (varsayılan: aktif)')
    
    # Subdomain keşfi argümanları
    parser.add_argument('--subdomains', '-s', action='store_true',
                       help='Subdomain keşfi yap (subfinder + amass alternatifi)')
    parser.add_argument('--passive', action='store_true', default=True,
                       help='Passive enumeration yap (varsayılan: True, DNS brute force yapmaz)')
    parser.add_argument('--active', action='store_true',
                       help='Active enumeration yap (DNS brute force dahil)')
    parser.add_argument('--wordlist', type=str,
                       help='Subdomain wordlist dosyası (her satırda bir kelime)')
    parser.add_argument('--check-live', '-l', action='store_true',
                       help='Bulunan subdomainlerin canlı olup olmadığını test et (httpx alternatifi)')
    parser.add_argument('--subdomain-output', type=str,
                       help='Subdomain listesi çıktı dosyası')
    parser.add_argument('--live-output', type=str,
                       help='Canlı subdomain listesi çıktı dosyası')
    
    args = parser.parse_args()
    
    # IP adresi mi domain mi kontrol et
    def is_ip_address(address: str) -> bool:
        """Bir string'in IP adresi olup olmadığını kontrol eder"""
        try:
            parts = address.split('.')
            if len(parts) == 4:
                return all(0 <= int(part) <= 255 for part in parts if part.isdigit())
        except:
            pass
        return False
    
    # Scanner oluştur
    scanner = DomainPortSSLScanner(timeout=args.timeout, max_workers=args.workers)
    
    # Subdomain keşfi
    if args.subdomains and not is_ip_address(args.target):
        start_time = time.time()
        
        # Wordlist yükle
        wordlist = None
        if args.wordlist:
            try:
                with open(args.wordlist, 'r', encoding='utf-8') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                print(f"[*] Wordlist yuklendi: {len(wordlist)} kelime")
            except Exception as e:
                print(f"[!] Wordlist yuklenemedi: {e}")
        
        # Passive/Active mod
        passive = args.passive and not args.active
        
        # Subdomain keşfi
        subdomains = scanner.discover_subdomains(args.target, wordlist=wordlist, passive=passive)
        
        # Subdomain listesini kaydet
        if args.subdomain_output:
            with open(args.subdomain_output, 'w', encoding='utf-8') as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
            print(f"[+] Subdomain listesi kaydedildi: {args.subdomain_output}")
        elif subdomains:
            print(f"\n[*] Bulunan subdomainler:")
            for subdomain in subdomains:
                print(f"  {subdomain}")
        
        # Canlı subdomain testi
        if args.check_live and subdomains:
            live_subdomains = scanner.check_live_subdomains(subdomains, ports=args.ports, timeout=args.timeout)
            
            # Canlı subdomain listesini kaydet
            if args.live_output:
                with open(args.live_output, 'w', encoding='utf-8') as f:
                    for result in live_subdomains:
                        f.write(f"{result['subdomain']}\n")
                print(f"[+] Canlı subdomain listesi kaydedildi: {args.live_output}")
            
            # JSON formatında detaylı rapor
            if args.format == 'json' and args.output:
                live_results = {
                    'domain': args.target,
                    'total_subdomains': len(subdomains),
                    'live_subdomains': len(live_subdomains),
                    'live_details': live_subdomains,
                    'timestamp': datetime.now().isoformat()
                }
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(live_results, f, indent=2, ensure_ascii=False)
        
        elapsed_time = time.time() - start_time
        print(f"\n[*] Subdomain keşfi suresi: {elapsed_time:.2f} saniye")
        print("=" * 60)
        return
    
    # Normal tarama
    start_time = time.time()
    
    is_ip = is_ip_address(args.target)
    
    # Port listesi hazırla
    ports_to_scan = args.ports
    if ports_to_scan is None:
        # Varsayılan: İlk 10000 port (1-10000)
        ports_to_scan = list(range(1, 10001))
        print(f"[*] Port araligi: 1-10000 (toplam {len(ports_to_scan)} port)")
    
    if is_ip:
        # IP adresi verilmiş
        if args.reverse_dns or True:  # Varsayılan olarak reverse DNS aktif
            results = scanner.scan_from_ip(args.target, ports=ports_to_scan, check_ssl=not args.no_ssl)
        else:
            # Sadece IP için tarama (domain bulmadan)
            results = scanner.scan_domain(args.target, ports=ports_to_scan, check_ssl=not args.no_ssl)
    else:
        # Domain verilmiş
        results = scanner.scan_domain(args.target, ports=ports_to_scan, check_ssl=not args.no_ssl)
    
    elapsed_time = time.time() - start_time
    
    # Rapor oluştur
    scanner.generate_report(results, output_format=args.format, output_file=args.output)
    
    print(f"\n[*] Tarama suresi: {elapsed_time:.2f} saniye")
    print("=" * 60)


if __name__ == '__main__':
    main()
