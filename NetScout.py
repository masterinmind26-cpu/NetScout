#!/usr/bin/env python
"""
NetScout v7 - rootsuz, kurulumsuz ağ analiz aracı.
  1) nmap      - port ve servis taraması (yerleşik; nmap varsa o da çalışır)
  2) masscan   - hızlı port taraması (yerleşik asenkron tarayıcı)
  3) wireshark - .pcap dosyası analizi
  4) zeek      - .pcap dosyasından bağlantı, DNS ve HTTP logları
  5) openvas   - servis sürümlerinden olası CVE'ler (NVD)
  6) HEPSİ    - tek URL/IP gir, her şey birlikte çalışsın

Termux ve Kali Linux için. Dil: --dil tr | --dil en

YALNIZCA kendi sistemlerinde veya yazılı izin verilen sistemlerde kullan.
Use ONLY on systems you own or are explicitly authorized to test.
"""

import asyncio
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import concurrent.futures as cf
import datetime
import html as htmllib
import urllib.error
from collections import Counter

SURUM = "1.0"
DIL = "tr"
DIL_SECILDI = False
ZEEK_KLASORU = "netscout_zeek"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TERS_IP_API = "https://api.hackertarget.com/reverseiplookup/?q="

ORNEK_PORTLAR = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2375, 3000, 3306, 3389, 5432, 5900, 6379, 8000,
    8080, 8443, 9200, 27017,
]
KESIF_PORTLARI = [80, 443, 22, 445, 3389, 8080]
TLS_PORTLARI = {443, 465, 993, 995, 8443}
ALT_DOMENLER = [
    "www", "mail", "ftp", "api", "dev", "test", "staging", "admin", "blog", "shop",
    "vpn", "ns1", "ns2", "smtp", "imap", "portal", "app", "cdn", "static", "git",
    "gitlab", "jenkins", "old", "beta", "webmail", "mx", "ssh", "db", "backup", "intranet",
]
EK_YOLLAR = ["/robots.txt", "/.well-known/security.txt"]
GUVENLIK_BASLIKLARI = {
    "Strict-Transport-Security": {"tr": "HSTS: yalnızca HTTPS", "en": "HSTS: HTTPS only"},
    "Content-Security-Policy": {"tr": "CSP: XSS riskini azaltır", "en": "CSP: reduces XSS risk"},
    "X-Frame-Options": {"tr": "Clickjacking'e karşı koruma", "en": "Clickjacking protection"},
    "X-Content-Type-Options": {"tr": "MIME sniffing'e karşı koruma", "en": "MIME sniffing protection"},
    "Referrer-Policy": {"tr": "Referrer bilgisinin kontrolü", "en": "Referrer control"},
    "Permissions-Policy": {"tr": "Tarayıcı özelliklerine sınırlama", "en": "Browser feature limits"},
}
DNS_TIPLERI = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
DNS_YEDEK_SUNUCULAR = ["8.8.8.8", "1.1.1.1"]

RISKLI_PORTLAR = {
    21: ("FTP", {"tr": "Şifreler düz metin gider. SFTP/FTPS kullan ya da gereksizse kapat.",
                 "en": "Passwords travel in plain text. Use SFTP/FTPS or disable it."}),
    23: ("Telnet", {"tr": "Şifreler düz metin gider. SSH'e geç ve Telnet'i kapat.",
                    "en": "Passwords travel in plain text. Switch to SSH and disable Telnet."}),
    25: ("SMTP", {"tr": "Açık relay olup olmadığını kontrol et.",
                  "en": "Check that it is not an open relay."}),
    110: ("POP3", {"tr": "Şifreleme yoksa POP3S (995) kullan.",
                   "en": "If unencrypted, use POP3S (995)."}),
    135: ("MS RPC", {"tr": "Dışarıya açık olmamalı, güvenlik duvarıyla kapat.",
                     "en": "Should not be exposed. Block it with a firewall."}),
    139: ("NetBIOS", {"tr": "Dışarıya açık olmamalı, güvenlik duvarıyla kapat.",
                      "en": "Should not be exposed. Block it with a firewall."}),
    445: ("SMB", {"tr": "Dışarıya açık olmamalı. Güncellemelerin yüklü olduğundan emin ol.",
                  "en": "Should not be exposed. Make sure updates are installed."}),
    1433: ("MSSQL", {"tr": "Veritabanı dışarıya açık olmamalı, yalnızca iç ağdan erişilmeli.",
                     "en": "Database should not be public. Allow only the internal network."}),
    1521: ("Oracle DB", {"tr": "Veritabanı dışarıya açık olmamalı.",
                         "en": "Database should not be public."}),
    2375: ("Docker API", {"tr": "Kimlik doğrulamasız Docker API çok tehlikelidir. Kapat ya da TLS ile koru.",
                          "en": "Unauthenticated Docker API is very dangerous. Disable it or protect with TLS."}),
    3306: ("MySQL", {"tr": "Veritabanı dışarıya açık olmamalı, yalnızca iç ağdan erişilmeli.",
                     "en": "Database should not be public. Allow only the internal network."}),
    3389: ("RDP", {"tr": "Uzak masaüstü dışarıya açıksa saldırı hedefi olur. VPN arkasına al.",
                   "en": "Exposed remote desktop is a common target. Put it behind a VPN."}),
    5432: ("PostgreSQL", {"tr": "Veritabanı dışarıya açık olmamalı.",
                          "en": "Database should not be public."}),
    5900: ("VNC", {"tr": "Güçlü parola ve şifreleme olmadan açık bırakma. VPN arkasına al.",
                   "en": "Do not leave open without a strong password and encryption. Use a VPN."}),
    6379: ("Redis", {"tr": "Kimlik doğrulamasız Redis dışarıya açıksa çok tehlikelidir. Erişimi kısıtla.",
                     "en": "Unauthenticated Redis exposed to the internet is very dangerous. Restrict access."}),
    9200: ("Elasticsearch", {"tr": "Kimlik doğrulaması yoksa veriler herkese açık olabilir. Güvenliği etkinleştir.",
                             "en": "Without authentication, data may be public. Enable security."}),
    27017: ("MongoDB", {"tr": "Kimlik doğrulaması yoksa veriler herkese açık olabilir. Güvenliği etkinleştir.",
                        "en": "Without authentication, data may be public. Enable security."}),
}

# Harici nmap (varsa) için seçenek düzeltmeleri
EK_RISKLI = {
    873: ("rsync", {"tr": "Dışarıya açıksa dosya modülleri listelenebilir. Erişimi kısıtla.",
                    "en": "If exposed, file modules can be listed. Restrict access."}),
    2049: ("NFS", {"tr": "Ağ dosya sistemi dışarıya açık olmamalı. Dışarıdan erişimi kapat.",
                   "en": "Network file system should not be public. Block external access."}),
    5984: ("CouchDB", {"tr": "Veritabanı dışarıya açıksa kimlik doğrulamasını etkinleştir.",
                       "en": "If the database is public, enable authentication."}),
    6443: ("Kubernetes API", {"tr": "Kubernetes API dışarıya açık olmamalı. Kimlik doğrulama ve IP kısıtı koy.",
                              "en": "Kubernetes API should not be public. Enforce authentication and IP limits."}),
    11211: ("Memcached", {"tr": "Kimlik doğrulamasız Memcached dışarıdan erişilebilirse risklidir. Kapat.",
                          "en": "Memcached without authentication is risky when reachable. Close it."}),
}
RISKLI_PORTLAR.update(EK_RISKLI)

ROOT_GEREKEN = {"-sS", "-sU", "-sY", "-sZ", "-sO", "-sI", "-sA", "-sW", "-sN", "-sF", "-sX",
                "-O", "-A", "--traceroute", "-PE", "-PP", "-PM", "-PS", "-PA", "-PU", "-PY",
                "--privileged", "--send-eth", "--send-ip"}
ROOT_DEGISTIRME = {"-sS": "-sT", "-A": "-sV -sC"}
YASAKLI_SCRIPT_PARCALARI = ("exploit", "brute", "dos", "intrusive", "malware", "fuzzer")

YERLESIK_PROFILLER = {
    "1": ({"tr": "Hızlı tarama (en sık portlar)", "en": "Quick scan (common ports)"},
          {"portlar": None, "sv": False}),
    "2": ({"tr": "Servis ve sürüm tespiti", "en": "Service and version detection"},
          {"portlar": None, "sv": True}),
    "3": ({"tr": "Tüm portlar (1-65535) + sürüm", "en": "All ports (1-65535) + versions"},
          {"portlar": "all", "sv": True}),
    "4": ({"tr": "Sadece canlı cihaz bulma", "en": "Live host discovery only"},
          {"kesif": True}),
    "5": ({"tr": "Güvenlik kontrolü (sürüm + olası CVE)", "en": "Security check (versions + possible CVEs)"},
          {"portlar": None, "sv": True, "cve": True}),
}
NMAP_HARICI_PROFILLER = {
    "1": ({"tr": "Hızlı (-F -T4)", "en": "Quick (-F -T4)"}, ["-F", "-T4"]),
    "2": ({"tr": "Servis ve sürüm (-sV)", "en": "Services and versions (-sV)"}, ["-sV", "-T4"]),
    "3": ({"tr": "Varsayılan + güvenli scriptler", "en": "Default + safe scripts"},
          ["-sV", "--script=default,safe"]),
    "4": ({"tr": "Tüm portlar + sürüm", "en": "All ports + versions"}, ["-p-", "-sV", "-T4"]),
    "5": ({"tr": "Sadece canlı host (-sn)", "en": "Host discovery only (-sn)"}, ["-sn"]),
}

BANNER = r"""
 _   _ _____ _____
| \ | | ____|_   _|
|  \| |  _|   | |
| |\  | |___  | |
|_| \_|_____| |_|
  ____   ____ ___  _   _ _____
 / ___| / ___/ _ \| | | |_   _|
 \___ \| |  | | | | | | | | |
  ___) | |__| |_| | |_| | | |
 |____/ \____\___/ \___/  |_|
"""

RENKLI = "NO_COLOR" not in os.environ
YESIL, KIRMIZI, SARI, MAVI, GRI = "1;32", "1;31", "1;33", "1;36", "0;37"
URUN_REGEX = re.compile(r"([A-Za-z][A-Za-z0-9_\-]{1,30})[/_ ]v?(\d+(?:\.\d+)+[A-Za-z0-9.\-]*)")
_AD_LABEL_RE = re.compile(r"^[A-Za-z0-9-]{1,63}$")


# ============================================================ genel yardımcılar
def iki(tr_metin, en_metin):
    return en_metin if DIL == "en" else tr_metin


def renk(metin, kod):
    if not RENKLI:
        return metin
    return f"\033[{kod}m{metin}\033[0m"


def uyari(metin):
    print(renk(f"  [!] {metin}", KIRMIZI))


def bilgi(metin):
    print(renk(f"  [*] {metin}", MAVI))


def basari(metin):
    print(renk(f"  [+] {metin}", YESIL))


def baslik(metin):
    print()
    print(renk(f"  ━━━ {metin} ━━━", MAVI))


def evet_mi(soru):
    return input(soru).strip().lower() in ("e", "y", "evet", "yes")


def temizle():
    if RENKLI:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def harici_var(komut):
    return shutil.which(komut) is not None


def hedef_coz(hedef):
    """(ip listesi, ağ mı?, hostname veya None) döndürür."""
    try:
        ag = ipaddress.ip_network(hedef, strict=False)
    except ValueError:
        try:
            ip = socket.gethostbyname(hedef)
        except OSError:
            sys.exit(iki(f"Hedef çözülemedi: {hedef}", f"Could not resolve target: {hedef}"))
        return [ip], False, hedef
    ips = [str(h) for h in ag.hosts()] or [str(ag.network_address)]
    if len(ips) > 4096:
        sys.exit(iki("Ağ çok büyük (en fazla 4096 host).", "Network too large (max 4096 hosts)."))
    return ips, ag.num_addresses > 1, None


def port_siyahisi(spec):
    if not spec:
        return ORNEK_PORTLAR
    if spec == "all":
        return list(range(1, 65536))
    try:
        secim = set()
        for parca in spec.split(","):
            parca = parca.strip()
            if not parca:
                continue
            if "-" in parca:
                a, b = parca.split("-", 1)
                secim.update(range(int(a), int(b) + 1))
            else:
                secim.add(int(parca))
    except ValueError:
        sys.exit(iki("Port formatı yanlış. Örnek: 22,80,1-1024",
                     "Wrong port format. Example: 22,80,1-1024"))
    return sorted(p for p in secim if 1 <= p <= 65535)


def ters_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def servis_adi(port):
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return "?"


def json_kaydet(yol, veri):
    with open(yol, "w", encoding="utf-8") as f:
        json.dump(veri, f, ensure_ascii=False, indent=2, default=str)
    basari(iki(f"Rapor kaydedildi: {os.path.abspath(yol)}", f"Report saved: {os.path.abspath(yol)}"))


# ============================================================ giriş animasyonu ve görünüm
LOGO_RENKLERI = ["1;32", "1;92", "1;32", "1;92", "1;32", "1;92", "1;32", "1;92"]


def giris_animasyonu():
    """Logo satır satır belirir, ardından yükleme çubuğu ve 'hazır' yazısı çıkar."""
    temizle()
    satirlar = BANNER.strip("\n").splitlines()
    for i, satir in enumerate(satirlar):
        print(renk(satir, LOGO_RENKLERI[i % len(LOGO_RENKLERI)]))
        time.sleep(0.07)
    print(renk(iki("   root gerektirmeyen ağ analiz aracı", "   rootless network analysis tool")
               + f"   v{SURUM}", "1;32"))
    print()
    cerceve = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    metin = iki("Araçlar hazırlanıyor", "Preparing tools")
    toplam = 32
    for adim in range(toplam + 1):
        dolu = "█" * adim
        bos = "░" * (toplam - adim)
        yuzde = int(adim * 100 / toplam)
        sys.stdout.write(f"\r  {renk(cerceve[adim % len(cerceve)], '1;36')} {metin} "
                         f"[{renk(dolu, '1;32')}{bos}] {yuzde:>3}%")
        sys.stdout.flush()
        time.sleep(0.035)
    sys.stdout.write("\r" + " " * 70 + "\r")
    print("  " + renk(iki("✔ Hazır!", "✔ Ready!"), "1;32"))
    time.sleep(0.4)


def logo_yazdir():
    for satir in BANNER.strip("\n").splitlines():
        print(renk(satir, "1;32"))
    print(renk(iki("   root gerektirmeyen ağ analiz aracı", "   rootless network analysis tool")
               + f"   v{SURUM}", "1;32"))
    print()


def kutu(satirlar, renkkodu=MAVI):
    en = max(len(s) for s in satirlar) + 4
    print(renk("  ┌" + "─" * en + "┐", renkkodu))
    for s in satirlar:
        print(renk("  │  ", renkkodu) + f"{s:<{en - 2}}" + renk("│", renkkodu))
    print(renk("  └" + "─" * en + "┘", renkkodu))


# ============================================================ yerleşik tarayıcı çekirdeği
async def port_durumu(host, port, timeout, sem):
    """'açık', 'red' (RST geldi, host canlı) veya 'yanıt yok' döndürür."""
    async with sem:
        try:
            _, yazici = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except ConnectionRefusedError:
            return "red"
        except Exception:
            return "yanıt yok"
        yazici.close()
        return "açık"


async def kesif_et(ips, timeout, paralel):
    sem = asyncio.Semaphore(paralel)

    async def bir_host(ip):
        try:
            for port in KESIF_PORTLARI:
                durum = await port_durumu(ip, port, timeout, sem)
                if durum != "yanıt yok":
                    ad = await asyncio.get_running_loop().run_in_executor(None, ters_dns, ip)
                    return {"ip": ip, "ad": ad, "port": port, "durum": durum}
        except Exception:
            return None
        return None

    sonuc = await asyncio.gather(*(bir_host(ip) for ip in ips))
    return [s for s in sonuc if s]


def yazdir_kesif(canlilar):
    if not canlilar:
        print("  " + iki("Canlı cihaz bulunamadı.", "No live hosts found."))
        return
    print(renk(f"  {'IP':<16}{iki('HOST ADI', 'HOSTNAME'):<36}{'PORT':<7}DURUM", MAVI))
    for c in canlilar:
        print(f"  {c['ip']:<16}{(c['ad'] or '-'):<36}{c['port']:<7}{c['durum']}")


async def banner_al(host, port, timeout):
    ctx = None
    if port in TLS_PORTLARI:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        okuyucu, yazici = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host if ctx else None),
            timeout)
    except Exception:
        return ""
    try:
        try:
            veri = await asyncio.wait_for(okuyucu.read(1024), timeout=1.5)
        except asyncio.TimeoutError:
            veri = b""
        if not veri:
            istek = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: NetScout/7.0\r\n\r\n"
            yazici.write(istek.encode())
            await yazici.drain()
            veri = await asyncio.wait_for(okuyucu.read(2048), timeout=timeout)
        return veri.decode("latin-1", errors="replace")
    except Exception:
        return ""
    finally:
        yazici.close()


def banner_tani(banner):
    satirlar = [s.strip() for s in banner.splitlines() if s.strip()]
    if not satirlar:
        return "", ""
    ilk = satirlar[0]
    if ilk.startswith("SSH-"):
        return "ssh", ilk
    if ilk.startswith("HTTP/"):
        eslesme = re.search(r"^Server:\s*(.+)$", banner, re.I | re.M)
        return "http", (eslesme.group(1).strip() if eslesme else ilk)
    if re.match(r"^(220|200)[ -]", ilk):
        return "smtp/ftp", ilk[4:80]
    if ilk.startswith("+OK"):
        return "pop3", ilk[:80]
    if ilk.startswith("* OK"):
        return "imap", ilk[:80]
    return "?", ilk[:80]


async def port_tara(host, portlar, timeout, paralel, sv):
    sem = asyncio.Semaphore(paralel)
    durumlar = await asyncio.gather(*(port_durumu(host, p, timeout, sem) for p in portlar))
    netice = []
    for port, durum in zip(portlar, durumlar):
        if durum != "açık":
            continue
        satir = {"port": port, "servis": servis_adi(port), "tip": "", "versiya": ""}
        if sv:
            banner = await banner_al(host, port, timeout)
            satir["tip"], satir["versiya"] = banner_tani(banner)
        netice.append(satir)
    return netice


def yazdir_port(satirlar):
    if not satirlar:
        print("  " + iki("Açık port bulunamadı.", "No open ports found."))
        return
    print(renk(f"  {'PORT':<11}{iki('SERVİS', 'SERVICE'):<14}{iki('TİP', 'TYPE'):<11}"
               f"{iki('SÜRÜM / BANNER', 'VERSION / BANNER')}", MAVI))
    for s in satirlar:
        print(f"  {str(s['port']) + '/tcp':<11}{s['servis']:<14}{s['tip']:<11}{s['versiya']}")
        if s["port"] in RISKLI_PORTLAR:
            ad, aciklama = RISKLI_PORTLAR[s["port"]]
            print(renk(f"      [!] {ad}: {aciklama.get(DIL, aciklama['tr'])}", SARI))


def kritik_tablo(satirlar_acik, ip):
    """Tehlikeli portların her biri için açık/kapalı durumunu gösterir."""
    acik = {s["port"] for s in satirlar_acik}
    baslik(iki(f"KRİTİK PORTLAR: {ip}", f"CRITICAL PORTS: {ip}"))
    for port in sorted(RISKLI_PORTLAR):
        ad, aciklama = RISKLI_PORTLAR[port]
        if port in acik:
            durum = renk(iki("AÇIK ", "OPEN  "), KIRMIZI)
            not_metni = aciklama.get(DIL, aciklama["tr"])
        else:
            durum = renk(iki("kapalı", "closed"), YESIL)
            not_metni = ""
        print(f"  {str(port) + '/tcp':<11}{ad:<14}{durum}  {not_metni if port in acik else ''}")
    kritik_acik = [p for p in RISKLI_PORTLAR if p in acik]
    if not kritik_acik:
        basari(iki("Tehlikeli portlardan açık olan yok.", "No dangerous ports are open."))
    else:
        uyari(iki(f"{len(kritik_acik)} tehlikeli port açık. Yukarıdaki önerilere bak.",
                  f"{len(kritik_acik)} dangerous ports are open. See the advice above."))


# ============================================================ CVE (NVD)
def urun_anahtari(tip, metin):
    if not metin:
        return ""
    if tip == "ssh" and metin.count("-") >= 2:
        metin = metin.split("-", 2)[-1]
    eslesme = URUN_REGEX.search(metin)
    return f"{eslesme.group(1)} {eslesme.group(2)}" if eslesme else ""


def nvd_sorgula(anahtar, limit=5):
    url = NVD_URL + "?keywordSearch=" + urllib.parse.quote(anahtar) + f"&resultsPerPage={limit}"
    istek = urllib.request.Request(url, headers={"User-Agent": "NetScout/7.0"})
    with urllib.request.urlopen(istek, timeout=25) as cevap:
        veri = json.loads(cevap.read().decode("utf-8", errors="replace"))
    sonuc = []
    for v in veri.get("vulnerabilities", []):
        c = v.get("cve", {})
        aciklama = next((d.get("value", "") for d in c.get("descriptions", [])
                         if d.get("lang") == "en"), "")
        skor, siddet = "?", "?"
        metrik = c.get("metrics", {})
        for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrik.get(mk):
                kayit = metrik[mk][0]
                cvss = kayit.get("cvssData", {})
                skor = cvss.get("baseScore", "?")
                siddet = cvss.get("baseSeverity", kayit.get("baseSeverity", "?"))
                break
        sonuc.append({"id": c.get("id", "?"), "skor": skor, "siddet": siddet,
                      "aciklama": aciklama[:150]})
    sonuc.sort(key=lambda x: x["skor"] if isinstance(x["skor"], (int, float)) else -1, reverse=True)
    return sonuc


def cve_kontrol(satirlar, host):
    gorulen = set()
    sorgu = 0
    sonuclar = []
    for s in satirlar:
        anahtar = urun_anahtari(s["tip"], s["versiya"])
        if not anahtar or anahtar in gorulen or sorgu >= 5:
            continue
        gorulen.add(anahtar)
        sorgu += 1
        baslik(iki(f"Olası CVE'ler: {anahtar} ({host}:{s['port']})",
                   f"Possible CVEs: {anahtar} ({host}:{s['port']})"))
        try:
            liste = nvd_sorgula(anahtar)
        except Exception as e:
            uyari(iki(f"NVD'ye ulaşılamadı: {e}", f"Could not reach NVD: {e}"))
            return sonuclar
        if not liste:
            print("  " + iki("Kayıt bulunamadı.", "No records found."))
        for c in liste:
            print(f"  {c['id']:<18} {str(c['skor']):<5} {c['siddet']:<9} {c['aciklama']}")
        sonuclar.append({"urun": anahtar, "cve": liste})
        if sorgu < 5:
            time.sleep(6)
    return sonuclar


# ============================================================ DNS (ham UDP sorgusu)
def _ad_coz(veri, ofs):
    etiketler = []
    atlanan = None
    sayac = 0
    while ofs < len(veri) and sayac < 50:
        uzunluk = veri[ofs]
        if uzunluk == 0:
            ofs += 1
            break
        if uzunluk & 0xC0 == 0xC0:
            isaret = struct.unpack(">H", veri[ofs:ofs + 2])[0] & 0x3FFF
            if atlanan is None:
                atlanan = ofs + 2
            ofs = isaret
            sayac += 1
            continue
        etiketler.append(veri[ofs + 1:ofs + 1 + uzunluk].decode("ascii", errors="replace"))
        ofs += 1 + uzunluk
    if atlanan is not None:
        ofs = atlanan
    return ".".join(etiketler), ofs


def dns_sorgu_paketi(domen, tip_no):
    import random
    tid = random.randint(0, 0xFFFF)
    baslik_b = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    soru = b""
    for etiket in domen.strip(".").split("."):
        soru += bytes([len(etiket)]) + etiket.encode("ascii")
    soru += b"\x00" + struct.pack(">HH", tip_no, 1)
    return tid, baslik_b + soru


def dns_cevap_coz(veri, tid):
    if len(veri) < 12:
        return []
    rid, _, soru_sayisi, cevap_sayisi, _, _ = struct.unpack(">HHHHHH", veri[:12])
    if rid != tid:
        return []
    ofs = 12
    for _ in range(soru_sayisi):
        _, ofs = _ad_coz(veri, ofs)
        ofs += 4
    sonuclar = []
    for _ in range(cevap_sayisi):
        _, ofs = _ad_coz(veri, ofs)
        tip, _, _, rdlen = struct.unpack(">HHIH", veri[ofs:ofs + 10])
        ofs += 10
        rd = veri[ofs:ofs + rdlen]
        basla = ofs
        ofs += rdlen
        if tip == 1 and rdlen == 4:
            deger = socket.inet_ntoa(rd)
        elif tip == 28 and rdlen == 16:
            deger = str(ipaddress.IPv6Address(rd))
        elif tip in (2, 5):
            deger, _ = _ad_coz(veri, basla)
        elif tip == 15:
            pref = struct.unpack(">H", rd[:2])[0]
            host, _ = _ad_coz(veri, basla + 2)
            deger = f"{pref} {host}"
        elif tip == 16:
            parcalar = []
            i = 0
            while i < len(rd):
                n = rd[i]
                parcalar.append(rd[i + 1:i + 1 + n].decode("utf-8", errors="replace"))
                i += 1 + n
            deger = " ".join(parcalar)
        else:
            deger = rd.hex()
        sonuclar.append(deger)
    return sonuclar


def _resolver_listesi():
    liste = []
    try:
        with open("/etc/resolv.conf") as f:
            for satir in f:
                if satir.startswith("nameserver"):
                    liste.append(satir.split()[1])
    except Exception:
        pass
    return liste + DNS_YEDEK_SUNUCULAR


def dns_kayit_sorgula(domen, tip, timeout=3.0):
    tid, paket = dns_sorgu_paketi(domen, DNS_TIPLERI[tip])
    for sunucu in _resolver_listesi():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(paket, (sunucu, 53))
                cevap, _ = s.recvfrom(4096)
            return dns_cevap_coz(cevap, tid)
        except Exception:
            continue
    return []


def dns_yoxla(domen, alt=True, paralel=30):
    from concurrent.futures import ThreadPoolExecutor
    n = {"domen": domen, "a": [], "ters": {}, "alt": [], "kayitlar": {}}
    try:
        _, _, ips = socket.gethostbyname_ex(domen)
    except Exception:
        n["hata"] = iki("Ad çözülmedi.", "Name could not be resolved.")
        return n
    n["a"] = ips
    for ip in ips:
        n["ters"][ip] = ters_dns(ip)
    if alt:
        def coz(ad):
            tam = f"{ad}.{domen}"
            try:
                return tam, socket.gethostbyname(tam)
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=paralel) as icra:
            for cevap in icra.map(coz, ALT_DOMENLER):
                if cevap:
                    n["alt"].append({"ad": cevap[0], "ip": cevap[1]})
    for tip in ("MX", "NS", "TXT"):
        n["kayitlar"][tip] = dns_kayit_sorgula(domen, tip)
    return n


def yazdir_dns(n):
    baslik(f"DNS: {n['domen']}")
    if "hata" in n:
        uyari(n["hata"])
        return
    for ip in n["a"]:
        print(f"  A      {ip:<16} {n['ters'].get(ip) or '-'}")
    for a in n["alt"]:
        print(f"  ALT    {a['ad']} -> {a['ip']}")
    if not n["alt"]:
        print("  " + iki("Alt alan adı bulunamadı.", "No subdomains found."))
    for tip, degerler in n["kayitlar"].items():
        if not degerler:
            print(f"  {tip:<6} {iki('kayıt yok', 'no record')}")
        for d in degerler:
            print(f"  {tip:<6} {d}")


# ============================================================ web kontrolü
def _baglanti_yarat(p, timeout):
    if p.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        import http.client
        return http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=timeout, context=ctx)
    import http.client
    return http.client.HTTPConnection(p.hostname, p.port or 80, timeout=timeout)


def web_yoxla(url, timeout=8):
    zencir, basliklar, mevcut = [], {}, url
    for _ in range(10):
        p = urllib.parse.urlsplit(mevcut)
        if p.scheme not in ("http", "https") or not p.hostname:
            zencir.append({"url": mevcut, "hata": "geçersiz URL"})
            break
        yol = (p.path or "/") + (f"?{p.query}" if p.query else "")
        baglanti = _baglanti_yarat(p, timeout)
        try:
            baglanti.request("GET", yol, headers={"User-Agent": "NetScout/7.0"})
            cevap = baglanti.getresponse()
        except Exception as e:
            zencir.append({"url": mevcut, "hata": str(e)})
            break
        finally:
            baglanti.close()
        zencir.append({"url": mevcut, "kod": cevap.status})
        if cevap.status in (301, 302, 303, 307, 308):
            yeni = cevap.getheader("Location")
            if not yeni:
                break
            mevcut = urllib.parse.urljoin(mevcut, yeni)
            continue
        basliklar = {k.lower(): v for k, v in cevap.getheaders()}
        break
    return {"zencir": zencir, "basliklar": basliklar}


def ek_dosyalar(url, timeout=6):
    p = urllib.parse.urlsplit(url)
    sonuc = {}
    if not p.hostname:
        return sonuc
    for yol in EK_YOLLAR:
        baglanti = _baglanti_yarat(p, timeout)
        try:
            baglanti.request("GET", yol, headers={"User-Agent": "NetScout/7.0"})
            sonuc[yol] = baglanti.getresponse().status
        except Exception as e:
            sonuc[yol] = f"hata: {e}"
        finally:
            baglanti.close()
    return sonuc


def sertifikat_yoxla(host, port=443, timeout=8):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as soket:
            with ctx.wrap_socket(soket, server_hostname=host) as tls:
                sertifika = tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return {"gecerli": False, "hata": e.verify_message or str(e)}
    except Exception as e:
        return {"gecerli": None, "hata": str(e)}
    try:
        bitis = ssl.cert_time_to_seconds(sertifika["notAfter"])
    except Exception:
        return {"gecerli": True, "bitis": sertifika.get("notAfter", "?"), "kalan_gun": None}
    return {"gecerli": True, "bitis": sertifika["notAfter"],
            "kalan_gun": int((bitis - time.time()) // 86400)}


def web_tam(url, timeout=8):
    n = web_yoxla(url, timeout)
    n["url"] = url
    basliklar = n["basliklar"]
    n["guvenlik"] = [{"ad": ad, "aciklama": acik.get(DIL, acik["tr"]),
                      "var": ad.lower() in basliklar}
                     for ad, acik in GUVENLIK_BASLIKLARI.items()]
    n["sunucu"] = basliklar.get("server", "")
    n["sertifika"] = None
    n["ek"] = {}
    if n["zencir"]:
        son_url = n["zencir"][-1]["url"]
        son = urllib.parse.urlsplit(son_url)
        if son.scheme == "https" and son.hostname:
            n["sertifika"] = sertifikat_yoxla(son.hostname, son.port or 443, timeout)
        n["ek"] = ek_dosyalar(son_url, timeout)
    return n


def yazdir_web(n):
    baslik(f"WEB: {n['url']}")
    for adim in n["zencir"]:
        if "hata" in adim:
            uyari(f"{adim['url']} -> {adim['hata']}")
        else:
            print(f"  [{adim['kod']}] {adim['url']}")
    if n["sunucu"]:
        print("  " + iki(f"Sunucu: {n['sunucu']}", f"Server: {n['sunucu']}"))
    s = n.get("sertifika")
    if s:
        if s.get("gecerli") is True:
            kalan = s.get("kalan_gun")
            print("  " + iki(f"TLS: geçerli, bitiş {s['bitis']} ({kalan} gün kaldı)",
                             f"TLS: valid, expires {s['bitis']} ({kalan} days left)"))
            if kalan is not None and kalan < 30:
                uyari(iki("Sertifikanın bitmesine 30 günden az kaldı.",
                          "Certificate expires in less than 30 days."))
        elif s.get("gecerli") is False:
            uyari(iki(f"TLS GEÇERSİZ ({s['hata']})", f"TLS INVALID ({s['hata']})"))
        else:
            print("  " + iki(f"TLS: kontrol edilemedi ({s.get('hata', '')})",
                             f"TLS: could not check ({s.get('hata', '')})"))
    print("  " + iki("Güvenlik başlıkları:", "Security headers:"))
    for g in n["guvenlik"]:
        isaret = renk("+", "1;32") if g["var"] else renk("-", KIRMIZI)
        print(f"    [{isaret}] {g['ad']:<28} {g['aciklama']}")
    if n.get("ek"):
        print("  " + iki("Ek dosyalar:", "Extra files:"))
        for yol, durum in n["ek"].items():
            print(f"    {yol:<28} {durum}")


# ============================================================ ters IP
def ters_ip_sorgula(ip, timeout=15):
    url = TERS_IP_API + urllib.parse.quote(ip)
    istek = urllib.request.Request(url, headers={"User-Agent": "NetScout/7.0"})
    try:
        with urllib.request.urlopen(istek, timeout=timeout) as cevap:
            metin = cevap.read().decode("utf-8", errors="replace").strip()
    except Exception as e:
        return {"hata": f"{iki('sorgu başarısız', 'request failed')}: {e}", "alanlar": []}
    kucuk = metin.lower()
    if not metin:
        return {"hata": iki("Boş cevap geldi.", "Empty reply."), "alanlar": []}
    if "api count exceeded" in kucuk or kucuk.startswith("error"):
        return {"hata": iki("Günlük sorgu limiti doldu.", "Daily query limit reached."), "alanlar": []}
    if "no records found" in kucuk or "no dns" in kucuk:
        return {"hata": None, "alanlar": []}
    alanlar = sorted({s.strip().lower() for s in metin.splitlines() if s.strip()})
    return {"hata": None, "alanlar": alanlar}


def yazdir_ters_ip(ip, n):
    baslik(iki(f"TERS IP: {ip}", f"REVERSE IP: {ip}"))
    if n["hata"]:
        uyari(n["hata"])
        return
    if not n["alanlar"]:
        print("  " + iki("Bu IP için alan adı kaydı yok.", "No domain records for this IP."))
        return
    print("  " + iki(f"{len(n['alanlar'])} alan adı bulundu:", f"{len(n['alanlar'])} domains found:"))
    for a in n["alanlar"]:
        print(f"    - {a}")


# ============================================================ pcap analizi (rootsuz)
def pcap_tara(yol):
    try:
        with open(yol, "rb") as f:
            veri = f.read()
    except OSError as e:
        raise RuntimeError(iki(f"Dosya okunamadı: {e}", f"Could not read file: {e}"))
    if len(veri) < 24:
        raise RuntimeError(iki("Geçersiz pcap dosyası.", "Invalid pcap file."))
    if veri[:4] == b"\x0a\x0d\x0d\x0a":
        raise RuntimeError(iki("pcapng desteklenmiyor. Wireshark'ta Dosya > Dışa Aktar > "
                               "Eski pcap ile çevir.",
                               "pcapng not supported. In Wireshark use File > Export > "
                               "Legacy pcap."))
    if veri[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif veri[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise RuntimeError(iki("Geçersiz pcap dosyası.", "Invalid pcap file."))
    if struct.unpack(endian + "I", veri[20:24])[0] != 1:
        raise RuntimeError(iki("Sadece Ethernet yakalamaları destekleniyor.",
                               "Only Ethernet captures are supported."))

    protokol, kaynak, port = {}, {}, {}
    dns, http, akis = [], [], {}
    toplam = 0
    ofs = 24
    while ofs + 16 <= len(veri):
        ts, _, incl, _ = struct.unpack(endian + "IIII", veri[ofs:ofs + 16])
        ofs += 16
        paket = veri[ofs:ofs + incl]
        ofs += incl
        toplam += 1
        if len(paket) < 34 or struct.unpack(">H", paket[12:14])[0] != 0x0800:
            protokol["other"] = protokol.get("other", 0) + 1
            continue
        ip = paket[14:]
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        kaynak[src] = kaynak.get(src, 0) + 1
        ad = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
        protokol[ad] = protokol.get(ad, 0) + 1
        sport = dport = 0
        if proto in (6, 17) and len(ip) >= ihl + 4:
            sport, dport = struct.unpack(">HH", ip[ihl:ihl + 4])
            port[dport] = port.get(dport, 0) + 1
            if proto == 6 and len(ip) >= ihl + 13:
                yuk_ofs = ihl + (ip[ihl + 12] >> 4) * 4
            else:
                yuk_ofs = ihl + 8
            yuk = ip[yuk_ofs:]
            if proto == 17 and 53 in (sport, dport) and len(yuk) > 12 and len(dns) < 60:
                dns_ad, _ = _ad_coz(yuk, 12)
                if dns_ad and dns_ad not in dns:
                    dns.append(dns_ad)
            if proto == 6 and dport == 80 and yuk[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                eslesme = re.search(rb"Host:\s*([^\r\n]+)", yuk)
                if eslesme and len(http) < 60:
                    h = eslesme.group(1).decode("latin-1", "replace").strip()
                    if h not in http:
                        http.append(h)
        anahtar = (ad,) + tuple(sorted([(src, sport), (dst, dport)]))
        kayit = akis.get(anahtar)
        if kayit is None:
            akis[anahtar] = {"ilk": ts, "son": ts, "paket": 1, "bayt": len(paket)}
        else:
            kayit["son"] = ts
            kayit["paket"] += 1
            kayit["bayt"] += len(paket)
    akis_liste = sorted(akis.items(), key=lambda x: x[1]["paket"], reverse=True)
    return {"dosya": yol, "paket": toplam, "protokol": protokol,
            "kaynak_ip": sorted(kaynak.items(), key=lambda x: x[1], reverse=True)[:10],
            "hedef_port": sorted(port.items(), key=lambda x: x[1], reverse=True)[:10],
            "dns": dns, "http": http, "akis": akis_liste}


def _ad_coz_guvenli(veri, ofs):
    return _ad_coz(veri, ofs)


def pcap_goster(n):
    ad = os.path.basename(n["dosya"])
    baslik(iki(f"PCAP ANALİZİ: {ad}", f"PCAP ANALYSIS: {ad}"))
    print("  " + iki(f"Toplam paket: {n['paket']}", f"Total packets: {n['paket']}"))
    print("  " + iki("Protokoller:", "Protocols:"))
    for pad, sayi in sorted(n["protokol"].items(), key=lambda x: x[1], reverse=True):
        print(f"    {pad:<8} {sayi}")
    print("  " + iki("En çok konuşan kaynak IP'ler:", "Top talking source IPs:"))
    for ip, sayi in n["kaynak_ip"]:
        print(f"    {ip:<16} {sayi}")
    print("  " + iki("En çok hedeflenen portlar:", "Most targeted ports:"))
    for p, sayi in n["hedef_port"]:
        print(f"    {p:<8} {sayi} {servis_adi(p)}")
    print("  " + iki("DNS sorguları:", "DNS queries:"))
    for d in n["dns"][:30] or [iki("Yok", "None")]:
        print(f"    {d}")
    print("  " + iki("HTTP Host başlıkları:", "HTTP Host headers:"))
    for h in n["http"][:30] or [iki("Yok", "None")]:
        print(f"    {h}")


def zeek_yaz(n, klasor):
    """Bağlantı, DNS ve HTTP loglarını (Zeek benzeri) klasöre yazar."""
    os.makedirs(klasor, exist_ok=True)
    with open(os.path.join(klasor, "conn.log"), "w", encoding="utf-8") as f:
        f.write("ts\tproto\tsrc\tsport\tdst\tdport\tpackets\tbytes\tduration\n")
        for (proto, a, b), k in n["akis"][:5000]:
            f.write(f"{k['ilk']}\t{proto}\t{a[0]}\t{a[1]}\t{b[0]}\t{b[1]}\t"
                    f"{k['paket']}\t{k['bayt']}\t{k['son'] - k['ilk']}\n")
    with open(os.path.join(klasor, "dns.log"), "w", encoding="utf-8") as f:
        f.write("query\n")
        for d in n["dns"]:
            f.write(d + "\n")
    with open(os.path.join(klasor, "http.log"), "w", encoding="utf-8") as f:
        f.write("host\n")
        for h in n["http"]:
            f.write(h + "\n")


def zeek_ozeti_goster(n, klasor):
    baslik(iki(f"ZEEK ÖZETİ (loglar: {klasor})", f"ZEEK SUMMARY (logs: {klasor})"))
    print("  " + iki(f"Bağlantı sayısı: {len(n['akis'])}", f"Connections: {len(n['akis'])}"))
    print(renk(f"  {'PROTO':<6}{'KAYNAK':<24}{'HEDEF':<24}{'PAKET':<8}BAYT", MAVI))
    for (proto, a, b), k in n["akis"][:10]:
        print(f"  {proto:<6}{a[0] + ':' + str(a[1]):<24}{b[0] + ':' + str(b[1]):<24}"
              f"{k['paket']:<8}{k['bayt']}")


# ============================================================ 1) NMAP
def _script_filtrele(deger):
    kabul = []
    for parca in deger.split(","):
        parca = parca.strip()
        if parca and not any(y in parca.lower() for y in YASAKLI_SCRIPT_PARCALARI):
            kabul.append(parca)
    return ",".join(kabul)


def nmap_temizle(arglar):
    """Harici nmap komutunu, sessizce rootsuz çalışacak şekilde düzeltir."""
    temiz = []
    i = 0
    while i < len(arglar):
        a = arglar[i]
        if a in ROOT_DEGISTIRME:
            temiz += ROOT_DEGISTIRME[a].split()
        elif a in ROOT_GEREKEN:
            pass
        elif a.startswith("--script="):
            yeni = _script_filtrele(a.split("=", 1)[1])
            if yeni:
                temiz.append(f"--script={yeni}")
        elif a == "--script" and i + 1 < len(arglar):
            i += 1
            yeni = _script_filtrele(arglar[i])
            if yeni:
                temiz += ["--script", yeni]
        else:
            temiz.append(a)
        i += 1
    return temiz


def nmap_harici_calistir():
    baslik(iki("Harici nmap profilleri", "External nmap profiles"))
    for anahtar, (aciklama, _) in NMAP_HARICI_PROFILLER.items():
        print(f"  {anahtar}) {aciklama.get(DIL, aciklama['tr'])}")
    secim = input(iki("  Seçim: ", "  Choice: ")).strip()
    if secim not in NMAP_HARICI_PROFILLER:
        uyari(iki("Geçersiz seçim.", "Invalid choice."))
        return
    hedef = input(iki("  Hedef: ", "  Target: ")).strip()
    if not hedef:
        return
    arglar = nmap_temizle(["nmap", hedef] + NMAP_HARICI_PROFILLER[secim][1])
    bilgi(iki("Çalıştırılıyor: ", "Running: ") + " ".join(arglar))
    try:
        subprocess.run(arglar)
    except KeyboardInterrupt:
        uyari(iki("Durduruldu.", "Stopped."))


def yerlesik_tara(hedef, profil, timeout, paralel):
    ips, sebeke, ad = hedef_coz(hedef)
    if profil.get("kesif"):
        bilgi(iki(f"{len(ips)} adres kontrol ediliyor...", f"Checking {len(ips)} addresses..."))
        yazdir_kesif(asyncio.run(kesif_et(ips, timeout, paralel)))
        return
    portlar = port_siyahisi(profil.get("portlar"))
    if sebeke:
        bilgi(iki(f"{len(ips)} adres için canlı cihaz aranıyor...",
                  f"Searching {len(ips)} addresses for live hosts..."))
        hedefler = [c["ip"] for c in asyncio.run(kesif_et(ips, timeout, paralel))]
        if not hedefler:
            print("  " + iki("Canlı cihaz bulunamadı.", "No live hosts found."))
            return
    else:
        hedefler = ips
    for ip in hedefler:
        satirlar = asyncio.run(port_tara(ip, portlar, timeout, paralel, profil.get("sv", False)))
        baslik(f"{ip} ({ad or ters_dns(ip) or iki('ad yok', 'no name')})")
        yazdir_port(satirlar)
        if profil.get("cve") and satirlar:
            cve_kontrol(satirlar, ip)


def nmap_modu():
    baslik("nmap")
    for anahtar, (aciklama, _) in YERLESIK_PROFILLER.items():
        print(f"  {anahtar}) {aciklama.get(DIL, aciklama['tr'])}")
    if harici_var("nmap"):
        print("  n) " + iki("Harici nmap komutları", "External nmap commands"))
    secim = input(iki("  Seçim: ", "  Choice: ")).strip().lower()
    if secim == "n" and harici_var("nmap"):
        nmap_harici_calistir()
        return
    if secim not in YERLESIK_PROFILLER:
        uyari(iki("Geçersiz seçim.", "Invalid choice."))
        return
    hedef = input(iki("  Hedef (IP, CIDR veya hostname): ",
                      "  Target (IP, CIDR or hostname): ")).strip()
    if not hedef:
        return
    try:
        zaman = float(input(iki("  Zaman aşımı, saniye [1.0]: ",
                                "  Timeout, seconds [1.0]: ")).strip() or "1.0")
        paralel = int(input(iki("  Aynı anda bağlantı [200]: ",
                                "  Parallel connections [200]: ")).strip() or "200")
    except ValueError:
        uyari(iki("Sayı girmelisin.", "Enter a number."))
        return
    try:
        yerlesik_tara(hedef, YERLESIK_PROFILLER[secim][1], zaman, max(1, min(paralel, 1000)))
    except KeyboardInterrupt:
        uyari(iki("Durduruldu.", "Stopped."))


# ============================================================ 2) MASSCAN (yerleşik)
async def _hizli_tara(ips, portlar, timeout, paralel):
    sem = asyncio.Semaphore(paralel)

    async def bir(ip, port):
        return (ip, port) if await port_durumu(ip, port, timeout, sem) == "açık" else None

    sonuc = await asyncio.gather(*(bir(ip, p) for ip in ips for p in portlar))
    return [s for s in sonuc if s]


def masscan_modu():
    baslik("masscan")
    hedef = input(iki("  Hedef (IP veya CIDR, örn 192.168.1.0/24): ",
                      "  Target (IP or CIDR, e.g. 192.168.1.0/24): ")).strip()
    if not hedef:
        return
    portlar_metni = input(iki("  Portlar [1-1024]: ", "  Ports [1-1024]: ")).strip() or "1-1024"
    try:
        paralel = int(input(iki("  Aynı anda bağlantı [300]: ",
                                "  Parallel connections [300]: ")).strip() or "300")
        zaman = float(input(iki("  Zaman aşımı, saniye [1.0]: ",
                                "  Timeout, seconds [1.0]: ")).strip() or "1.0")
    except ValueError:
        uyari(iki("Sayı girmelisin.", "Enter a number."))
        return
    ips, _, _ = hedef_coz(hedef)
    portlar = port_siyahisi(portlar_metni)
    if len(ips) * len(portlar) > 100000:
        uyari(iki("Tarama çok büyük (adres x port > 100000). Aralığı daralt.",
                  "Scan too large (addresses x ports > 100000). Narrow the range."))
        return
    bilgi(iki(f"{len(ips)} adres x {len(portlar)} port taranıyor...",
              f"Scanning {len(ips)} addresses x {len(portlar)} ports..."))
    try:
        sonuc = asyncio.run(_hizli_tara(ips, portlar, zaman, max(1, min(paralel, 1000))))
    except KeyboardInterrupt:
        uyari(iki("Durduruldu.", "Stopped."))
        return
    if not sonuc:
        print("  " + iki("Açık port bulunamadı.", "No open ports found."))
    for ip, port in sonuc:
        print(f"  {ip:<16} {port}/tcp  {servis_adi(port)}")


# ============================================================ 3) WIRESHARK (pcap)
def wireshark_modu():
    baslik("Wireshark (pcap)")
    yol = input(iki("  Dosya yolu (.pcap): ", "  File path (.pcap): ")).strip()
    if not os.path.isfile(yol):
        uyari(iki("Dosya bulunamadı.", "File not found."))
        return
    try:
        pcap_goster(pcap_tara(yol))
    except RuntimeError as e:
        uyari(str(e))


# ============================================================ 4) ZEEK (pcap)
def zeek_modu():
    baslik("Zeek (pcap)")
    yol = input(iki("  Dosya yolu (.pcap): ", "  File path (.pcap): ")).strip()
    if not os.path.isfile(yol):
        uyari(iki("Dosya bulunamadı.", "File not found."))
        return
    try:
        n = pcap_tara(yol)
    except RuntimeError as e:
        uyari(str(e))
        return
    klasor = os.path.abspath(ZEEK_KLASORU)
    zeek_yaz(n, klasor)
    zeek_ozeti_goster(n, klasor)


# ============================================================ 5) OPENVAS (CVE, NVD)
def openvas_modu():
    baslik("OpenVAS (CVE)")
    print("  " + iki("Servislerin sürümüne göre NVD veritabanından olası CVE'ler listelenir.",
                     "Lists possible CVEs for the service versions from the NVD database."))
    hedef = input(iki("  Hedef (IP veya hostname): ", "  Target (IP or hostname): ")).strip()
    if not hedef:
        return
    ips, sebeke, ad = hedef_coz(hedef)
    if sebeke:
        uyari(iki("CVE taraması tek host içindir.", "CVE scan is for a single host."))
        return
    ip = ips[0]
    bilgi(iki(f"{ip} üzerinde servisler taranıyor...", f"Scanning services on {ip}..."))
    satirlar = asyncio.run(port_tara(ip, ORNEK_PORTLAR, 1.0, 200, True))
    yazdir_port(satirlar)
    if satirlar:
        cve_kontrol(satirlar, ip)


# ============================================================ PASİF SİTE ARAŞTIRMASI
sr_SURUM = "1.0"
UA = "NetScout-SiteResearch/1.0 (passive public-information research)"
ZAMAN = 12
WD = "https://www.wikidata.org/w/api.php?format=json&"
CONTACT_YOLLARI = ["iletisim", "contact", "contact-us", "about", "about-us", "hakkimizda",
                   "bize-ulasin", "impressum", "legal", "terms", "privacy", "gizlilik"]

# dial: telefon ülke kodu | lang: <html lang> değerleri | cur: benzersiz para işaretleri/kodları
sr_ULKELER = {
    "az": {"tr": "Azerbaycan", "en": "Azerbaijan", "dial": "+994", "lang": ["az"], "tz": 4,
           "cur": ["₼", "AZN"], "sehir": ["Baku", "Bakı", "Ganja", "Gəncə", "Sumqayit", "Sumgait"]},
    "am": {"tr": "Ermenistan", "en": "Armenia", "dial": "+374", "lang": ["hy"], "tz": 4,
           "cur": ["֏", "AMD"], "sehir": ["Yerevan", "Erivan", "Gyumri"]},
    "ge": {"tr": "Gürcistan", "en": "Georgia", "dial": "+995", "lang": ["ka"], "tz": 4,
           "cur": ["₾", "GEL"], "sehir": ["Tbilisi", "Tiflis", "Batumi", "Kutaisi"]},
    "tr": {"tr": "Türkiye", "en": "Turkey", "dial": "+90", "lang": ["tr"], "tz": 3,
           "cur": ["₺", "TRY"], "sehir": ["İstanbul", "Istanbul", "Ankara", "İzmir", "Izmir", "Bursa", "Antalya"]},
    "ru": {"tr": "Rusya", "en": "Russia", "dial": "+7", "lang": ["ru"], "tz": 3,
           "cur": ["₽", "RUB"], "sehir": ["Moscow", "Moskova", "Saint Petersburg", "Kazan"]},
    "kz": {"tr": "Kazakistan", "en": "Kazakhstan", "dial": "+7", "lang": ["kk"], "tz": 5,
           "cur": ["₸"], "sehir": ["Almaty", "Astana"]},
    "ua": {"tr": "Ukrayna", "en": "Ukraine", "dial": "+380", "lang": ["uk"], "tz": 2,
           "cur": ["₴", "UAH"], "sehir": ["Kyiv", "Kiev", "Kharkiv", "Odesa", "Lviv", "Dnipro"]},
    "ir": {"tr": "İran", "en": "Iran", "dial": "+98", "lang": ["fa"], "tz": 3.5,
           "cur": [], "sehir": ["Tehran", "Tahran", "Isfahan", "Mashhad", "Tabriz"]},
    "de": {"tr": "Almanya", "en": "Germany", "dial": "+49", "lang": ["de"], "tz": 1,
           "cur": [], "sehir": ["Berlin", "Munich", "München", "Hamburg", "Frankfurt"]},
    "fr": {"tr": "Fransa", "en": "France", "dial": "+33", "lang": ["fr"], "tz": 1,
           "cur": [], "sehir": ["Paris", "Lyon", "Marseille"]},
    "it": {"tr": "İtalya", "en": "Italy", "dial": "+39", "lang": ["it"], "tz": 1,
           "cur": [], "sehir": ["Rome", "Roma", "Milan", "Milano", "Naples", "Napoli"]},
    "es": {"tr": "İspanya", "en": "Spain", "dial": "+34", "lang": ["es"], "tz": 1,
           "cur": [], "sehir": ["Madrid", "Barcelona", "Valencia", "Seville", "Sevilla"]},
    "us": {"tr": "ABD", "en": "United States", "dial": "+1", "lang": [], "tz": -5,
           "cur": [], "sehir": ["New York", "Los Angeles", "San Francisco", "Chicago", "Miami"]},
    "ca": {"tr": "Kanada", "en": "Canada", "dial": "+1", "lang": [], "tz": -5,
           "cur": [], "sehir": ["Toronto", "Montreal", "Montréal", "Vancouver", "Ottawa"]},
    "gb": {"tr": "Birleşik Krallık", "en": "United Kingdom", "dial": "+44", "lang": [], "tz": 0,
           "cur": [], "sehir": ["London", "Manchester", "Birmingham", "Edinburgh"]},
    "ae": {"tr": "BAE", "en": "United Arab Emirates", "dial": "+971", "lang": [], "tz": 4,
           "cur": [], "sehir": ["Dubai", "Abu Dhabi", "Sharjah"]},
    "sa": {"tr": "Suudi Arabistan", "en": "Saudi Arabia", "dial": "+966", "lang": [], "tz": 3,
           "cur": [], "sehir": ["Riyadh", "Jeddah"]},
    "jp": {"tr": "Japonya", "en": "Japan", "dial": "+81", "lang": ["ja"], "tz": 9,
           "cur": [], "sehir": ["Tokyo", "Osaka"]},
    "kr": {"tr": "Güney Kore", "en": "South Korea", "dial": "+82", "lang": ["ko"], "tz": 9,
           "cur": [], "sehir": ["Seoul"]},
    "in": {"tr": "Hindistan", "en": "India", "dial": "+91", "lang": [], "tz": 5.5,
           "cur": ["₹"], "sehir": ["Mumbai", "Delhi", "Bangalore"]},
    "br": {"tr": "Brezilya", "en": "Brazil", "dial": "+55", "lang": ["pt"], "tz": -3,
           "cur": [], "sehir": ["São Paulo", "Rio de Janeiro"]},
}
# Ülke adı olarak da kelime olan, bu yüzden düşük ağırlık verilenler
BELIRSIZ = {"Georgia", "Turkey", "Nice", "Chad", "Jordan"}
TLD_HARITA = {"uk": "gb"}

DIAL_HARITA = {}
for _k, _u in sr_ULKELER.items():
    DIAL_HARITA.setdefault(_u["dial"], []).append(_k)

sr_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
TEL_HREF = re.compile(r'href="tel:([^"]+)"', re.I)
TEL_METIN = re.compile(r"(?:tel|telefon|phone|gsm|whatsapp|çağrı)[^0-9+]{0,20}"
                       r"(\+?[0-9][0-9 ()./-]{7,20}[0-9])", re.I)
MAIL_HREF = re.compile(r'mailto:([^"?\s]+)', re.I)
sr_ADRES_RE = re.compile(r"[^.|]{0,80}\b(?:Street|St\.|Avenue|Ave\.|Road|Blvd|Boulevard|Caddesi|"
                      r"Cad\.|Sokak|Sok\.|Mahallesi|Mah\.|Bulvar[ıi]?)\b[^.|]{0,60}", re.I)


# ============================================================ yardımcılar
def sr_baslik(m):
    print(f"\n━━━ {m} ━━━")


def sr_bilgi(m):
    print(f"  [*] {m}")


def sr_uyari(m):
    print(f"  [!] {m}")


def al(url, zaman=ZAMAN, limit=600000):
    istek = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(istek, timeout=zaman) as c:
            return c.read(limit).decode("utf-8", errors="replace")
    except Exception:
        return None


def al_json(url, zaman=ZAMAN):
    metin = al(url, zaman)
    if not metin:
        return None
    try:
        return json.loads(metin)
    except ValueError:
        return None


def host_kok(host):
    h = (host or "").lower().split(":")[0]
    return h[4:] if h.startswith("www.") else h


def fmt_ts(ts):
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"


def say(metin, ifade):
    if not metin or not ifade:
        return 0
    return len(re.findall(r"(?<!\w)" + re.escape(ifade) + r"(?!\w)", metin, re.I))


def sr_metin_cikar(h):
    t = re.sub(r"<script.*?</script>|<style.*?</style>", " ", h, flags=re.S | re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    return re.sub(r"\s+", " ", htmllib.unescape(t))


def baslik_al(h):
    m = re.search(r"<title[^>]*>(.*?)</title>", h, re.I | re.S)
    return htmllib.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:120] if m else ""


def temiz(s):
    return htmllib.unescape(re.sub(r"<[^>]+>", " ", s)).strip()


# ============================================================ site sayfaları ve iletişim
def sayfalari_al(url):
    p = urllib.parse.urlsplit(url)
    taban = f"{p.scheme}://{p.netloc}"
    adresler = [url] + [taban + "/" + y for y in CONTACT_YOLLARI]
    adresler = list(dict.fromkeys(adresler))
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        icerik = list(ex.map(al, adresler))
    return {a: h for a, h in zip(adresler, icerik) if h}


def sr_iletisim_coz(html):
    emailler, telefonlar = set(), set()
    for t in TEL_HREF.findall(html) + TEL_METIN.findall(html):
        t = re.sub(r"\s+", " ", t).strip(" .-")
        if len(re.sub(r"\D", "", t)) >= 8:
            telefonlar.add(t)
    for e in MAIL_HREF.findall(html) + sr_EMAIL_RE.findall(html):
        e = e.lower()
        if e.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")):
            continue
        if any(x in e for x in ("example.", "sentry", "wixpress", "domain.com")):
            continue
        emailler.add(e)
    return sorted(emailler)[:10], sorted(telefonlar)[:10]


def sr_adres_bul(metin):
    sonuc = []
    for m in sr_ADRES_RE.finditer(metin):
        s = m.group(0).strip()
        if s and s not in sonuc:
            sonuc.append(s)
        if len(sonuc) >= 3:
            break
    return sonuc


def dial_ulkeleri(numara):
    t = re.sub(r"[^\d+]", "", numara)
    if t.startswith("00"):
        t = "+" + t[2:]
    if not t.startswith("+"):
        return []
    for onek in sorted(DIAL_HARITA, key=len, reverse=True):
        if t.startswith(onek):
            return DIAL_HARITA[onek]
    return []


# ============================================================ web kaynakları (Vikipedi, DuckDuckGo)
def vikipedi_ara(sorgu, limit=5):
    v = al_json("https://en.wikipedia.org/w/api.php?action=query&list=search&format=json"
                "&srlimit=%d&srsearch=%s" % (limit, urllib.parse.quote(sorgu)))
    q = (v or {}).get("query") or {}
    sonuc = []
    for x in q.get("search", []):
        baslik_v = x.get("title", "")
        sonuc.append({
            "sr_baslik": baslik_v,
            "ozet": temiz(x.get("snippet", ""))[:220],
            "link": "https://en.wikipedia.org/wiki/" + urllib.parse.quote(baslik_v.replace(" ", "_")),
        })
    return sonuc


def ddg_ara(sorgu):
    h = al("https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(sorgu), ZAMAN, 300000)
    if not h:
        return []
    basliklar = re.findall(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', h, re.S)
    ozetler = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', h, re.S)
    sonuc = []
    for i, (link, bh) in enumerate(basliklar[:8]):
        if "uddg=" in link:
            link = urllib.parse.unquote(link.split("uddg=", 1)[1].split("&", 1)[0])
        sonuc.append({
            "sr_baslik": temiz(bh),
            "ozet": temiz(ozetler[i]) if i < len(ozetler) else "",
            "link": link,
        })
    return sonuc


def karanlik_taraf(kok, ad):
    return {
        "vikipedi": vikipedi_ara(f'"{ad}" lawsuit OR fraud OR scandal OR controversy'),
        "web": ddg_ara(f'"{kok}" lawsuit OR fraud OR scam OR breach'),
    }


# ============================================================ Wikidata (kurum ve resmi ülke)
def degerler(varlik, ozellik):
    cikti = []
    for c in varlik.get("claims", {}).get(ozellik, []):
        v = c.get("mainsnak", {}).get("datavalue", {}).get("value")
        if isinstance(v, dict):
            if "id" in v:
                cikti.append(v["id"])
            elif "time" in v:
                cikti.append(v["time"].lstrip("+")[:10])
            elif "text" in v:
                cikti.append(v["text"])
        elif isinstance(v, str):
            cikti.append(v)
    return cikti


def etiket(e):
    lab = e.get("labels", {})
    for d in ("tr", "en"):
        if d in lab:
            return lab[d]["value"]
    return ""


def etiketler(idler):
    if not idler:
        return {}
    v = al_json(WD + "action=wbgetentities&props=labels&languages=en|tr&ids=" + "|".join(idler[:45]))
    return {k: etiket(e) for k, e in (v or {}).get("entities", {}).items()}


def site_eslesir(site_url, kok):
    h = host_kok(urllib.parse.urlsplit(site_url).hostname or "")
    return bool(h) and (h == kok or h.endswith("." + kok) or kok.endswith("." + h))


def sr_gelir(e):
    """Wikidata'da kayıtlı toplam gelir (P2139): (miktar, birim kimliği) listesi."""
    cikti = []
    for c in e.get("claims", {}).get("P2139", []):
        v = c.get("mainsnak", {}).get("datavalue", {}).get("value", {})
        if isinstance(v, dict) and "amount" in v:
            birim = v.get("unit", "")
            cikti.append((v["amount"].lstrip("+"), birim.rsplit("/", 1)[-1] if "/" in birim else ""))
    return cikti[:2]


def wd_kurum(kok, adaylar):
    """Resmi web adresi (P856) bu alan adıyla eşleşen ilk Wikidata kaydını döndürür."""
    kimlikler = []
    for ad in adaylar:
        v = al_json(WD + "action=wbsearchentities&language=en&limit=5&type=item&search="
                    + urllib.parse.quote(ad))
        for x in (v or {}).get("search", []):
            if x.get("id") and x["id"] not in kimlikler:
                kimlikler.append(x["id"])
    kimlikler = kimlikler[:12]
    if not kimlikler:
        return None
    v = al_json(WD + "action=wbgetentities&props=claims|labels&languages=en|tr&ids="
                + "|".join(kimlikler))
    varlik = (v or {}).get("entities", {})
    for qid in kimlikler:
        e = varlik.get(qid, {})
        if not any(site_eslesir(s, kok) for s in degerler(e, "P856")):
            continue
        ozellikler = {p: degerler(e, p) for p in ("P17", "P159", "P749", "P127", "P112")}
        gelir = sr_gelir(e)
        q_idler = [i for lst in ozellikler.values() for i in lst if i.startswith("Q")] + [b for _, b in gelir if b.startswith("Q")]
        etk = etiketler(list(dict.fromkeys(q_idler)))

        def isimler(p):
            return [etk.get(q, "") for q in ozellikler[p] if etk.get(q)]

        return {
            "qid": qid, "ad": etiket(e),
            "ulke": isimler("P17"), "merkez": isimler("P159"),
            "ust_kurum": isimler("P749"), "sahip": isimler("P127"), "kurucu": isimler("P112"),
            "kurulus": degerler(e, "P571")[:1],
            "gelir": [(m, etk.get(b, b)) for m, b in gelir],
        }
    return None


def ad_adaylari(ana, kok):
    adaylar = []
    m = re.search(r'<meta[^>]+property="og:site_name"[^>]+content="([^"]+)"', ana, re.I)
    if m:
        adaylar.append(htmllib.unescape(m.group(1)).strip())
    for parca in re.split(r"\s[|\-–—:]\s", baslik_al(ana))[:2]:
        if parca.strip():
            adaylar.append(parca.strip())
    adaylar.append(kok.split(".")[0].capitalize())
    tekil = []
    for a in adaylar:
        if 2 <= len(a) <= 60 and a not in tekil:
            tekil.append(a)
    return tekil[:4]


def ad_den_kod(ad):
    a = ad.lower()
    for k, u in sr_ULKELER.items():
        if a in (u["en"].lower(), u["tr"].lower()):
            return k
    return None


# ============================================================ RDAP, arşiv, sertifika
def vcard(vc, anahtar):
    for i in vc or []:
        if i and i[0] == anahtar and len(i) > 3:
            d = i[3]
            return " ".join(d) if isinstance(d, list) else str(d)
    return None


def rdap(kok):
    parca = kok.split(".")
    if len(parca) < 2:
        return None
    alan = ".".join(parca[-2:])
    v = al_json("https://rdap.org/domain/" + alan, 12)
    if not v:
        return None
    k = {"alan": alan}
    for ent in v.get("entities", []):
        roller = ent.get("roles", [])
        vc = (ent.get("vcardArray") or [None, []])[1]
        if "registrar" in roller:
            k["kayit_firmasi"] = vcard(vc, "fn")
        if "registrant" in roller:
            k["sahip"] = vcard(vc, "org") or vcard(vc, "fn")
    for ev in v.get("events", []):
        eylem, t = ev.get("eventAction"), (ev.get("eventDate") or "")[:10]
        if eylem == "registration":
            k["kayit"] = t
        if eylem == "expiration":
            k["bitis"] = t
    return k


def arsiv(kok):
    v = al_json("https://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(kok)
                + "/*&output=json&fl=timestamp,original&filter=statuscode:200"
                  "&filter=mimetype:text/html&collapse=timestamp:4&limit=5000", 25)
    if v is None:
        return None
    satirlar = [r for r in v[1:] if len(r) >= 2] if v else []
    if not satirlar:
        return {"var": False}
    yillar = sorted({int(r[0][:4]) for r in satirlar})
    adim = max(1, len(satirlar) // 15)
    ornek = satirlar[::adim][:15]

    def bas(r):
        h = al(f"https://web.archive.org/web/{r[0]}id_/{r[1]}", 15)
        return r[0][:4], (baslik_al(h) if h else "")

    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        sonuc = list(ex.map(bas, ornek))
    degisim, onceki = [], None
    for yil, b in sonuc:
        if b and b != onceki:
            degisim.append((yil, b))
        if b:
            onceki = b
    return {"var": True, "ilk": fmt_ts(satirlar[0][0]), "son": fmt_ts(satirlar[-1][0]),
            "yillar": yillar, "degisim": degisim}


def sertifika(kok):
    v = al_json("https://crt.sh/?q=" + urllib.parse.quote("%." + kok) + "&output=json", 25)
    if v is None:
        return None
    if not isinstance(v, list) or not v:
        return {"var": False}
    tarih = sorted(k["not_before"][:10] for k in v if k.get("not_before"))
    alt = set()
    for k in v:
        for n in (k.get("name_value") or "").split("\n"):
            n = n.strip().lower()
            if n and "*" not in n:
                alt.add(n)
    return {"var": True, "ilk": tarih[0] if tarih else "?", "son": tarih[-1] if tarih else "?",
            "adet": len(v), "altalan": sorted(alt)[:25]}


def vikipedi_ozet(ad):
    """Adla eşleşen Vikipedi maddesinin giriş paragrafını döndürür."""
    arama = vikipedi_ara(ad, 3)
    en_iyi = next((x for x in arama if ad.lower() in x["sr_baslik"].lower()), None)
    if not en_iyi:
        return None
    v = al_json("https://en.wikipedia.org/w/api.php?action=query&prop=extracts&exintro=1"
                "&explaintext=1&format=json&redirects=1&titles="
                + urllib.parse.quote(en_iyi["sr_baslik"]))
    sayfa = next(iter((((v or {}).get("query") or {}).get("pages") or {}).values()), {})
    metin = (sayfa.get("extract") or "").strip()
    if not metin:
        return None
    return {"sr_baslik": en_iyi["sr_baslik"], "link": en_iyi["link"], "ozet": metin[:600]}


HIKAYE_ANAHTAR = re.compile(r"founded|established|was launched|started (?:in|as)|kuruldu|kuruluş|"
                            r"kurulmuş|kurucu", re.I)
HIKAYE_SAYFA = ("about", "hakkimizda", "kurumsal", "hikaye", "our-story", "history")


def kurulus_hikayesi(sayfalar):
    """Sitenin kendi 'hakkında' sayfalarındaki kuruluşla ilgili cümleleri toplar."""
    cumleler = []
    for adres, h in sayfalar.items():
        if not any(y in adres.lower() for y in HIKAYE_SAYFA):
            continue
        for c in re.split(r"(?<=[.!?])\s+", sr_metin_cikar(h)):
            c = c.strip()
            if HIKAYE_ANAHTAR.search(c) and 40 <= len(c) <= 400 and c not in cumleler:
                cumleler.append(c)
    return cumleler[:4]


# ============================================================ KORUYUCU DUVAR (WAF/CDN) — yalnızca pasif tespit
SR_WAF = [
    ("Cloudflare", lambda h, c, b: "cloudflare" in h.get("server", "") or "cf-ray" in h or "__cf_bm" in c or "cf_clearance" in c),
    ("Akamai", lambda h, c, b: "akamai" in h.get("server", "") or any(k.startswith("x-akamai") for k in h)),
    ("Imperva / Incapsula", lambda h, c, b: "x-iinfo" in h or "incap_ses" in c or "visid_incap" in c),
    ("Sucuri", lambda h, c, b: "x-sucuri-id" in h or "sucuri" in h.get("server", "")),
    ("AWS WAF / CloudFront", lambda h, c, b: "x-amz-cf-id" in h or "cloudfront" in h.get("via", "") or "aws-waf-token" in c),
    ("DataDome", lambda h, c, b: "datadome" in c or "x-datadome" in h),
    ("F5 BIG-IP", lambda h, c, b: "bigipserver" in c or "x-wa-info" in h),
    ("Fastly", lambda h, c, b: "fastly" in h.get("via", "") or "x-fastly-request-id" in h),
    ("ModSecurity", lambda h, c, b: "modsecurity" in h.get("server", "") or "mod_security" in h.get("server", "")),
    ("Azure Front Door", lambda h, c, b: "x-azure-ref" in h or "azure" in h.get("server", "")),
    ("Barracuda", lambda h, c, b: "barra_counter_session" in c),
    ("Citrix NetScaler", lambda h, c, b: "ns_af=" in c or "netscaler" in h.get("server", "")),
    ("Reblaze", lambda h, c, b: "rbzid" in c),
    ("StackPath", lambda h, c, b: "x-sp-" in " ".join(h.keys())),
]
SR_ENGEL_IFADE = ("access denied", "attention required", "just a moment", "checking your browser",
                  "request unsuccessful", "captcha", "erişim engellendi", "erişiminiz engellendi")


def sr_yanit_al(url):
    """Ana sayfayı tek istekle alır; durum kodu, başlıklar ve çerezleri döndürür. Tekrar denemez."""
    istek = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*;q=0.8"})
    try:
        with urllib.request.urlopen(istek, timeout=ZAMAN) as c:
            durum, bas, govde = c.status, c.headers.items(), c.read(200000)
    except urllib.error.HTTPError as e:
        durum, bas, govde = e.code, e.headers.items(), e.read(200000)
    except Exception:
        return None
    h, cerez = {}, []
    for k, v in bas:
        if k.lower() == "set-cookie":
            cerez.append(v.lower())
        else:
            h[k.lower()] = v.lower()
    return {"durum": durum, "h": h, "cerez": "; ".join(cerez), "govde": govde.decode("utf-8", "replace").lower()}


def sr_savunma_raporu(y):
    if not y:
        return None
    katmanlar = [ad for ad, kosul in SR_WAF if kosul(y["h"], y["cerez"], y["govde"])]
    engel = (y["durum"] in (403, 429, 503) and any(i in y["govde"] for i in SR_ENGEL_IFADE)) or y["durum"] == 429
    return {"durum": y["durum"], "katmanlar": katmanlar, "engel": engel}


# ============================================================ ülke kararı (IP kullanılmaz)
def ulke_karar(kok, ana, metin, web, tel_listesi, wd_kodlari):
    puan, kanit = Counter(), []
    sehirler = {k: Counter() for k in sr_ULKELER}

    def ekle(kod, w, neden):
        puan[kod] += w
        kanit.append((kod, w, neden))

    tld = kok.rsplit(".", 1)[-1]
    tld_kod = TLD_HARITA.get(tld, tld)
    if tld_kod in sr_ULKELER:
        ekle(tld_kod, 3, f"Alan adı uzantısı .{tld}")
    for t in tel_listesi:
        kodlar = dial_ulkeleri(t)
        for k in kodlar:
            ekle(k, 4 / len(kodlar), f"Sitedeki telefon ülke kodu ({t})")
    m = re.search(r'<html[^>]*\blang="([A-Za-z]{2})', ana, re.I)
    if m:
        dil = m.group(1).lower()
        aday = [k for k, u in sr_ULKELER.items() if dil in u["lang"]]
        if len(aday) == 1:
            ekle(aday[0], 2, f"Sayfa dili: {dil}")
    for kod in wd_kodlari:
        ekle(kod, 6, "Wikidata resmi ülke kaydı")
    for kod, u in sr_ULKELER.items():
        for s in u["cur"]:
            if say(metin, s):
                ekle(kod, 2, f"Para birimi: {s}")
        for ad in (u["en"], u["tr"]):
            n = say(metin, ad)
            if n:
                ekle(kod, (1 if ad in BELIRSIZ else 2) * min(n, 6), f"Sitede ülke adı: {ad} ({n}x)")
            n = say(web, ad)
            if n:
                ekle(kod, min(n, 5) * (0.5 if ad in BELIRSIZ else 1),
                     f"Web sonuçlarında ülke adı: {ad} ({n}x)")
        for s in u["sehir"]:
            n = say(metin, s)
            if n:
                sehirler[kod][s] += n
                ekle(kod, 3 * min(n, 3), f"Sitede şehir: {s} ({n}x)")
            n = say(web, s)
            if n:
                sehirler[kod][s] += n
                ekle(kod, min(n, 3), f"Web sonuçlarında şehir: {s} ({n}x)")
    if not puan:
        return None
    kod, _ = puan.most_common(1)[0]
    oran = puan[kod] / sum(puan.values())
    sehir = sehirler[kod].most_common(1)[0][0] if sehirler[kod] else ""
    kanitlar = sorted([x for x in kanit if x[0] == kod], key=lambda x: -x[1])[:8]
    return {"kod": kod, "oran": oran, "sehir": sehir, "kanit": kanitlar}


def guven(oran):
    if oran >= 0.6:
        return "yüksek"
    if oran >= 0.35:
        return "orta"
    return "düşük"


def sr_yerel_saat(tz):
    simdi = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=tz)
    return simdi.strftime("%H:%M")


# ============================================================ 6) HEPSİ
# ============================================================ ülke, şehir, iletişim (siteden yayımlananlar)
ULKE_ADLARI = {
    "am": ("Ermenistan", "Armenia"), "az": ("Azerbaycan", "Azerbaijan"),
    "tr": ("Türkiye", "Turkey"), "ge": ("Gürcistan", "Georgia"), "ru": ("Rusya", "Russia"),
    "de": ("Almanya", "Germany"), "uk": ("Birleşik Krallık", "United Kingdom"),
    "fr": ("Fransa", "France"), "it": ("İtalya", "Italy"), "es": ("İspanya", "Spain"),
    "nl": ("Hollanda", "Netherlands"), "ca": ("Kanada", "Canada"), "us": ("ABD", "United States"),
    "ir": ("İran", "Iran"), "iq": ("Irak", "Iraq"), "jp": ("Japonya", "Japan"),
    "cn": ("Çin", "China"), "in": ("Hindistan", "India"), "br": ("Brezilya", "Brazil"),
    "kz": ("Kazakistan", "Kazakhstan"), "ua": ("Ukrayna", "Ukraine"), "by": ("Belarus", "Belarus"),
    "pl": ("Polonya", "Poland"), "ae": ("BAE", "UAE"), "sa": ("Suudi Arabistan", "Saudi Arabia"),
    "eg": ("Mısır", "Egypt"), "se": ("İsveç", "Sweden"), "ch": ("İsviçre", "Switzerland"),
    "at": ("Avusturya", "Austria"), "gr": ("Yunanistan", "Greece"), "ro": ("Romanya", "Romania"),
    "bg": ("Bulgaristan", "Bulgaria"), "kr": ("Güney Kore", "South Korea"),
}
TEL_KODLARI = {"+374": "am", "+994": "az", "+90": "tr", "+995": "ge", "+7": "ru", "+1": "us",
               "+44": "uk", "+49": "de", "+33": "fr", "+39": "it", "+34": "es", "+31": "nl",
               "+98": "ir", "+964": "iq", "+380": "ua", "+81": "jp", "+86": "cn", "+91": "in",
               "+55": "br", "+971": "ae", "+966": "sa", "+20": "eg", "+46": "se", "+41": "ch",
               "+82": "kr", "+43": "at", "+30": "gr", "+40": "ro", "+359": "bg", "+48": "pl",
               "+375": "by"}
DIL_ULKE = {"hy": "am", "az": "az", "tr": "tr", "ru": "ru", "ka": "ge", "de": "de", "fr": "fr",
            "it": "it", "es": "es", "nl": "nl", "fa": "ir", "ja": "jp", "zh": "cn", "ko": "kr",
            "uk": "ua", "pl": "pl", "sv": "se"}
CDN_ANAHTARLARI = ("cloudflare", "akamai", "fastly", "amazon", "aws", "google", "microsoft",
                   "azure", "incapsula", "imperva")
ILETISIM_YOLLARI = ["", "iletisim", "contact", "contact-us", "about", "hakkimizda", "bize-ulasin"]
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TEL_METIN_RE = re.compile(r"(?:tel|telefon|phone|çağrı|gsm|whatsapp)[^0-9+]{0,20}"
                          r"(\+?[0-9][0-9 ()./-]{7,20}[0-9])", re.I)
TEL_HREF_RE = re.compile(r'href="tel:([^"]+)"', re.I)
MAIL_HREF_RE = re.compile(r'mailto:([^"?\s]+)', re.I)


def ip_geo(ip):
    """IP'nin yaklaşık konumu ve sahibi (ipapi.co). Sadece tahmindir."""
    try:
        istek = urllib.request.Request(f"https://ipapi.co/{ip}/json/",
                                       headers={"User-Agent": "NetScout/8.0"})
        with urllib.request.urlopen(istek, timeout=10) as c:
            v = json.loads(c.read().decode("utf-8", errors="replace"))
    except Exception:
        return None
    if v.get("error"):
        return None
    return {"kod": (v.get("country") or "").lower(), "ulke": v.get("country_name", ""),
            "sehir": v.get("city", ""), "bolge": v.get("region", ""), "org": v.get("org", "")}


def rdap_bilgisi(alan):
    """Alan adının kayıt bilgisi (kayıt firması, tarihler). Kişisel bilgi genelde gizlidir."""
    parca = alan.split(".")
    if len(parca) < 2 or re.match(r"^\d+\.\d+\.\d+\.\d+$", alan):
        return None
    kok = ".".join(parca[-2:])
    try:
        istek = urllib.request.Request(f"https://rdap.org/domain/{kok}",
                                       headers={"User-Agent": "NetScout/8.0"})
        with urllib.request.urlopen(istek, timeout=12) as c:
            v = json.loads(c.read().decode("utf-8", errors="replace"))
    except Exception:
        return None
    kayit = {"alan": kok}
    for ent in v.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn" and len(item) > 3:
                    kayit["kayit_firmasi"] = item[3]
    for ev in v.get("events", []):
        eylem = ev.get("eventAction", "")
        tarih = (ev.get("eventDate") or "")[:10]
        if eylem == "registration":
            kayit["kayit_tarihi"] = tarih
        if eylem == "expiration":
            kayit["bitis_tarihi"] = tarih
    return kayit


def _sayfa_getir(url, timeout=8):
    istek = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 NetScout/8.0"})
    try:
        with urllib.request.urlopen(istek, timeout=timeout) as c:
            return c.read(600000).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _tel_temizle(t):
    return re.sub(r"\s+", " ", t).strip(" .-")


def _gercek_email(e):
    if e.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")):
        return False
    return not any(x in e for x in ("example", "sentry", "wixpress", "@2x", "domain.com"))


def iletisim_bul(url):
    """Sitenin ana sayfa ve iletişim sayfalarında YAYIMLADIĞI e-posta ve telefonları bulur."""
    p = urllib.parse.urlsplit(url)
    taban = f"{p.scheme}://{p.netloc}"
    emailler, telefonlar, kaynaklar, dil = set(), set(), [], ""
    for yol in ILETISIM_YOLLARI:
        adres = taban + "/" + yol
        html = _sayfa_getir(adres)
        if not html:
            continue
        if not dil:
            m = re.search(r'<html[^>]*\blang="([A-Za-z-]+)"', html, re.I)
            if m:
                dil = m.group(1)
        bulunan = False
        for t in TEL_HREF_RE.findall(html) + TEL_METIN_RE.findall(html):
            telefonlar.add(_tel_temizle(t))
            bulunan = True
        for e in MAIL_HREF_RE.findall(html) + EMAIL_RE.findall(html):
            e = e.lower()
            if _gercek_email(e):
                emailler.add(e)
                bulunan = True
        if bulunan:
            kaynaklar.append(adres)
    telefonlar = {t for t in telefonlar if len(re.sub(r"\D", "", t)) >= 8}
    return {"emailler": sorted(emailler)[:10], "telefonlar": sorted(telefonlar)[:10],
            "dil": dil, "kaynaklar": kaynaklar}


def telefon_ulkesi(tel):
    t = re.sub(r"[^\d+]", "", tel)
    if t.startswith("00"):
        t = "+" + t[2:]
    if not t.startswith("+"):
        return None
    for onek in sorted(TEL_KODLARI, key=len, reverse=True):
        if t.startswith(onek):
            return TEL_KODLARI[onek]
    return None


def ulke_tahmini(host, geo, ilet):
    """Birden çok kanıtı puanlar: alan adı uzantısı, telefon kodu, dil ve IP konumu."""
    puan, kanitlar = {}, []

    def ekle(kod, agirlik, tr_m, en_m):
        if not kod:
            return
        kod = kod.lower()
        puan[kod] = puan.get(kod, 0) + agirlik
        kanitlar.append((kod, agirlik, tr_m, en_m))

    tld = host.rsplit(".", 1)[-1].lower()
    if tld in ULKE_ADLARI:
        ekle(tld, 3, f"Alan adı uzantısı .{tld}", f"Domain extension .{tld}")
    for tel in ilet["telefonlar"]:
        kod = telefon_ulkesi(tel)
        if kod:
            ekle(kod, 4, f"İletişim telefonu {tel} (ülke koduna göre)",
                 f"Contact phone {tel} (by country code)")
    if ilet.get("dil"):
        dk = ilet["dil"].split("-")[0].lower()
        if dk in DIL_ULKE:
            ekle(DIL_ULKE[dk], 1, f"Sayfa dili: {ilet['dil']}", f"Page language: {ilet['dil']}")
    cdn = bool(geo and any(k in (geo.get("org") or "").lower() for k in CDN_ANAHTARLARI))
    if geo and geo.get("kod") and not cdn:
        ekle(geo["kod"], 1, "IP konumu (yaklaşık)", "IP location (approx.)")
    en_olasi = max(puan.items(), key=lambda x: x[1])[0] if puan else None
    return {"en_olasi": en_olasi, "puan": puan, "kanitlar": kanitlar, "cdn": cdn}


def ulke_iletisim_bolumu(url, host, ip, rapor):
    baslik(iki("ÜLKE, ŞEHİR VE İLETİŞİM", "COUNTRY, CITY AND CONTACT"))
    geo = ip_geo(ip)
    rdap = rdap_bilgisi(host)
    ilet = iletisim_bul(url)
    tahmin = ulke_tahmini(host, geo, ilet)
    rapor["geo"] = geo
    rapor["rdap"] = rdap
    rapor["iletisim"] = ilet
    rapor["ulke_tahmini"] = {"en_olasi": tahmin["en_olasi"], "puan": tahmin["puan"]}

    if tahmin["en_olasi"]:
        tr_ad, en_ad = ULKE_ADLARI.get(tahmin["en_olasi"], (tahmin["en_olasi"], tahmin["en_olasi"]))
        basari(iki(f"Sitenin en olası ülkesi: {tr_ad}", f"Most likely country: {en_ad}"))
    else:
        uyari(iki("Ülke için yeterli kanıt bulunamadı.", "Not enough evidence for a country."))
    for _kod, agirlik, tr_m, en_m in tahmin["kanitlar"]:
        print("    · " + iki(tr_m, en_m) + f"  (+{agirlik})")

    if geo:
        print("  " + iki(f"IP konumu (yaklaşık): {geo['ulke']}, {geo['sehir'] or '-'} / {geo['bolge'] or '-'}",
                         f"IP location (approx.): {geo['ulke']}, {geo['sehir'] or '-'} / {geo['bolge'] or '-'}"))
        print("  " + iki(f"IP sahibi: {geo['org'] or '-'}", f"IP owner: {geo['org'] or '-'}"))
    if tahmin["cdn"]:
        uyari(iki("Bu IP bir CDN/bulut sağlayıcıya ait. Yukarıdaki IP konumu sitenin gerçek konumu "
                  "olmayabilir. Ülke tahmininde alan adı ve iletişim bilgisi daha çok ağırlıklı.",
                  "This IP belongs to a CDN/cloud provider. The IP location may not be the site's real "
                  "location. Domain and contact info are weighted more."))
    if rdap:
        print("  " + iki(f"Alan adı: {rdap.get('alan')}", f"Domain: {rdap.get('alan')}"))
        if rdap.get("kayit_firmasi"):
            print("  " + iki(f"Kayıt firması: {rdap['kayit_firmasi']}", f"Registrar: {rdap['kayit_firmasi']}"))
        if rdap.get("kayit_tarihi"):
            print("  " + iki(f"Kayıt tarihi: {rdap['kayit_tarihi']}", f"Registered: {rdap['kayit_tarihi']}"))
        if rdap.get("bitis_tarihi"):
            print("  " + iki(f"Bitiş tarihi: {rdap['bitis_tarihi']}", f"Expires: {rdap['bitis_tarihi']}"))

    if ilet["emailler"] or ilet["telefonlar"]:
        baslik(iki("Siteden yayımlanmış iletişim bilgileri", "Contact details published on the site"))
        for t in ilet["telefonlar"]:
            print(f"  Tel     : {t}")
        for e in ilet["emailler"]:
            print(f"  E-posta : {e}")
        for k in ilet["kaynaklar"]:
            print(renk(f"    kaynak: {k}", "0;37"))
        print(renk("  " + iki("Not: Bunlar sitenin kendi yayımladığı bilgilerdir. "
                              "Kişisel veri toplamak için kullanma.",
                              "Note: Published by the site itself. Do not use them to collect personal data."),
                   "0;37"))
# ============================================================ kritik portların derin kontrolü (pasif)
def _tcp_al(ip, port, gonder=b"", bekle=4.0):
    try:
        with socket.create_connection((ip, port), timeout=bekle) as s:
            s.settimeout(bekle)
            if gonder:
                s.sendall(gonder)
            try:
                return s.recv(2048)
            except socket.timeout:
                return b""
    except OSError:
        return None


def _http_al(ip, port, yol):
    import http.client
    try:
        c = http.client.HTTPConnection(ip, port, timeout=4)
        c.request("GET", yol, headers={"User-Agent": "NetScout/8.0"})
        r = c.getresponse()
        govde = r.read(4096).decode("utf-8", errors="replace")
        c.close()
        return r.status, govde
    except Exception:
        return None, ""


def _ftp_anonim(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=4) as s:
            s.recv(1024)
            s.sendall(b"USER anonymous\r\n")
            s.recv(1024)
            s.sendall(b"PASS netscout@local\r\n")
            cevap = s.recv(1024)
            s.sendall(b"QUIT\r\n")
            return cevap.startswith(b"230")
    except OSError:
        return False


def _vnc_sifresiz(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=4) as s:
            s.recv(12)
            s.sendall(b"RFB 003.008\n")
            n = s.recv(1)
            if not n:
                return False
            tipler = s.recv(n[0])
            return 1 in tipler
    except OSError:
        return False


def _smtp_ehlo(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=4) as s:
            s.recv(512)
            s.sendall(b"EHLO netscout.local\r\n")
            return s.recv(2048)
    except OSError:
        return b""


def derin_bulgu(ip, port):
    """(seviye, tr_metin, en_metin). Sadece bağlanıp bakar, giriş denemesi veya sömürü yapmaz."""
    if port == 9200:
        durum, govde = _http_al(ip, port, "/")
        surum = re.search(r'"number"\s*:\s*"([^"]+)"', govde)
        surum_metni = f" (sürüm {surum.group(1)})" if surum else ""
        if durum == 200 and "cluster_name" in govde:
            return ("kritik", f"Elasticsearch kimlik doğrulamasız erişilebilir{surum_metni}. Veriler açık olabilir.",
                    f"Elasticsearch is reachable without authentication{surum_metni}. Data may be exposed.")
        if durum in (401, 403):
            return ("bilgi", f"Elasticsearch kimlik doğrulaması istiyor (iyi){surum_metni}.",
                    f"Elasticsearch requires authentication (good){surum_metni}.")
        return ("uyari", "Elasticsearch portu açık, anlamlı yanıt alınamadı.",
                "Elasticsearch port is open, no meaningful reply.")
    if port == 2375:
        durum, govde = _http_al(ip, port, "/version")
        surum = re.search(r'"Version"\s*:\s*"([^"]+)"', govde)
        surum_metni = f" (Docker {surum.group(1)})" if surum else ""
        if durum == 200 and "ApiVersion" in govde:
            return ("kritik", f"Docker API şifresiz açık{surum_metni}. Konteyner çalıştırılabilir.",
                    f"Docker API is open without a password{surum_metni}. Containers can be run.")
        return ("uyari", "Docker portu açık, yanıt alınamadı.", "Docker port is open, no reply.")
    if port == 110:
        try:
            with socket.create_connection((ip, port), timeout=4) as s:
                s.recv(512)
                s.sendall(b"CAPA\r\n")
                cevap = s.recv(1024).upper()
        except OSError:
            cevap = b""
        if b"STLS" in cevap:
            return ("bilgi", "POP3 şifreli bağlantıyı (STLS) destekliyor.",
                    "POP3 supports encrypted connection (STLS).")
        if b"USER" in cevap:
            return ("kritik", "POP3 şifresiz kullanıcı girişi kabul ediyor. Şifreler düz metin gider.",
                    "POP3 accepts plain user login. Passwords travel in plain text.")
        return ("uyari", "POP3 portu açık. Şifreli bağlantı kullanıldığından emin ol.",
                "POP3 port is open. Make sure encrypted access is used.")
    if port == 587:
        cevap = _smtp_ehlo(ip, port).upper()
        if b"AUTH" in cevap and b"STARTTLS" not in cevap:
            return ("kritik", "Gönderim sunucusu (587) kimlik doğrulamayı şifresiz sunuyor.",
                    "Submission server (587) offers authentication without encryption.")
        if b"STARTTLS" in cevap:
            return ("bilgi", "Gönderim sunucusu (587) STARTTLS destekliyor.",
                    "Submission server (587) supports STARTTLS.")
        return ("uyari", "587 portu açık, STARTTLS görünmüyor.",
                "Port 587 is open, STARTTLS not visible.")
    if port == 3306:
        try:
            with socket.create_connection((ip, port), timeout=4) as s:
                veri = s.recv(256)
        except OSError:
            veri = b""
        if len(veri) > 6 and veri[4] == 0x0A:
            surum = veri[5:].split(b"\x00")[0].decode("latin-1", "replace")
            return ("uyari", f"MySQL dışarıdan erişilebilir (sürüm {surum}). Sadece iç ağa izin ver.",
                    f"MySQL is reachable from outside (version {surum}). Allow only the internal network.")
        return ("uyari", "MySQL portu açık. Sadece iç ağdan erişilmeli.",
                "MySQL port is open. Internal network only.")
    if port == 5432:
        cevap = _tcp_al(ip, port, b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        if cevap and cevap[:1] == b"N":
            return ("kritik", "PostgreSQL dışarıda açık ve şifreli bağlantıyı desteklemiyor.",
                    "PostgreSQL is open to the outside and does not support encrypted connections.")
        if cevap and cevap[:1] == b"S":
            return ("uyari", "PostgreSQL dışarıda açık ama şifreli bağlantıyı destekliyor. İç ağa kısıtla.",
                    "PostgreSQL is open but supports encryption. Restrict it to the internal network.")
        return ("uyari", "PostgreSQL portu açık.", "PostgreSQL port is open.")
    if port == 11211:
        cevap = _tcp_al(ip, port, b"stats\r\n")
        if cevap and b"STAT " in cevap:
            return ("kritik", "Memcached kimlik doğrulamasız istatistik veriyor. Kapat.",
                    "Memcached returns statistics without authentication. Close it.")
        return ("uyari", "Memcached portu açık.", "Memcached port is open.")
    if port == 873:
        cevap = _tcp_al(ip, port, b"")
        if cevap and cevap.startswith(b"@RSYNCD"):
            return ("uyari", "rsync açık. Dosya modülleri dışarıdan listelenebilir olabilir.",
                    "rsync is open. File modules may be listable from outside.")
        return ("uyari", "873 portu açık.", "Port 873 is open.")
    if port == 5984:
        durum, govde = _http_al(ip, port, "/_all_dbs")
        if durum == 200:
            return ("kritik", "CouchDB veritabanı listesi kimlik doğrulamasız açık.",
                    "CouchDB database list is open without authentication.")
        return ("uyari", "CouchDB açık. Kimlik doğrulamasını kontrol et.",
                "CouchDB is open. Check authentication.")
    if port == 6443:
        durum, govde = _https_al(ip, port, "/api/v1/namespaces")
        if durum == 200:
            return ("kritik", "Kubernetes API kimliksiz erişilebilir. Acil kapat.",
                    "Kubernetes API is reachable without authentication. Close urgently.")
        return ("uyari", "Kubernetes API dışarıda açık. IP kısıtı koy.",
                "Kubernetes API is open to the outside. Add IP restrictions.")
    if port == 22:
        cevap = _tcp_al(ip, port, b"")
        if cevap and cevap.startswith(b"SSH-"):
            surum = cevap.split(b"\n")[0].decode("latin-1", "replace").strip()
            if re.search(r"OpenSSH_[0-6]\.", surum):
                return ("kritik", f"Çok eski SSH sürümü: {surum}. Hemen güncelle.",
                        f"Very old SSH version: {surum}. Update immediately.")
            return ("bilgi", f"SSH sürümü: {surum}. Parola yerine anahtar kullan, kök girişini kapat.",
                    f"SSH version: {surum}. Use keys instead of passwords, disable root login.")
        return ("uyari", "SSH portu açık. Parola girişini kapat, anahtar kullan.",
                "SSH port is open. Disable password login, use keys.")
    if port == 3389:
        istek = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        cevap = _tcp_al(ip, port, istek)
        if cevap and len(cevap) >= 19 and cevap[11] == 0x02:
            secilen = struct.unpack("<I", cevap[15:19])[0]
            if secilen == 0:
                return ("kritik", "RDP NLA/TLS istemiyor. Eski ve zayıf RDP güvenliği açık.",
                        "RDP does not require NLA/TLS. Old, weak RDP security is exposed.")
            return ("bilgi", "RDP NLA/TLS destekliyor (iyi). Yine de VPN arkasına al.",
                    "RDP supports NLA/TLS (good). Still put it behind a VPN.")
        return ("uyari", "RDP açık. VPN arkasına al.", "RDP is open. Put it behind a VPN.")
    if port == 143:
        try:
            with socket.create_connection((ip, port), timeout=4) as s:
                s.recv(512)
                s.sendall(b"a1 CAPABILITY\r\n")
                cevap = s.recv(1024).upper()
        except OSError:
            cevap = b""
        if b"LOGINDISABLED" in cevap:
            return ("bilgi", "IMAP düz metin girişi kapalı, şifreli bağlantı zorunlu.",
                    "IMAP plain login is disabled, encrypted connection is required.")
        if cevap:
            return ("uyari", "IMAP'te düz metin girişi açık görünüyor. STARTTLS zorunlu yap.",
                    "IMAP plain login appears enabled. Require STARTTLS.")
        return ("uyari", "IMAP portu açık.", "IMAP port is open.")
    if port == 6379:
        cevap = _tcp_al(ip, port, b"*1\r\n$4\r\nPING\r\n")
        if cevap and cevap.startswith(b"+PONG"):
            return ("kritik", "Redis kimlik doğrulamasız çalışıyor. Herkes veriyi okuyup değiştirebilir.",
                    "Redis works without authentication. Anyone can read and modify the data.")
        return ("uyari", "Redis portu açık. PING'e yanıt yok, muhtemelen parolalı.",
                "Redis port is open. No PING reply, probably password protected.")
    if port == 9200:
        durum, govde = _http_al(ip, port, "/")
        if durum == 200 and "cluster_name" in govde:
            return ("kritik", "Elasticsearch kimlik doğrulamasız erişilebilir. Veriler açık olabilir.",
                    "Elasticsearch is reachable without authentication. Data may be exposed.")
        if durum in (401, 403):
            return ("bilgi", "Elasticsearch kimlik doğrulaması istiyor (iyi).",
                    "Elasticsearch requires authentication (good).")
        return ("uyari", "Elasticsearch portu açık, anlamlı yanıt alınamadı.",
                "Elasticsearch port is open, no meaningful reply.")
    if port == 2375:
        durum, govde = _http_al(ip, port, "/version")
        if durum == 200 and "ApiVersion" in govde:
            return ("kritik", "Docker API şifresiz açık. Sunucuda konteyner çalıştırılabilir.",
                    "Docker API is open without a password. Containers can be run on the server.")
        return ("uyari", "Docker portu açık, yanıt alınamadı.", "Docker port is open, no reply.")
    if port == 21:
        if _ftp_anonim(ip, port):
            return ("kritik", "FTP anonim (anonymous) girişe açık.",
                    "FTP allows anonymous login.")
        return ("uyari", "FTP açık, anonim giriş kapalı görünüyor. Düz metin kullanır.",
                "FTP is open, anonymous login seems disabled. Uses plain text.")
    if port == 23:
        return ("kritik", "Telnet açık. Parolalar düz metin gider.",
                "Telnet is open. Passwords are sent in plain text.")
    if port == 5900:
        if _vnc_sifresiz(ip, port):
            return ("kritik", "VNC şifresiz (güvenlik türü None). Ekran herkese açık.",
                    "VNC has no password (security type None). Screen is open to anyone.")
        return ("uyari", "VNC açık, kimlik doğrulama istiyor.", "VNC is open and requires authentication.")
    if port == 3389:
        return ("uyari", "RDP açık. En sık saldırı hedeflerinden biri. VPN arkasına al.",
                "RDP is open. One of the most attacked services. Put it behind a VPN.")
    if port in (135, 139, 445):
        return ("uyari", "Windows paylaşım/RPC portu dışarıda açık.",
                "Windows share/RPC port is exposed to the outside.")
    if port in (1433, 1521, 3306, 5432, 27017):
        return ("uyari", "Veritabanı dışarıdan erişilebilir. Sadece iç ağa izin ver.",
                "Database is reachable from outside. Allow only the internal network.")
    if port == 25:
        cevap = _smtp_ehlo(ip, port)
        if b"AUTH" in cevap.upper() and b"STARTTLS" not in cevap.upper():
            return ("kritik", "SMTP kimlik doğrulamasını şifresiz (STARTTLS yok) sunuyor.",
                    "SMTP offers authentication without encryption (no STARTTLS).")
        if b"STARTTLS" in cevap.upper():
            return ("bilgi", "SMTP STARTTLS destekliyor (şifreli iletişim var).",
                    "SMTP supports STARTTLS (encrypted transport).")
        return ("uyari", "SMTP'de STARTTLS görünmüyor. Mail şifresiz gidebilir.",
                "STARTTLS not visible on SMTP. Mail may travel unencrypted.")
    if port == 110:
        return ("uyari", "POP3 açık. Şifreli bağlantı (995) kullanıldığından emin ol.",
                "POP3 is open. Make sure encrypted access (995) is used.")
    return ("uyari", "Açık tehlikeli port. Gerekli değilse kapat.",
            "Open dangerous port. Close it if not needed.")


def kritik_derin_kontrol(ip, satirlar):
    acik = [s["port"] for s in satirlar if s["port"] in RISKLI_PORTLAR]
    baslik(iki("KRİTİK PORTLARIN DERİN KONTROLÜ (pasif, giriş denemesi yok)",
               "DEEP CHECK OF CRITICAL PORTS (passive, no login attempts)"))
    if not acik:
        basari(iki("Açık kritik port yok, derin kontrol gerekmedi.",
                   "No open critical ports, no deep check needed."))
        return []
    sonuc = []
    for port in acik:
        seviye, tr_m, en_m = derin_bulgu(ip, port)
        ad, aciklama = RISKLI_PORTLAR[port]
        etiket = "KRİTİK" if seviye == "kritik" else ("UYARI" if seviye == "uyari" else "BİLGİ")
        kod = KIRMIZI if seviye == "kritik" else (SARI if seviye == "uyari" else "1;32")
        print(renk(f"  [{etiket}] {port}/tcp {ad}: {iki(tr_m, en_m)}", kod))
        print("      -> " + aciklama.get(DIL, aciklama["tr"]))
        sonuc.append({"port": port, "ad": ad, "seviye": seviye, "bulgu": iki(tr_m, en_m)})
    print()
    print(renk("  " + iki("Genel yapılacaklar:", "General actions:"), "1;33"))
    print("   1) " + iki("Gerekmeyen kritik portları güvenlik duvarında (firewall) kapat.",
                         "Close unneeded critical ports in the firewall."))
    print("   2) " + iki("Gerekli olanlara sadece güvenilen IP'lerden erişime izin ver.",
                         "Allow needed ones only from trusted IPs."))
    print("   3) " + iki("Servislerin güncel sürümde olduğundan ve parolalı çalıştığından emin ol.",
                         "Make sure services are up to date and password protected."))
    return sonuc


def _https_al(ip, port, yol):
    import http.client
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        c = http.client.HTTPSConnection(ip, port, timeout=4, context=ctx)
        c.request("GET", yol, headers={"User-Agent": "NetScout/8.0"})
        r = c.getresponse()
        govde = r.read(2048).decode("utf-8", errors="replace")
        c.close()
        return r.status, govde
    except Exception:
        return None, ""


# ============================================================ ülke ve şehir analizi (siteye göre)
ULKELER = {
    "am": {"tr": "Ermenistan", "en": "Armenia", "adlar": ["Armenia", "Ermenistan", "Հայաստան", "Hayastan"],
           "sehirler": ["Yerevan", "Erivan", "Gyumri", "Vanadzor", "Kapan", "Hrazdan", "Abovyan",
                        "Echmiadzin", "Ejmiatsin", "Ararat", "Sevan"], "tz": 4, "dial": "+374", "dil": "hy"},
    "az": {"tr": "Azerbaycan", "en": "Azerbaijan", "adlar": ["Azerbaijan", "Azerbaycan", "Azərbaycan"],
           "sehirler": ["Baku", "Bakı", "Ganja", "Gəncə", "Sumqayit", "Sumgait", "Lankaran", "Shaki",
                        "Mingachevir"], "tz": 4, "dial": "+994", "dil": "az"},
    "tr": {"tr": "Türkiye", "en": "Turkey", "adlar": ["Türkiye", "Turkey", "Turkiye"],
           "sehirler": ["İstanbul", "Istanbul", "Ankara", "İzmir", "Izmir", "Bursa", "Antalya", "Adana",
                        "Konya", "Gaziantep", "Mersin", "Trabzon"], "tz": 3, "dial": "+90", "dil": "tr"},
    "ge": {"tr": "Gürcistan", "en": "Georgia", "adlar": ["Georgia", "Gürcistan", "საქართველო"],
           "sehirler": ["Tbilisi", "Tiflis", "Batumi", "Kutaisi", "Rustavi"], "tz": 4, "dial": "+995", "dil": "ka"},
    "ru": {"tr": "Rusya", "en": "Russia", "adlar": ["Russia", "Rusya", "Россия"],
           "sehirler": ["Moscow", "Moskova", "Москва", "Saint Petersburg", "St. Petersburg", "Kazan",
                        "Novosibirsk"], "tz": 3, "dial": "+7", "dil": "ru"},
    "ua": {"tr": "Ukrayna", "en": "Ukraine", "adlar": ["Ukraine", "Ukrayna", "Україна"],
           "sehirler": ["Kyiv", "Kiev", "Kharkiv", "Odesa", "Lviv", "Dnipro"], "tz": 2, "dial": "+380", "dil": "uk"},
    "de": {"tr": "Almanya", "en": "Germany", "adlar": ["Germany", "Almanya", "Deutschland"],
           "sehirler": ["Berlin", "Munich", "München", "Hamburg", "Frankfurt", "Cologne", "Köln"],
           "tz": 1, "dial": "+49", "dil": "de"},
    "fr": {"tr": "Fransa", "en": "France", "adlar": ["France", "Fransa"],
           "sehirler": ["Paris", "Lyon", "Marseille", "Nice", "Toulouse"], "tz": 1, "dial": "+33", "dil": "fr"},
    "it": {"tr": "İtalya", "en": "Italy", "adlar": ["Italy", "İtalya", "Italia"],
           "sehirler": ["Rome", "Roma", "Milan", "Milano", "Naples", "Napoli", "Turin"], "tz": 1,
           "dial": "+39", "dil": "it"},
    "es": {"tr": "İspanya", "en": "Spain", "adlar": ["Spain", "İspanya", "España"],
           "sehirler": ["Madrid", "Barcelona", "Valencia", "Seville", "Sevilla"], "tz": 1,
           "dial": "+34", "dil": "es"},
    "us": {"tr": "ABD", "en": "United States", "adlar": ["United States", "USA", "ABD",
                                                       "Amerika Birleşik Devletleri"],
           "sehirler": ["New York", "Los Angeles", "San Francisco", "Chicago", "Houston", "Miami",
                        "Seattle", "Washington"], "tz": -5, "dial": "+1", "dil": "en"},
    "ca": {"tr": "Kanada", "en": "Canada", "adlar": ["Canada", "Kanada"],
           "sehirler": ["Toronto", "Montreal", "Montréal", "Vancouver", "Ottawa", "Calgary"],
           "tz": -5, "dial": "", "dil": "en"},
    "uk": {"tr": "Birleşik Krallık", "en": "United Kingdom", "adlar": ["United Kingdom", "Birleşik Krallık",
                                                                   "Great Britain", "England"],
           "sehirler": ["London", "Manchester", "Birmingham", "Edinburgh"], "tz": 0, "dial": "+44", "dil": "en"},
    "ir": {"tr": "İran", "en": "Iran", "adlar": ["Iran", "İran", "ایران"],
           "sehirler": ["Tehran", "Tahran", "Isfahan", "Mashhad", "Tabriz", "Shiraz"], "tz": 3.5,
           "dial": "+98", "dil": "fa"},
    "ae": {"tr": "BAE", "en": "UAE", "adlar": ["UAE", "BAE", "United Arab Emirates", "Birleşik Arap Emirlikleri"],
           "sehirler": ["Dubai", "Abu Dhabi", "Sharjah"], "tz": 4, "dial": "+971", "dil": "ar"},
    "sa": {"tr": "Suudi Arabistan", "en": "Saudi Arabia", "adlar": ["Saudi Arabia", "Suudi Arabistan"],
           "sehirler": ["Riyadh", "Jeddah", "Mecca", "Makkah", "Medina", "Dammam"], "tz": 3,
           "dial": "+966", "dil": "ar"},
    "iq": {"tr": "Irak", "en": "Iraq", "adlar": ["Iraq", "Irak"],
           "sehirler": ["Baghdad", "Bağdat", "Basra", "Erbil", "Mosul"], "tz": 3, "dial": "+964", "dil": "ar"},
}
SCRIPT_KURALLARI = [("am", r"[\u0531-\u058F]", 3), ("ge", r"[\u10A0-\u10FF]", 3),
                    ("ua", r"[іїєґІЇЄҐ]", 2), ("ru", r"[\u0400-\u04FF]", 1), ("ir", r"[پچژگ]", 2)]
PARA_KURALLARI = [("az", "₼", 3), ("am", "֏", 3), ("ge", "₾", 3), ("ru", "₽", 3),
                  ("ua", "₴", 3), ("tr", "₺", 2), ("uk", "£", 1)]
ADRES_RE = re.compile(r"[^.|]{0,80}\b(?:Street|St\.|Avenue|Ave\.|Road|Blvd|Boulevard|Caddesi|Cad\.|"
                      r"Sokak|Sok\.|Mahallesi|Mah\.|Bulvar|Bulvarı|Փողոց)\b[^.|]{0,60}", re.I)


def sayfa_topla(url, timeout=8):
    p = urllib.parse.urlsplit(url)
    taban = f"{p.scheme}://{p.netloc}"
    parcalar, kaynaklar = [], []
    for yol in ILETISIM_YOLLARI:
        adres = taban + "/" + yol
        h = _sayfa_getir(adres, timeout)
        if h:
            parcalar.append(h)
            kaynaklar.append(adres)
    return {"html": "\n".join(parcalar), "kaynaklar": kaynaklar}


def metin_cikar(html):
    import html as _htmllib
    t = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.S | re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    return re.sub(r"\s+", " ", _htmllib.unescape(t))


def web_arama_metni(host):
    """DuckDuckGo üzerinden siteyle ilgili arama sonuçlarının metnini alır."""
    import html as _htmllib
    sorgu = f'"{host}" company address contact'
    url = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(sorgu)
    istek = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) NetScout/8.0"})
    try:
        with urllib.request.urlopen(istek, timeout=12) as c:
            sayfa = c.read(400000).decode("utf-8", errors="replace")
    except Exception:
        return "", False
    parcalar = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', sayfa, re.S)
    parcalar += re.findall(r'class="result__title"[^>]*>(.*?)</a>', sayfa, re.S)
    metin = " ".join(re.sub(r"<[^>]+>", " ", p) for p in parcalar)
    return _htmllib.unescape(metin), bool(parcalar)


def _say(metin, kelime):
    return len(re.findall(r"(?<!\w)" + re.escape(kelime) + r"(?!\w)", metin, re.IGNORECASE))


def dial_ulkesi(numara):
    t = re.sub(r"[^\d+]", "", numara)
    if t.startswith("00"):
        t = "+" + t[2:]
    if not t.startswith("+"):
        return None
    harita = {u["dial"]: k for k, u in ULKELER.items() if u.get("dial")}
    for onek in sorted(harita, key=len, reverse=True):
        if t.startswith(onek):
            return harita[onek]
    return None


def iletisim_coz(html):
    emailler, telefonlar = set(), set()
    for t in TEL_HREF_RE.findall(html) + TEL_METIN_RE.findall(html):
        telefonlar.add(_tel_temizle(t))
    for e in MAIL_HREF_RE.findall(html) + EMAIL_RE.findall(html):
        e = e.lower()
        if _gercek_email(e):
            emailler.add(e)
    telefonlar = {t for t in telefonlar if len(re.sub(r"\D", "", t)) >= 8}
    return {"emailler": sorted(emailler)[:10], "telefonlar": sorted(telefonlar)[:10]}


def adres_bul(metin):
    sonuc = []
    for m in ADRES_RE.finditer(metin):
        s = m.group(0).strip()
        if s and s not in sonuc:
            sonuc.append(s)
        if len(sonuc) >= 2:
            break
    return sonuc


def ulke_puanla(host, html, metin, arama, ilet, geo):
    puan, kanit, sehir_bul = {}, [], {}

    def ekle(kod, agirlik, tr_m, en_m):
        if not kod:
            return
        puan[kod] = puan.get(kod, 0) + agirlik
        kanit.append((kod, agirlik, tr_m, en_m))

    tld = host.rsplit(".", 1)[-1].lower()
    if tld in ULKELER:
        ekle(tld, 3, f"Alan adı uzantısı .{tld}", f"Domain extension .{tld}")

    dil_etiketi = re.search(r'<html[^>]*\blang="([A-Za-z]{2})', html, re.I)
    if dil_etiketi:
        dil = dil_etiketi.group(1).lower()
        adaylar = [k for k, u in ULKELER.items() if u["dil"] == dil]
        if len(adaylar) == 1:
            ekle(adaylar[0], 2, f"Sayfa dili: {dil}", f"Page language: {dil}")

    for kod, desen, w in SCRIPT_KURALLARI:
        if len(re.findall(desen, metin)) >= 15:
            ekle(kod, w, f"Metnin yazı sistemi ({kod.upper()})", f"Text script ({kod.upper()})")
    for kod, sembol, w in PARA_KURALLARI:
        if sembol in metin:
            ekle(kod, w, f"Para birimi işareti {sembol}", f"Currency sign {sembol}")

    for kod, u in ULKELER.items():
        toplam = sum(_say(metin, ad) for ad in u["adlar"])
        if toplam:
            ekle(kod, 2 * min(toplam, 6), f"Sitede ülke adı geçiyor ({toplam}x)",
                 f"Country name on site ({toplam}x)")
        for sehir in u["sehirler"]:
            c = _say(metin, sehir)
            if c:
                sehir_bul.setdefault(kod, []).append((sehir, c))
                ekle(kod, 3 * min(c, 3), f"Sitede şehir geçiyor: {sehir} ({c}x)",
                     f"City on site: {sehir} ({c}x)")

    if arama:
        for kod, u in ULKELER.items():
            toplam = sum(_say(arama, ad) for ad in u["adlar"])
            sehirler = [(s, _say(arama, s)) for s in u["sehirler"]]
            sehirler = [x for x in sehirler if x[1]]
            if toplam or sehirler:
                ekle(kod, 2, "Web aramasındaki siteyle ilgili sonuçlarda geçiyor",
                     "Appears in web search results about the site")
                for s, c in sehirler:
                    sehir_bul.setdefault(kod, []).append((s, c))

    for tel in ilet["telefonlar"]:
        kod = dial_ulkesi(tel)
        if kod:
            ekle(kod, 4, f"Sitede telefon ülke kodu: {tel}", f"Phone country code on site: {tel}")

    if geo and geo.get("kod") and not any(k in (geo.get("org") or "").lower() for k in CDN_ANAHTARLARI):
        ekle(geo["kod"], 0.5, "IP konumu (zayıf kanıt)", "IP location (weak evidence)")

    if not puan:
        return {"en": None, "puan": {}, "kanit": [], "sehir_bul": {}, "oran": 0}
    en = max(puan, key=puan.get)
    return {"en": en, "puan": puan, "kanit": kanit, "sehir_bul": sehir_bul,
            "oran": puan[en] / sum(puan.values())}


def bayrak_emoji(kod):
    kod = (kod or "").upper()
    if len(kod) != 2 or not kod.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in kod)


def guven_etiketi(oran):
    if oran >= 0.6:
        return iki("yüksek", "high")
    if oran >= 0.35:
        return iki("orta", "medium")
    return iki("düşük", "low")


def yerel_saat(tz):
    import datetime
    simdi = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=tz)
    return simdi.strftime("%H:%M")


def dis_kaynak_arastirma(host, en_fazla=300):
    """Siteyle ilgili arama sonuçlarındaki en fazla 40 sayfayı okur (ülke/şehir/geçmiş ipuçları için)."""
    from concurrent.futures import ThreadPoolExecutor
    ekler = ["company", "about", "address", "owner", "review", "history", "contact", "country",
             "founded", "former name", "renamed", "news", "wikipedia", "registration", "location",
             "headquarters", "team", "services", "legal", "privacy"]
    sorgular = [f'"{host}"'] + [f'"{host}" {e}' for e in ekler]
    linkler = []
    for sorgu in sorgular:
        if len(linkler) >= en_fazla:
            break
        istek = urllib.request.Request("https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(sorgu),
                                       headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) NetScout/1.0"})
        try:
            with urllib.request.urlopen(istek, timeout=12) as c:
                sayfa = c.read(400000).decode("utf-8", errors="replace")
        except Exception:
            continue
        for link in re.findall(r'class="result__a"[^>]*href="([^"]+)"', sayfa):
            if "uddg=" in link:
                link = urllib.parse.unquote(link.split("uddg=", 1)[1].split("&", 1)[0])
            if not link.startswith("http") or host in link or link in linkler:
                continue
            linkler.append(link)
            if len(linkler) >= en_fazla:
                break

    def al(link):
        h = _sayfa_getir(link, timeout=8)
        return metin_cikar(h)[:20000] if h else ""

    with ThreadPoolExecutor(max_workers=8) as ex:
        metinler = list(ex.map(al, linkler))
    dolu = [m for m in metinler if m]
    return {"sayfa": len(dolu), "urls": linkler, "metin": " ".join(dolu)}


def ulke_analizi_v2(url, host, ip, rapor):
    baslik(iki("ÜLKE VE ŞEHİR ANALİZİ (siteye ve web kayıtlarına göre)",
               "COUNTRY AND CITY ANALYSIS (site content and web records)"))
    bilgi(iki("Site içeriği okunuyor (ana sayfa, iletişim, hakkımızda)...",
              "Reading site content (home, contact, about)..."))
    sayfa = sayfa_topla(url)
    html = sayfa["html"]
    metin = metin_cikar(html)
    bilgi(iki("Web'de siteyle ilgili kayıtlar aranıyor (DuckDuckGo)...",
              "Searching the web for records about the site (DuckDuckGo)..."))
    arama, arama_var = web_arama_metni(host)
    dis = dis_kaynak_arastirma(host)
    arama = arama + " " + dis["metin"]
    arama_var = arama_var or dis["sayfa"] > 0
    bilgi(iki(f"{dis['sayfa']} dış kaynak incelendi.", f"{dis['sayfa']} external sources reviewed."))
    if not arama_var:
        uyari(iki("Web aramasından sonuç alınamadı. Analiz sadece siteye göre yapıldı.",
                  "No web search results. Analysis is based on the site only."))
    ilet = iletisim_coz(html)
    geo = ip_geo(ip)
    sonuc = ulke_puanla(host, html, metin, arama, ilet, None)  # IP konumu kullanılmıyor
    rapor["ulke"] = {"en": sonuc["en"], "oran": round(sonuc["oran"], 2), "puan": sonuc["puan"]}

    if not sonuc["en"]:
        uyari(iki("Ülke için kanıt bulunamadı.", "No country evidence found."))
    else:
        kod = sonuc["en"]
        u = ULKELER.get(kod)
        ad = (u["tr"] if DIL == "tr" else u["en"]) if u else kod.upper()
        tz = u["tz"] if u else 0
        agg = {}
        for s, c in sonuc["sehir_bul"].get(kod, []):
            agg[s] = agg.get(s, 0) + c
        sehir = max(agg.items(), key=lambda x: x[1])[0] if agg else ""
        satirlar = [
            f"{bayrak_emoji(kod)}  {ad}   {iki('güven', 'confidence')}: "
            f"{guven_etiketi(sonuc['oran'])} (%{int(sonuc['oran'] * 100)})",
            f"{iki('Şehir', 'City')}: {sehir or iki('siteden belirlenemedi', 'not determined from site')}",
        ]
        if u:
            satirlar += [
                f"{iki('Yerel saat', 'Local time')}: {yerel_saat(tz)} (UTC{tz:+g})",
                f"{iki('Sayfa dili', 'Page language')}: {u['dil']}",
            ]
        kutu(satirlar, "1;32")
        for _k, w, tr_m, en_m in sorted(sonuc["kanit"], key=lambda x: x[1], reverse=True)[:6]:
            print("    · " + iki(tr_m, en_m) + f"  (+{w:g})")
        if geo and not sonuc["oran"] >= 0.35:
            uyari(iki("Güven düşük. Sonuç IP konumuna çok yaslanmadı, ama bir yanlışlık olabilir.",
                      "Low confidence. It does not rely on IP location much, but may still be wrong."))

    adresler = adres_bul(metin)
    if ilet["telefonlar"] or ilet["emailler"] or adresler:
        baslik(iki("Sitede yazılı iletişim bilgileri", "Contact details written on the site"))
        for t in ilet["telefonlar"]:
            print(f"  Tel     : {t}")
        for e in ilet["emailler"]:
            print(f"  E-posta : {e}")
        for a in adresler:
            print(f"  Adres   : {a}")
        print(renk("  " + iki("Not: Bunlar sitenin kendi yayımladığı bilgilerdir.",
                             "Note: These are published by the site itself."), "0;37"))
    rapor["iletisim"] = {"telefonlar": ilet["telefonlar"], "emailler": ilet["emailler"], "adresler": adresler}


# ============================================================ savunma katmanları, geçmiş, site taraması (v1.0)
WAF_IMZALARI = [
    ("Cloudflare", lambda b: "cloudflare" in b.get("server", "").lower() or "cf-ray" in b,
     {"tr": "Trafik Cloudflare üzerinden geçiyor. Gerçek sunucu IP'si gizlenmiş olabilir.",
      "en": "Traffic goes through Cloudflare. The real server IP may be hidden."}),
    ("Akamai", lambda b: "akamai" in b.get("server", "").lower() or any(k.startswith("x-akamai") for k in b),
     {"tr": "Akamai CDN/WAF kullanılıyor.", "en": "Akamai CDN/WAF in use."}),
    ("AWS CloudFront / ELB", lambda b: "cloudfront" in b.get("via", "").lower() or "x-amz-cf-id" in b
     or "awselb" in b.get("server", "").lower(),
     {"tr": "AWS yük dengeleyici veya CloudFront kullanılıyor.",
      "en": "AWS load balancer or CloudFront in use."}),
    ("Sucuri", lambda b: "x-sucuri-id" in b or "sucuri" in b.get("server", "").lower(),
     {"tr": "Sucuri WAF kullanılıyor.", "en": "Sucuri WAF in use."}),
    ("Imperva / Incapsula", lambda b: "x-iinfo" in b or "incap_ses" in b.get("set-cookie", "").lower(),
     {"tr": "Imperva (Incapsula) WAF kullanılıyor.", "en": "Imperva (Incapsula) WAF in use."}),
    ("ModSecurity", lambda b: "mod_security" in b.get("server", "").lower()
     or "modsecurity" in b.get("server", "").lower(),
     {"tr": "ModSecurity kuralları açık. Kuralları güncel tut.",
      "en": "ModSecurity rules active. Keep rules updated."}),
    ("F5 BIG-IP", lambda b: "bigipserver" in b.get("set-cookie", "").lower(),
     {"tr": "F5 BIG-IP yük dengeleyici.", "en": "F5 BIG-IP load balancer."}),
    ("Fastly", lambda b: "fastly" in b.get("via", "").lower(),
     {"tr": "Fastly CDN kullanılıyor.", "en": "Fastly CDN in use."}),
]


def waf_tespit(basliklar):
    bulunan = []
    for ad, kosul, not_ in WAF_IMZALARI:
        try:
            if kosul(basliklar):
                bulunan.append((ad, not_["tr"], not_["en"]))
        except Exception:
            pass
    return bulunan


def arsiv_gecmisi(host):
    """Wayback Machine (CDX) üzerinden sitenin arşiv geçmişi. None = servise ulaşılamadı."""
    url = ("https://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(host)
           + "/*&output=json&fl=timestamp,statuscode&collapse=timestamp:4&filter=statuscode:200&limit=5000")
    istek = urllib.request.Request(url, headers={"User-Agent": "NetScout/1.0"})
    try:
        with urllib.request.urlopen(istek, timeout=25) as c:
            veri = json.loads(c.read().decode("utf-8", errors="replace"))
    except Exception:
        return None
    satirlar = [r for r in veri[1:] if r and len(r[0]) >= 8] if veri else []
    if not satirlar:
        return {"var": False}
    yillar = sorted({int(r[0][:4]) for r in satirlar})
    dagilim = {}
    for r in satirlar:
        yil = int(r[0][:4])
        dagilim[yil] = dagilim.get(yil, 0) + 1
    bosluklar = [b - a for a, b in zip(yillar, yillar[1:]) if b - a > 1]
    ilk, son = satirlar[0][0], satirlar[-1][0]
    return {"var": True, "ilk": f"{ilk[:4]}-{ilk[4:6]}-{ilk[6:8]}",
            "son": f"{son[:4]}-{son[4:6]}-{son[6:8]}", "yillar": yillar,
            "bosluk_yil": len(bosluklar), "kayit": len(satirlar), "dagilim": dagilim}


def olay_aramasi(host):
    """Halka açık haber/rapor eşleşmelerini arar. Olayın gerçekten yaşandığını doğrulamaz."""
    import html as _htmllib
    sorgu = f'"{host}" hacked OR breach OR defacement OR "data leak" OR DDoS'
    istek = urllib.request.Request("https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(sorgu),
                                   headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) NetScout/1.0"})
    try:
        with urllib.request.urlopen(istek, timeout=12) as c:
            sayfa = c.read(400000).decode("utf-8", errors="replace")
    except Exception:
        return None
    sonuc = []
    for link, baslik_html in re.findall(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', sayfa, re.S):
        if "uddg=" in link:
            link = urllib.parse.unquote(link.split("uddg=", 1)[1].split("&", 1)[0])
        metin = _htmllib.unescape(re.sub(r"<[^>]+>", " ", baslik_html)).strip()
        if metin and link:
            sonuc.append({"baslik": metin, "link": link})
        if len(sonuc) >= 8:
            break
    return sonuc


def site_gezi(url, max_sayfa=40, timeout=6):
    """Aynı alan adı içinde en fazla max_sayfa sayfa gezer. [(adres, html), ...] döndürür."""
    p = urllib.parse.urlsplit(url)
    kok = p.netloc
    sira = [url]
    gorulen = {url}
    sayfalar = []
    while sira and len(sayfalar) < max_sayfa:
        adres = sira.pop(0)
        h = _sayfa_getir(adres, timeout)
        if not h:
            continue
        sayfalar.append((adres, h))
        for href in re.findall(r'href="([^"#]+)"', h)[:300]:
            tam = urllib.parse.urljoin(adres, href)
            tp = urllib.parse.urlsplit(tam)
            if tp.netloc != kok or tp.scheme not in ("http", "https"):
                continue
            if re.search(r"\.(png|jpe?g|gif|svg|webp|css|js|pdf|zip|ico|woff2?|xml)$", tp.path, re.I):
                continue
            norm = urllib.parse.urlunsplit((tp.scheme, tp.netloc, tp.path or "/", "", ""))
            if norm not in gorulen:
                gorulen.add(norm)
                sira.append(norm)
    return sayfalar


TEKNOLOJI_IMZALARI = [
    ("WordPress", r"wp-content|wp-includes"), ("Joomla", r"/media/jui/|Joomla!"),
    ("Drupal", r"Drupal\.settings|/sites/default/files"), ("Bitrix", r"/bitrix/"),
    ("Shopify", r"cdn\.shopify\.com"), ("Wix", r"static\.wixstatic\.com"),
    ("React", r"react-dom|data-reactroot"), ("Next.js", r"/_next/static"),
    ("Vue.js", r"vue(\.min)?\.js"), ("Angular", r"ng-version|angular(\.min)?\.js"),
    ("Google Analytics", r"googletagmanager\.com|google-analytics\.com"),
    ("Yandex Metrica", r"mc\.yandex\.ru"), ("Facebook Pixel", r"connect\.facebook\.net"),
]


def teknoloji_tespit(html):
    bulunan = [ad for ad, desen in TEKNOLOJI_IMZALARI if re.search(desen, html, re.I)]
    gen = re.search(r'<meta[^>]+name="generator"[^>]+content="([^"]+)"', html, re.I)
    if gen:
        bulunan.append("generator: " + gen.group(1)[:60])
    return bulunan


def sertifika_gecmisi(host):
    """Sertifika Şeffaflığı kayıtları (crt.sh). Sitenin ne zaman sertifika aldığını ve alt alanlarını gösterir."""
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + host) + "&output=json"
    istek = urllib.request.Request(url, headers={"User-Agent": "NetScout/1.0"})
    try:
        with urllib.request.urlopen(istek, timeout=25) as c:
            veri = json.loads(c.read().decode("utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(veri, list) or not veri:
        return {"var": False}
    tarihler = [k.get("not_before", "")[:10] for k in veri if k.get("not_before")]
    isimler = set()
    for k in veri:
        for n in (k.get("name_value") or "").split("\n"):
            n = n.strip().lower()
            if n and "*" not in n:
                isimler.add(n)
    return {"var": True, "ilk": min(tarihler) if tarihler else "?",
            "son": max(tarihler) if tarihler else "?", "adet": len(veri),
            "altalanlar": sorted(isimler)[:60]}


def arsiv_donem_ozeti(host, en_fazla=12):
    """Arşivdeki eski sayfaların başlık ve açıklamalarından sitenin geçmişteki konusunu çıkarır."""
    import html as _htmllib
    from concurrent.futures import ThreadPoolExecutor
    url = ("https://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(host)
           + "/*&output=json&fl=timestamp,original&collapse=timestamp:4&filter=statuscode:200"
           + "&filter=mimetype:text/html&limit=5000")
    istek = urllib.request.Request(url, headers={"User-Agent": "NetScout/1.0"})
    try:
        with urllib.request.urlopen(istek, timeout=25) as c:
            veri = json.loads(c.read().decode("utf-8", errors="replace"))
    except Exception:
        return None
    satirlar = [r for r in veri[1:] if r and len(r) >= 2] if veri else []
    if not satirlar:
        return []
    if len(satirlar) > en_fazla:
        adim = len(satirlar) / en_fazla
        satirlar = [satirlar[int(i * adim)] for i in range(en_fazla)]

    def getir(satir):
        ts, orijinal = satir[0], satir[1]
        h = _sayfa_getir(f"https://web.archive.org/web/{ts}id_/{orijinal}", timeout=15)
        if not h:
            return None
        t = re.search(r"<title[^>]*>(.*?)</title>", h, re.I | re.S)
        d = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]*)"', h, re.I)
        baslik_metni = _htmllib.unescape(re.sub(r"\s+", " ", t.group(1))).strip()[:120] if t else ""
        aciklama = _htmllib.unescape(d.group(1)).strip()[:200] if d else ""
        return {"yil": ts[:4], "baslik": baslik_metni, "aciklama": aciklama}

    with ThreadPoolExecutor(max_workers=6) as ex:
        sonuc = list(ex.map(getir, satirlar))
    return [s for s in sonuc if s and (s["baslik"] or s["aciklama"])]


def arsiv_gecmis_detay(host, ornek=60):
    """Arşivden aylık örnekler alır: başlık/site adı/açıklama zaman çizelgesi ve isim değişikliği."""
    import html as _htmllib
    from concurrent.futures import ThreadPoolExecutor
    url = ("https://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(host)
           + "/*&output=json&fl=timestamp,original&collapse=timestamp:6&filter=statuscode:200"
           + "&filter=mimetype:text/html&limit=5000")
    istek = urllib.request.Request(url, headers={"User-Agent": "NetScout/1.0"})
    try:
        with urllib.request.urlopen(istek, timeout=30) as c:
            veri = json.loads(c.read().decode("utf-8", errors="replace"))
    except Exception:
        return None
    satirlar = [r for r in veri[1:] if r and len(r) >= 2] if veri else []
    if not satirlar:
        return []
    if len(satirlar) > ornek:
        adim = len(satirlar) / ornek
        satirlar = [satirlar[int(i * adim)] for i in range(ornek)]

    def getir(satir):
        ts, orijinal = satir[0], satir[1]
        h = _sayfa_getir(f"https://web.archive.org/web/{ts}id_/{orijinal}", timeout=15)
        if not h:
            return None
        t = re.search(r"<title[^>]*>(.*?)</title>", h, re.I | re.S)
        d = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]*)"', h, re.I)
        og = re.search(r'<meta[^>]+property="og:site_name"[^>]+content="([^"]*)"', h, re.I)
        baslik_metni = _htmllib.unescape(re.sub(r"\s+", " ", t.group(1))).strip()[:120] if t else ""
        return {"tarih": f"{ts[:4]}-{ts[4:6]}", "baslik": baslik_metni,
                "aciklama": _htmllib.unescape(d.group(1)).strip()[:200] if d else "",
                "site_adi": _htmllib.unescape(og.group(1)).strip()[:80] if og else ""}

    with ThreadPoolExecutor(max_workers=8) as ex:
        sonuc = [s for s in ex.map(getir, satirlar)
                 if s and (s["baslik"] or s["aciklama"] or s["site_adi"])]
    onceki = None
    for s in sonuc:
        norm = re.sub(r"\W+", " ", (s["site_adi"] or s["baslik"])).strip().lower()
        s["degisti"] = bool(onceki is not None and norm and norm != onceki)
        if norm:
            onceki = norm
    return sonuc


def sr_ek_bolumleri(url, host, sayfalar):
    """HEPSİ akışının sonuna eklenen geniş pasif bilgi bölümleri."""
    kok = host_kok(host)
    ana = sayfalar[0][1] if sayfalar else ""
    tum_html = "\n".join(h for _, h in sayfalar)
    adaylar = ad_adaylari(ana, kok)
    ad0 = adaylar[0] if adaylar else kok.split(".")[0]
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        f_wd = ex.submit(wd_kurum, kok, adaylar)
        f_vozet = ex.submit(vikipedi_ozet, ad0)
        f_arsiv = ex.submit(arsiv, kok)
        f_crt = ex.submit(sertifika, kok)
        f_rdap = ex.submit(rdap, kok)
        f_yanit = ex.submit(sr_yanit_al, url)
        wd_s, vozet_s = f_wd.result(), f_vozet.result()
        arsiv_s, crt_s = f_arsiv.result(), f_crt.result()
        rd_s, yanit_s = f_rdap.result(), f_yanit.result()

    sr_baslik("ÜLKE VE ŞEHİR (telefon, dil, para birimi, sayfa metni ve Wikidata; IP kullanılmaz)")
    _, tel = sr_iletisim_coz(tum_html)
    wd_kod = [k for k in (ad_den_kod(u) for u in (wd_s or {}).get("ulke", [])) if k]
    karar = ulke_karar(kok, ana, sr_metin_cikar(tum_html), "", tel, wd_kod)
    if karar:
        u = sr_ULKELER[karar["kod"]]
        print(f"  {u['tr']} (güven: {guven(karar['oran'])}, %{int(karar['oran'] * 100)})")
        if karar["sehir"]:
            print(f"  Şehir: {karar['sehir']}")
        print(f"  Yerel saat (tahmini): {sr_yerel_saat(u['tz'])} (UTC{u['tz']:+g})")
        for _k, w, neden in karar["kanit"]:
            print(f"    · {neden} (+{w:g})")
    else:
        sr_uyari("Ülke için yeterli kanıt bulunamadı.")

    sr_baslik("KURUM (Wikidata; resmi web adresi bu alan adıyla eşleşmeli)")
    if wd_s:
        print(f"  Kurum        : {wd_s['ad']} ({wd_s['qid']})")
        for etk, alan in (("Ülke (resmi)", "ulke"), ("Merkez", "merkez"), ("Üst kurum", "ust_kurum"),
                          ("Sahip", "sahip"), ("Kurucu", "kurucu")):
            if wd_s[alan]:
                print(f"  {etk:<13}: {', '.join(wd_s[alan])}")
        if wd_s["kurulus"]:
            print(f"  Kuruluş      : {wd_s['kurulus'][0]}")
        for miktar, birim in wd_s.get("gelir", []):
            print(f"  Gelir (Wikidata kaydı, yıl ve kaynak kayıtta yazmayabilir): {miktar} {birim}")
    else:
        sr_uyari("Resmi web adresi bu siteyle eşleşen bir kurum Wikidata'da bulunamadı.")

    sr_baslik("ALAN ADI KAYDI (RDAP)")
    if rd_s:
        print(f"  Alan adı      : {rd_s['alan']}")
        if rd_s.get("kayit_firmasi"):
            print(f"  Kayıt firması : {rd_s['kayit_firmasi']}")
        if rd_s.get("kayit"):
            print(f"  Kayıt tarihi  : {rd_s['kayit']}")
        if rd_s.get("bitis"):
            print(f"  Bitiş tarihi  : {rd_s['bitis']}")
        sahip = rd_s.get("sahip") or ""
        gizli = not sahip or re.search(r"redact|privacy|gizli", sahip, re.I)
        print(f"  Sahip         : {'gizli (gizlilik hizmeti açık)' if gizli else sahip}")
    else:
        sr_uyari("RDAP kaydı alınamadı.")

    sr_baslik("AÇILIŞ VE KURULUŞ HİKAYESİ")
    tarihler = []
    if wd_s and wd_s["kurulus"]:
        tarihler.append(("Wikidata kuruluş tarihi", wd_s["kurulus"][0]))
    if arsiv_s and arsiv_s.get("var"):
        tarihler.append(("ilk arşiv kaydı", arsiv_s["ilk"]))
    if crt_s and crt_s.get("var") and crt_s["ilk"] != "?":
        tarihler.append(("ilk sertifika", crt_s["ilk"]))
    if tarihler:
        neden, tarih = min(tarihler, key=lambda x: x[1])
        print(f"  En erken kanıt: {tarih} ({neden}); kesin açılış tarihi değildir.")
    if vozet_s:
        print(f"  Vikipedi ({vozet_s['baslik']}): {vozet_s['ozet'][:400]}")
    hikaye = kurulus_hikayesi(dict(sayfalar))
    for c in hikaye:
        print(f"  · {c[:300]}")
    if not hikaye:
        print("  Sitenin hakkında sayfasında kuruluş anlatımı yok. Neden açıldığı yazılı değilse araç tahmin etmez.")

    sr_baslik("KORUYUCU DUVAR (ana sayfa yanıtı, pasif)")
    sv = sr_savunma_raporu(yanit_s)
    if not sv:
        sr_uyari("Ana sayfaya ulaşılamadı.")
    else:
        print(f"  Ana sayfa yanıt kodu: {sv['durum']}")
        for ad in sv["katmanlar"]:
            print(f"  [+] {ad}")
        if sv["engel"]:
            sr_uyari("Ana sayfa bu aracı engelliyor görünüyor. Engel aşılmaz; sahipten izin istenmeli.")


def hepsi_modu():
    baslik(iki("HEPSİ — tek hedefle tam analiz", "ALL — full analysis with one target"))
    girdi = input(iki("  Web URL veya IP/hostname (örn https://example.com): ",
                      "  Web URL or IP/hostname (e.g. https://example.com): ")).strip()
    if not girdi:
        return
    url = girdi if "://" in girdi else "https://" + girdi
    host = urllib.parse.urlsplit(url).hostname
    if not host:
        uyari(iki("Geçersiz hedef.", "Invalid target."))
        return
    pcap = input(iki("  Paket dosyası (.pcap) yolu, boş bırakırsan atlanır: ",
                     "  Packet file (.pcap) path, leave empty to skip: ")).strip()

    rapor = {"hedef": girdi, "url": url, "host": host}
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        uyari(iki("Hedef çözülemedi.", "Could not resolve the target."))
        return
    rapor["ip"] = ip
    print(renk(f"\n  {iki('Hedef', 'Target')}: {host}  ->  {ip}", "1;32"))

    # 0) Ülke, şehir, iletişim (önce bu)
    ulke_analizi_v2(url, host, ip, rapor)

    # 1) DNS
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        bilgi(iki("DNS kayıtları sorgulanıyor...", "Querying DNS records..."))
        dns = dns_yoxla(host)
        rapor["dns"] = dns
        yazdir_dns(dns)

    # 2) Ters IP
    bilgi(iki("Aynı IP'deki alan adları aranıyor...", "Looking up domains on the same IP..."))
    ters = ters_ip_sorgula(ip)
    rapor["ters_ip"] = ters
    yazdir_ters_ip(ip, ters)

    # 3) Web
    bilgi(iki("Web kontrolü yapılıyor...", "Checking the web..."))
    web = web_tam(url)
    rapor["web"] = web
    yazdir_web(web)

    # Savunma katmanları
    waf = waf_tespit(web.get("basliklar", {}))
    rapor["savunma"] = [w[0] for w in waf]
    baslik(iki("SAVUNMA KATMANLARI (WAF / CDN)", "DEFENSE LAYERS (WAF / CDN)"))
    if waf:
        for ad, tr_m, en_m in waf:
            print(renk(f"  [+] {ad}: {iki(tr_m, en_m)}", "1;32"))
    else:
        print("  " + iki("Bilinen bir savunma katmanı görünmedi (yanıt başlıklarına bakıldı).",
                         "No known defense layer visible (response headers checked)."))

    # Site geçmişi (arşiv)
    bilgi(iki("Arşiv geçmişi sorgulanıyor (Wayback Machine)...", "Querying archive history (Wayback Machine)..."))
    gecmis = arsiv_gecmisi(host)
    rapor["arsiv"] = gecmis
    baslik(iki("SİTENİN GEÇMİŞİ", "SITE HISTORY"))
    if gecmis is None:
        uyari(iki("Arşiv servisine ulaşılamadı.", "Could not reach the archive service."))
    elif not gecmis["var"]:
        print("  " + iki("Arşivde kayıt yok (yeni site ya da hiç arşivlenmemiş).",
                         "No archive records (new site or never archived)."))
    else:
        print("  " + iki(f"İlk arşiv kaydı : {gecmis['ilk']}", f"First archive record : {gecmis['ilk']}"))
        print("  " + iki(f"Son arşiv kaydı : {gecmis['son']}", f"Last archive record  : {gecmis['son']}"))
        print("  " + iki(f"Aktif yıllar     : {gecmis['yillar'][0]}-{gecmis['yillar'][-1]} "
                         f"({len(gecmis['yillar'])} yıl)",
                         f"Active years      : {gecmis['yillar'][0]}-{gecmis['yillar'][-1]} "
                         f"({len(gecmis['yillar'])} years)"))
        print("  " + iki(f"Arşivde boşluklu yıl: {gecmis['bosluk_yil']}",
                         f"Years with gaps     : {gecmis['bosluk_yil']}"))
        yillik = gecmis.get("dagilim", {})
        print("  " + iki("Yıllık arşiv kayıt sayısı:", "Archive records per year:"))
        for yil in sorted(yillik):
            print(f"    {yil}: {'█' * min(yillik[yil], 40)} ({yillik[yil]})")

    # Halka açık olay araması
    bilgi(iki("Halka açık olay kayıtları aranıyor...", "Searching public incident records..."))
    olaylar = olay_aramasi(host)
    rapor["olaylar"] = olaylar
    baslik(iki("HALKA AÇIK OLAY ARAMASI (doğrulanmamış)", "PUBLIC INCIDENT SEARCH (unverified)"))
    if olaylar is None:
        uyari(iki("Arama servisine ulaşılamadı.", "Could not reach the search service."))
    elif not olaylar:
        print("  " + iki("Olay eşleşmesi bulunamadı.", "No incident matches found."))
    else:
        for o in olaylar:
            print(f"  - {o['baslik'][:90]}")
            print(renk(f"    {o['link']}", "0;37"))
        print(renk("  " + iki("Not: Bunlar sadece arama eşleşmeleridir. Olayın gerçekten yaşandığını doğrulamaz.",
                             "Note: These are only search matches. They do not prove an incident happened."),
                   "0;37"))

    # Site taraması (en fazla 40 sayfa, sadece sitenin kendi sayfaları)
    bilgi(iki("Sitenin kendi sayfaları taranıyor (en fazla 40)...",
              "Crawling the site's own pages (max 40)..."))
    sayfalar = site_gezi(url, 40)
    tum_html = "\n".join(h for _, h in sayfalar)
    tum_ilet = iletisim_coz(tum_html)
    tum_adres = adres_bul(metin_cikar(tum_html))
    rapor["site_taramasi"] = {"sayfa": len(sayfalar), "telefonlar": tum_ilet["telefonlar"],
                              "emailler": tum_ilet["emailler"], "adresler": tum_adres}
    baslik(iki(f"SİTE TARAMASI: {len(sayfalar)} sayfa", f"SITE SCAN: {len(sayfalar)} pages"))
    if tum_ilet["telefonlar"] or tum_ilet["emailler"] or tum_adres:
        for t in tum_ilet["telefonlar"]:
            print(f"  Tel     : {t}")
        for e in tum_ilet["emailler"]:
            print(f"  E-posta : {e}")
        for a in tum_adres:
            print(f"  Adres   : {a}")
    else:
        print("  " + iki("Sitede yayımlanmış iletişim bilgisi bulunmadı.",
                         "No published contact details found on the site."))

    # 4) Portlar, servis sürümleri
    bilgi(iki("Portlar ve servis sürümleri taranıyor...", "Scanning ports and service versions..."))
    satirlar = asyncio.run(port_tara(ip, sorted(set(ORNEK_PORTLAR) | set(RISKLI_PORTLAR)),
                                     1.0, 300, True))
    rapor["portlar"] = satirlar
    baslik(iki(f"AÇIK PORTLAR: {host}", f"OPEN PORTS: {host}"))
    yazdir_port(satirlar)

    # 5) Kritik portlar: tablo + derin kontrol
    kritik_tablo(satirlar, ip)
    rapor["kritik_derin"] = kritik_derin_kontrol(ip, satirlar)

    # 6) CVE
    if satirlar:
        bilgi(iki("Servisler için olası CVE'ler aranıyor (birkaç saniye sürebilir)...",
                  "Looking up possible CVEs for the services (may take a few seconds)..."))
        rapor["cve"] = cve_kontrol(satirlar, host)

    # 7) Paket analizi ve Zeek logları (isteğe bağlı)
    if pcap:
        if os.path.isfile(pcap):
            try:
                n = pcap_tara(pcap)
                pcap_goster(n)
                klasor = os.path.abspath(ZEEK_KLASORU)
                zeek_yaz(n, klasor)
                zeek_ozeti_goster(n, klasor)
                rapor["pcap"] = {"paket": n["paket"], "protokol": n["protokol"]}
            except RuntimeError as e:
                uyari(str(e))
        else:
            uyari(iki("Paket dosyası bulunamadı, atlandı.", "Packet file not found, skipped."))
    else:
        bilgi(iki("Paket analizi atlandı (isteğe bağlı .pcap yolu verilmedi).",
                  "Packet analysis skipped (no .pcap path given)."))

    # Site profili (pasif araştırma, en sonda)
    baslik(iki("SİTE PROFİLİ (pasif araştırma)", "SITE PROFILE (passive research)"))
    teknolojiler = teknoloji_tespit(tum_html)
    rapor["teknolojiler"] = teknolojiler
    print("  " + iki("Kullanılan teknolojiler: ", "Technologies used: ")
          + (", ".join(teknolojiler) if teknolojiler else iki("belirlenemedi", "not determined")))
    sert = sertifika_gecmisi(host)
    rapor["sertifika_gecmisi"] = sert
    if sert is None:
        uyari(iki("Sertifika kayıtlarına (crt.sh) ulaşılamadı.", "Could not reach certificate records (crt.sh)."))
    elif not sert["var"]:
        print("  " + iki("Sertifika kaydı bulunamadı.", "No certificate records found."))
    else:
        print("  " + iki(f"İlk sertifika tarihi: {sert['ilk']} (sitenin en az bu tarihten beri var olduğuna dair ipucu)",
                         f"First certificate date: {sert['ilk']} (hint that the site exists since at least then)"))
        print("  " + iki(f"Son sertifika tarihi : {sert['son']}", f"Last certificate date  : {sert['son']}"))
        print("  " + iki(f"Toplam sertifika    : {sert['adet']}", f"Total certificates    : {sert['adet']}"))
        if sert["altalanlar"]:
            print("  " + iki("Bulunan alt alan adları (ilk 15):", "Subdomains found (first 15):"))
            for s in sert["altalanlar"][:15]:
                print(f"    - {s}")

    # Site geçmişi özeti (arşiv sayfalarının başlık ve açıklamaları)
    baslik(iki("SİTE GEÇMİŞİ ÖZETİ (arşiv sayfalarından)", "SITE HISTORY SUMMARY (from archived pages)"))
    bilgi(iki("Eski sayfalar okunuyor (en fazla 12 dönem)...", "Reading old pages (max 12 periods)..."))
    donem = arsiv_gecmis_detay(host)
    rapor["gecmis_ozet"] = donem
    if donem is None:
        uyari(iki("Arşiv sayfalarına ulaşılamadı.", "Could not reach archived pages."))
    elif not donem:
        print("  " + iki("Arşivde okunabilir sayfa bulunamadı.", "No readable archived pages found."))
    else:
        for d in donem:
            isaret = renk("  ⚠ isim/konu değişti", SARI) if d.get("degisti") else ""
            print(f"  {d['tarih']}: {d['baslik']}{isaret}")
            if d.get("site_adi"):
                print(renk(f"        site adı: {d['site_adi']}", "0;37"))
            if d["aciklama"]:
                print(renk(f"        {d['aciklama']}", "0;37"))

    # Özet

    acik_sayi = len(satirlar)
    kritik_sayi = len([s for s in satirlar if s["port"] in RISKLI_PORTLAR])
    baslik(iki("ÖZET", "SUMMARY"))
    kutu([
        iki(f"Hedef        : {host} ({ip})", f"Target       : {host} ({ip})"),
        iki(f"Açık port    : {acik_sayi}", f"Open ports   : {acik_sayi}"),
        iki(f"Kritik port  : {kritik_sayi}", f"Critical     : {kritik_sayi}"),
        iki(f"Web TLS      : {'var' if web.get('sertifika') else 'yok'}",
            f"Web TLS      : {'yes' if web.get('sertifika') else 'no'}"),
    ], "1;32")
    sr_ek_bolumleri(url, host, sayfalar)
    json_kaydet(f"netscout_rapor_{host.replace(':', '_')}.json", rapor)


# ============================================================ menü
MENU = [
    ("1", iki("nmap — port ve servis taraması", "nmap — port and service scan")),
    ("2", iki("masscan — hızlı port taraması", "masscan — fast port scan")),
    ("3", iki("wireshark — pcap analizi", "wireshark — pcap analysis")),
    ("4", iki("zeek — bağlantı ve DNS logları", "zeek — connection and DNS logs")),
    ("5", iki("openvas — olası CVE'ler", "openvas — possible CVEs")),
    ("6", iki("HEPSİ — tek URL ile her şey", "ALL — everything with one URL")),
]


def menu_goster():
    temizle()
    logo_yazdir()
    satirlar = [f"{numara}) {metin}" for numara, metin in MENU]
    satirlar.append("0) " + iki("Çıkış", "Exit"))
    kutu(satirlar)


def dil_sec():
    global DIL, DIL_SECILDI
    print()
    kutu(["1) Türkçe", "2) English"])
    cevap = input("  Dil / Language: ").strip()
    DIL = "en" if cevap == "2" else "tr"
    DIL_SECILDI = True


def calistir_secim(secim):
    islemler = {"1": nmap_modu, "2": masscan_modu, "3": wireshark_modu,
                "4": zeek_modu, "5": openvas_modu, "6": hepsi_modu}
    if secim in islemler:
        islemler[secim]()
    else:
        uyari(iki("Geçersiz seçim.", "Invalid choice."))


def menu():
    while True:
        menu_goster()
        try:
            secim = input(iki("\n  Seçim: ", "\n  Choice: ")).strip()
            if secim == "0":
                print(iki("  Görüşmek üzere.", "  Goodbye."))
                return
            try:
                calistir_secim(secim)
            except SystemExit as e:
                if isinstance(e.code, str):
                    uyari(e.code)
            input(iki("\n  Menüye dönmek için Enter'a bas...",
                      "\n  Press Enter to return to the menu..."))
        except (EOFError, KeyboardInterrupt):
            print()
            return


def giris_animasyonu_v2():
    import random
    temizle()
    karakterler = "01▓▒░#%&*+=<>"
    for _ in range(14):
        satir = "".join(random.choice(karakterler) for _ in range(56))
        print(renk(satir, "0;32"))
        time.sleep(0.04)
    temizle()
    dalga = ["1;32", "1;92", "1;36", "1;96", "1;36", "1;92"]
    for i, satir in enumerate(BANNER.strip("\n").splitlines()):
        print(renk(satir, dalga[i % len(dalga)]))
        time.sleep(0.08)
    print(renk(iki("   root gerektirmeyen ağ analiz aracı", "   rootless network analysis tool")
               + f"   v{SURUM}", "1;36"))
    print()
    adimlar = [iki("Modüller yükleniyor", "Loading modules"),
               iki("Ağ arayüzü algılanıyor", "Detecting network interface"),
               iki("Güvenlik kuralları hazırlanıyor", "Preparing security rules"),
               iki("Araçlar ısıtılıyor", "Warming up tools")]
    cerceve = "⣾⣽⣻⢿⡿⣟⣯⣷"
    for a in adimlar:
        for k in range(12):
            sys.stdout.write(f"\r  {renk(cerceve[k % len(cerceve)], '1;36')} {a}...")
            sys.stdout.flush()
            time.sleep(0.06)
        sys.stdout.write(f"\r  {renk('✔', '1;32')} {a}          \n")
        sys.stdout.flush()
    toplam = 40
    gradyan = ["1;32", "1;92", "1;93", "1;96", "1;36"]
    for adim in range(toplam + 1):
        dolu = "".join(renk("█", gradyan[(i * len(gradyan)) // toplam]) for i in range(adim))
        bos = "░" * (toplam - adim)
        sys.stdout.write(f"\r  [{dolu}{bos}] {int(adim * 100 / toplam):>3}%")
        sys.stdout.flush()
        time.sleep(0.03)
    print("\n\n  " + renk(iki("✔ Hazır! NetScout çalışmaya hazır.", "✔ Ready! NetScout is ready."), "1;32"))
    time.sleep(0.6)


def giris_animasyonu_v3():
    import math
    temizle()
    genislik, yukseklik = 31, 13
    cx, cy = 15, 6
    for kare in range(30):
        aci = kare * (2 * math.pi / 15)
        satirlar = []
        for y in range(yukseklik):
            satir = []
            for x in range(genislik):
                dx = (x - cx) / 2.0
                dy = float(y - cy)
                r = math.hypot(dx, dy)
                karakter = " "
                if 5.8 <= r <= 6.2 or 2.9 <= r <= 3.1:
                    karakter = "·"
                ang = math.atan2(-dy, dx) % (2 * math.pi)
                fark = (aci - ang) % (2 * math.pi)
                if r <= 6.0 and fark < 0.5:
                    karakter = "█" if fark < 0.15 else "▒"
                if r < 0.6:
                    karakter = "+"
                satir.append(karakter)
            satirlar.append(renk("".join(satir), "1;32"))
        sys.stdout.write("\033[H" + "\n".join(satirlar) + "\n")
        sys.stdout.flush()
        time.sleep(0.07)
    temizle()
    for satir in BANNER.strip("\n").splitlines():
        for ch in satir:
            sys.stdout.write(renk(ch, "1;32") if ch != " " else " ")
            sys.stdout.flush()
            time.sleep(0.003)
        print()
    tagline = iki("   root gerektirmeyen ağ analiz aracı", "   rootless network analysis tool") + f"   v{SURUM}"
    for ch in tagline:
        sys.stdout.write(renk(ch, "1;36"))
        sys.stdout.flush()
        time.sleep(0.012)
    print("\n")
    adimlar = [iki("Modüller yükleniyor", "Loading modules"),
               iki("Ağ arayüzü algılanıyor", "Detecting network interface"),
               iki("Güvenlik kuralları hazırlanıyor", "Preparing security rules"),
               iki("Araçlar ısıtılıyor", "Warming up tools")]
    cerceve = "⣾⣽⣻⢿⡿⣟⣯⣷"
    for a in adimlar:
        for k in range(10):
            sys.stdout.write(f"\r  {renk(cerceve[k % len(cerceve)], '1;36')} {a}...")
            sys.stdout.flush()
            time.sleep(0.05)
        sys.stdout.write(f"\r  {renk('✔', '1;32')} {a}          \n")
        sys.stdout.flush()
    toplam = 40
    gradyan = ["1;32", "1;92", "1;93", "1;96", "1;36"]
    for adim in range(toplam + 1):
        dolu = "".join(renk("█", gradyan[(i * len(gradyan)) // toplam]) for i in range(adim))
        bos = "░" * (toplam - adim)
        sys.stdout.write(f"\r  [{dolu}{bos}] {int(adim * 100 / toplam):>3}%")
        sys.stdout.flush()
        time.sleep(0.025)
    print("\n\n  " + renk(iki("✔ Hazır! NetScout çalışmaya hazır.", "✔ Ready! NetScout is ready."), "1;32"))
    time.sleep(0.6)


def main():
    global DIL, DIL_SECILDI
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a == "--dil" and i + 1 < len(argv) and argv[i + 1] in ("tr", "en"):
            DIL, DIL_SECILDI = argv[i + 1], True
        elif a.startswith("--dil=") and a.split("=", 1)[1] in ("tr", "en"):
            DIL, DIL_SECILDI = a.split("=", 1)[1], True
    if any(a in ("-h", "--help") for a in argv):
        print(f"NetScout v{SURUM} - python NetScout.py [--dil tr|en]")
        return
    temizle()
    if not DIL_SECILDI:
        logo_yazdir()
        dil_sec()
    giris_animasyonu_v3()
    menu()


if __name__ == "__main__":
    main()
