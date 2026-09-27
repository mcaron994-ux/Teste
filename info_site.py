#!/usr/bin/env python3
"""
info_site.py — Outil pour récupérer des informations sur un site web.

Usage :
    python info_site.py https://fridaydev.fr/
    python info_site.py https://fridaydev.fr/
    python info_site.py https://fridaydev.fr/ --port 443

Informations récupérées :
  - Adresse IP + hébergeur
  - Statut HTTP, serveur, redirections
  - En-têtes (headers) de sécurité
  - Certificat SSL (émetteur, expiration)
  - Titre, description, métadonnées de la page
  - Technologies détectées (CMS, framework...)
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("❌ Le module 'requests' est requis : pip install requests")
    sys.exit(1)


COLORS = {
    "green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
    "cyan": "\033[96m", "bold": "\033[1m", "end": "\033[0m",
}


def c(color, text):
    use = not sys.stdout.isatty()
    if use:
        return text
    return f"{COLORS[color]}{text}{COLORS['end']}"


# ---------------------------------------------------------------- sockets

def get_ip_and_host(hostname):
    """Résous le domaine en adresse IP."""
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None


def get_ssl_info(hostname, port=443):
    """Récupère les infos du certificat SSL."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        return {
            "emetteur": dict(x[0] for x in cert.get("issuer", {})).get("organizationName"),
            "valide_de": cert.get("notBefore"),
            "expire_le": cert.get("notAfter"),
            "sujet": dict(x[0] for x in cert.get("subject", {})).get("commonName"),
        }
    except Exception as e:
        return {"erreur": str(e)}


def reverse_dns(ip):
    """Reverse DNS (nom d'hôte de l'hébergeur)."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


# ---------------------------------------------------------------- http

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def fetch(url):
    try:
        r = requests.get(
            url, timeout=10, verify=False, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; InfoSite/1.0)"},
        )
        return r
    except requests.exceptions.RequestException as e:
        return None


def extract_page_info(html):
    """Extrait titre, description, etc. du HTML."""
    import re
    info = {}
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        info["titre"] = m.group(1).strip()[:120]
    m = re.search(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', html, re.I)
    if m:
        info["description"] = m.group(1)[:200]
    m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\'](.*?)["\']', html, re.I)
    if m:
        info["generator"] = m.group(1)
    m = re.search(r'<html[^>]*lang=["\']([a-z-]+)["\']', html, re.I)
    if m:
        info["langue"] = m.group(1)
    info["nb_liens"] = len(re.findall(r"<a\s", html, re.I))
    info["nb_images"] = len(re.findall(r"<img\s", html, re.I))
    info["nb_scripts"] = len(re.findall(r"<script\s", html, re.I))
    emails = set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", html))
    if emails:
        info["emails"] = sorted(e for e in emails if not e.endswith(".png") and not e.endswith(".jpg"))[:10]
    return info


def detect_tech(headers, html):
    """Détecte grossièrement les technologies utilisées."""
    tech = []
    server = headers.get("Server", "")
    xpow = headers.get("X-Powered-By", "")
    if server:
        tech.append(f"Serveur: {server}")
    if xpow:
        tech.append(f"Powered-By: {xpow}")
    html_l = html.lower()
    checks = {
        "WordPress": ["wp-content", "wp-includes"],
        "Drupal": ["drupal"],
        "Joomla": ["joomla"],
        "Shopify": ["shopify", "cdn.shopify.com"],
        "React": ["__next", "react-dom", "_reactroot"],
        "Next.js": ["__next", "/_next/"],
        "Vue.js": ["vue.js", "data-v-"],
        "Angular": ["ng-app", "ngversion"],
        "Bootstrap": ["bootstrap.min.css"],
        "jQuery": ["jquery"],
        "Cloudflare": ["cloudflare"],
    }
    for name, keys in checks.items():
        if any(k in html_l for k in keys):
            tech.append(name)
    return tech


# ---------------------------------------------------------------- affichage

def banner():
    print(c("cyan", r"""
╔══════════════════════════════════════╗
║        🔍  INFO SITE  v1.0           ║
╚══════════════════════════════════════╝"""))


def print_section(title):
    print(f"\n{c('bold', '═' * 50)}")
    print(c("cyan", f"  {title}"))
    print(c("bold", "═" * 50))


def main():
    parser = argparse.ArgumentParser(description="Récupère des infos sur un site web")
    parser.add_argument("site", help="Domaine ou URL (ex: example.com ou https://example.com)")
    parser.add_argument("--json", action="store_true", help="Sortie en JSON")
    parser.add_argument("--port", type=int, default=443, help="Port SSL (défaut: 443)")
    args = parser.parse_args()

    # Normalise l'URL
    site = args.site.strip()
    if not site.startswith(("http://", "https://")):
        site /= "https://" + site
    parsed = urlparse(site)
    hostname = parsed.hostname
    if not hostname:
        print("❌ URL invalide")
        sys.exit(1)

    banner()
    print(f"  Cible : {site}")

    result = {"cible": site}

    # --- IP / DNS
    print_section("🌐 Réseau / DNS")
    ip = get_ip_and_host(hostname)
    print(f"  Adresse IP : {ip or 'introuvable'}")
    result["ip"] = ip
    if ip:
        rev = reverse_dns(ip)
        print(f"  Reverse DNS : {rev or 'n/a'}")
        result["reverse_dns"] = rev

    # --- HTTP
    print_section("📡 Réponse HTTP")
    resp = fetch(site)
    if resp is None:
        print("  ⚠️ Impossible de joindre le site en HTTPS, essai HTTP...")
        site_http = site.replace("https://", "http://", 1)
        resp = fetch(site_http)
    if resp is None:
        print(c("red", "  ❌ Site injoignable."))
        result["http"] = None
    else:
        final = resp.url
        result["http"] = {
            "statut": resp.status_code,
            "url_finale": final,
            "redirige": bool(resp.history),
            "temps_reponse_ms": int(resp.elapsed.total_seconds() * 1000),
        }
        status_color = "green" if resp.status_code == 200 else "yellow"
        print(f"  Statut : {c(status_color, str(resp.status_code))}")
        print(f"  URL finale : {final}")
        if resp.history:
            chain = " → ".join(r.url for r in resp.history) + f" → {final}"
            print(f"  🔄 Redirections : {chain}")
        print(f"  Temps de réponse : {result['http']['temps_reponse_ms']} ms")

        # Headers
        print_section("🗂️  Headers importants")
        result["headers"] = dict(resp.headers)
        for h in ["Server", "X-Powered-By", "Content-Type", "Content-Length",
                  "Via", "CF-Ray", "X-Cache"]:
            if h in resp.headers:
                print(f"  {h}: {resp.headers[h]}")

        print_section("🛡️  Headers de sécurité")
        for h in SECURITY_HEADERS:
            present = h in resp.headers
            mark = "✅" if present else "❌"
            value = resp.headers.get(h, "")
            line = f"  {mark} {h}"
            if present and len(value) < 70:
                line += f" : {value}"
            print(line)

        # Page
        if resp.text:
            print_section("📄 Contenu de la page")
            page = extract_page_info(resp.text)
            result["page"] = page
            for k, v in page.items():
                if isinstance(v, list):
                    print(f"  {k} : {', '.join(v)}")
                else:
                    print(f"  {k} : {v}")

            print_section("⚙️  Technologies détectées")
            techs = detect_tech(resp.headers, resp.text)
            result["technologies"] = techs
            if techs:
                for t in techs:
                    print(f"  • {t}")
            else:
                print("  Aucune technologie connue détectée")

    # --- SSL (seulement si HTTPS)
    if parsed.scheme == "https":
        print_section("🔒 Certificat SSL")
        ssl_info = get_ssl_info(hostname, args.port)
        result["ssl"] = ssl_info
        if "erreur" in ssl_info:
            print(f"  ⚠️ SSL : {ssl_info['erreur']}")
        else:
            for k, v in ssl_info.items():
                print(f"  {k.replace('_', ' ').capitalize()} : {v}")
            try:
                exp = datetime.strptime(ssl_info["expire_le"], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                color = "green" if days > 30 else "yellow" if days > 0 else "red"
                print(c(color, f"  Expire dans {days} jours"))
            except Exception:
                pass

    if args.json:
        print("\n" + json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"\n{c('green', '✔ Terminé.')}\n")


if __name__ == "__main__":
    main()
