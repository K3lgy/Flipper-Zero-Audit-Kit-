"""
wifi_parser.py — Parseur de logs WiFi Flipper Zero (module ESP32 dev board)
Formats supportés :
  - Logs texte brut du module WiFi Marauder
  - Exports CSV des scans AP
  - Fichiers JSON de résultats de scan
"""

import os
import re
import csv
import json
from datetime import datetime
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_MATRIX_PATH = Path(__file__).parent.parent / "findings" / "severity_matrix.json"

# Seuils de signal
SIGNAL_THRESHOLDS = {
    "excellent": -50,   # dBm > -50 : excellent
    "good":      -65,   # dBm > -65 : bon
    "fair":      -75,   # dBm > -75 : moyen
    "poor":      -85,   # dBm > -85 : faible
    # En dessous : très faible
}

# Vendors OUI connus (3 premiers octets MAC)
KNOWN_VENDORS = {
    "00:50:f2": "Microsoft",
    "00:1a:11": "Google",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "28:d2:44": "NETGEAR",
    "c4:04:15": "NETGEAR",
    "00:1f:33": "NETGEAR",
    "00:11:50": "Belkin",
    "94:10:3e": "Belkin",
    "00:17:df": "Alfa Network",
    "00:c0:ca": "Alfa Network",
    "f8:1a:67": "TP-Link",
    "50:c7:bf": "TP-Link",
    "ec:08:6b": "TP-Link",
    "00:19:e3": "Cisco",
    "00:1b:d5": "Cisco",
    "fc:fb:fb": "Cisco",
    "00:1e:14": "Ubiquiti",
    "04:18:d6": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    "00:1f:9f": "Aruba Networks",
    "00:24:6c": "Aruba Networks",
    "d8:c7:c8": "Aruba Networks",
    "00:23:eb": "Cisco Meraki",
    "e0:55:3d": "Cisco Meraki",
    "88:15:44": "Cisco Meraki",
    "00:50:43": "Proxim",
    "00:02:6f": "Proxim",
    "00:80:c8": "D-Link",
    "1c:bd:b9": "D-Link",
    "14:91:82": "D-Link",
    "00:0e:35": "Fortinet",
    "90:6c:ac": "Fortinet",
    "a4:4e:31": "Fortinet",
}

# SSID suspects (Evil Twin, Honeypot)
SUSPICIOUS_SSID_PATTERNS = [
    r"free.*wifi",
    r"wifi.*gratuit",
    r"guest.*free",
    r"open.*network",
    r"atm.*wifi",
    r"hotel.*free",
    r"starbucks",
    r"mcdonalds",
    r"airport.*free",
    r"linksys",
    r"netgear",
    r"default",
    r"dlink",
]


# ──────────────────────────────────────────────────────────────────────────────
# Chargement matrice
# ──────────────────────────────────────────────────────────────────────────────

def load_severity_matrix() -> dict:
    with open(SEVERITY_MATRIX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["wifi"]


# ──────────────────────────────────────────────────────────────────────────────
# Parseurs de formats
# ──────────────────────────────────────────────────────────────────────────────

def parse_wifi_log_txt(filepath: str) -> list[dict]:
    """
    Parse un log texte brut du module WiFi Marauder.
    Format typique :
      [*] BSSID: AA:BB:CC:DD:EE:FF  RSSI: -65  Ch: 6  Enc: WPA2  ESSID: MonReseau
    """
    networks = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[ERREUR] Impossible de lire {filepath} : {e}")
        return []

    for line_num, line in enumerate(lines, 1):
        line = line.strip()

        # Format Marauder scan AP
        ap_match = re.search(
            r"BSSID:\s*([0-9A-Fa-f:]{17})"
            r".*?RSSI:\s*(-?\d+)"
            r".*?Ch(?:an)?:\s*(\d+)"
            r".*?Enc(?:ryption)?:\s*(\S+)"
            r".*?ESSID:\s*(.+?)(?:\s+\[|$)",
            line, re.IGNORECASE
        )
        if ap_match:
            bssid, rssi, channel, enc, essid = ap_match.groups()
            networks.append({
                "bssid":    bssid.upper(),
                "rssi":     int(rssi),
                "channel":  int(channel),
                "security": enc.upper(),
                "ssid":     essid.strip(),
                "pmf":      _detect_pmf_in_line(line),
                "hidden":   essid.strip() == "" or essid.strip() == "<hidden>",
                "source_line": line_num,
            })
            continue

        # Format alternatif simplifié
        simple_match = re.search(
            r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
            r"[^\w]*(-?\d+)[^\w]*(\d{1,2})[^\w]*(OPEN|WEP|WPA|WPA2|WPA3|WPA2/WPA3|OPN).*?\"(.+?)\"",
            line, re.IGNORECASE
        )
        if simple_match:
            bssid, rssi, channel, enc, ssid = simple_match.groups()
            networks.append({
                "bssid":    bssid.upper(),
                "rssi":     int(rssi),
                "channel":  int(channel),
                "security": enc.upper(),
                "ssid":     ssid.strip(),
                "pmf":      None,
                "hidden":   False,
                "source_line": line_num,
            })

    return networks


def parse_wifi_csv(filepath: str) -> list[dict]:
    """
    Parse un CSV exporté par Marauder ou airodump-ng.
    Colonnes attendues : BSSID, ESSID, channel, Privacy, Power/RSSI, ...
    """
    networks = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            # Détection du délimiteur
            sample = f.read(2048)
            f.seek(0)
            delimiter = ";" if sample.count(";") > sample.count(",") else ","
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                # Normalisation des noms de colonnes (variantes airodump/Marauder)
                bssid    = (row.get("BSSID") or row.get("bssid") or "").strip()
                ssid     = (row.get("ESSID") or row.get("ssid") or row.get("SSID") or "").strip()
                channel  = (row.get("channel") or row.get("Channel") or row.get(" channel") or "0").strip()
                security = (row.get("Privacy") or row.get("security") or row.get("Encryption") or "").strip()
                rssi     = (row.get("Power") or row.get("RSSI") or row.get("rssi") or "0").strip()

                if not bssid or len(bssid) < 17:
                    continue

                try:
                    rssi_int = int(rssi)
                except ValueError:
                    rssi_int = -100

                try:
                    ch_int = int(channel)
                except ValueError:
                    ch_int = 0

                networks.append({
                    "bssid":    bssid.upper(),
                    "rssi":     rssi_int,
                    "channel":  ch_int,
                    "security": security.upper(),
                    "ssid":     ssid,
                    "pmf":      None,
                    "hidden":   ssid == "" or ssid == "<hidden>",
                    "source_line": None,
                })
    except Exception as e:
        print(f"[ERREUR] Lecture CSV {filepath} : {e}")

    return networks


def parse_wifi_json(filepath: str) -> list[dict]:
    """Parse un fichier JSON de scan (format Marauder ou custom)."""
    networks = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERREUR] Lecture JSON {filepath} : {e}")
        return []

    # Formats possibles : liste directe, ou dict avec clé "aps"/"networks"
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("aps", data.get("networks", data.get("results", [])))
    else:
        return []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        bssid    = str(entry.get("bssid", entry.get("BSSID", ""))).upper()
        ssid     = str(entry.get("ssid", entry.get("ESSID", ""))).strip()
        channel  = int(entry.get("channel", entry.get("ch", 0)))
        security = str(entry.get("security", entry.get("enc", entry.get("privacy", "")))).upper()
        rssi     = int(entry.get("rssi", entry.get("power", entry.get("signal", -100))))
        pmf      = entry.get("pmf", None)

        if len(bssid) < 17:
            continue

        networks.append({
            "bssid":   bssid,
            "rssi":    rssi,
            "channel": channel,
            "security": security,
            "ssid":    ssid,
            "pmf":     pmf,
            "hidden":  ssid == "" or ssid == "<hidden>",
            "source_line": None,
        })

    return networks


def _detect_pmf_in_line(line: str) -> bool | None:
    """Tente de détecter la présence de PMF/MFP dans une ligne de log."""
    line_lower = line.lower()
    if "pmf" in line_lower or "mfp" in line_lower or "802.11w" in line_lower:
        if "required" in line_lower or "enabled" in line_lower:
            return True
        if "disabled" in line_lower or "none" in line_lower:
            return False
    return None  # Non déterminable


# ──────────────────────────────────────────────────────────────────────────────
# Analyse
# ──────────────────────────────────────────────────────────────────────────────

def analyze_network(network: dict, severity_matrix: dict, all_ssids: list[str]) -> dict:
    """Enrichit un réseau WiFi avec l'analyse de sécurité complète."""

    security  = network.get("security", "").upper()
    ssid      = network.get("ssid", "")
    bssid     = network.get("bssid", "")
    rssi      = network.get("rssi", -100)
    pmf       = network.get("pmf")
    is_hidden = network.get("hidden", False)

    # Détermination du type de sécurité principal
    sec_type = _classify_security(security)

    severity_info = severity_matrix.get(sec_type, {
        "severity": "MOYEN", "score": 5.0,
        "description": "Sécurité non déterminée",
        "recommendation": "Analyse manuelle requise",
        "cve_ref": None, "color": "orange",
    })

    finding = {
        **network,
        "security_type":     sec_type,
        "severity":          severity_info["severity"],
        "score":             severity_info["score"],
        "vuln_description":  severity_info["description"],
        "recommendation":    severity_info["recommendation"],
        "cve_ref":           severity_info.get("cve_ref"),
        "color":             severity_info.get("color", "orange"),
        "vendor":            _lookup_vendor(bssid),
        "signal_quality":    _classify_signal(rssi),
        "attack_vectors":    [],
        "additional_risks":  [],
        "is_evil_twin":      False,
    }

    # Détection Evil Twin
    ssid_count = sum(1 for s in all_ssids if s.lower() == ssid.lower())
    if ssid_count > 1 and ssid != "" and ssid != "<hidden>":
        finding["is_evil_twin"] = True
        evil_twin_info = severity_matrix.get("evil_twin", {})
        finding["severity"]         = evil_twin_info.get("severity", "CRITIQUE")
        finding["score"]            = evil_twin_info.get("score", 10.0)
        finding["vuln_description"] = evil_twin_info.get("description", "AP doublon détecté")
        finding["recommendation"]   = evil_twin_info.get("recommendation", "Investigation urgente")
        finding["color"]            = "red"
        finding["additional_risks"].append(
            f"⚠️ EVIL TWIN : SSID '{ssid}' présent {ssid_count} fois dans le scan — AP frauduleux probable"
        )

    # Risque PMF absent
    if sec_type in ("wpa2_personal", "wpa2_enterprise") and pmf is False:
        pmf_info = severity_matrix.get("no_pmf", {})
        finding["additional_risks"].append(
            f"PMF (802.11w) non activé — vulnérable aux attaques de déauthentification "
            f"[{pmf_info.get('severity', 'MOYEN')} / {pmf_info.get('score', 5.0)}]"
        )

    # SSID masqué
    if is_hidden:
        finding["additional_risks"].append(
            "SSID masqué — sécurité par l'obscurité inefficace, détectable avec n'importe quel scanner WiFi"
        )

    # SSID suspect (honeypot/captive)
    if _is_suspicious_ssid(ssid):
        finding["additional_risks"].append(
            f"SSID '{ssid}' correspond à un pattern de réseau honeypot/captif connu — vérifier l'authenticité"
        )

    # Vecteurs d'attaque
    if sec_type == "open_network":
        finding["attack_vectors"] = [
            "Capture passive de tout le trafic (Wireshark, tcpdump)",
            "Injection de paquets sans association préalable",
            "MITM trivial — redirection DNS, injection HTTP",
            "Vol de sessions non chiffrées (cookies, formulaires)",
        ]
    elif sec_type == "wep":
        finding["attack_vectors"] = [
            "Crack de la clé WEP en <60 secondes (aircrack-ng + ~5000 IVs)",
            "Attaque chopchop pour décrypter des paquets individuels",
            "Injection de paquets ARP pour accélérer la capture d'IVs",
        ]
    elif sec_type == "wpa_tkip":
        finding["attack_vectors"] = [
            "Attaque Beck-Tews (injection TKIP partielle en ~15 min)",
            "Attaque Ohigashi-Morri (amélioration Beck-Tews)",
            "Brute-force du handshake 4-way si PSK faible",
        ]
    elif sec_type == "wpa2_personal":
        finding["attack_vectors"] = [
            "Capture du handshake 4-way + attaque dictionnaire/brute-force offline",
            "Attaque PMKID (sans handshake complet, aircrack-ng 2018+)",
            "Risque de compromission via ex-employés/contractors (PSK partagée)",
        ]

    return finding


def _classify_security(security: str) -> str:
    """Normalise la chaîne de sécurité en clé de matrice."""
    s = security.upper().strip()
    if s in ("OPN", "OPEN", "", "NONE", "--"):
        return "open_network"
    if "WEP" in s and "WPA" not in s:
        return "wep"
    if "WPA2" in s and "ENTERPRISE" in s:
        return "wpa2_enterprise"
    if "WPA2" in s or "RSN" in s:
        return "wpa2_personal"
    if "WPA" in s and "WPA2" not in s and "WPA3" not in s:
        if "TKIP" in s:
            return "wpa_tkip"
        return "wpa_tkip"
    if "WPA3" in s:
        return "wpa2_enterprise"  # WPA3 → meilleure catégorie dispo
    return "wpa2_personal"


def _classify_signal(rssi: int) -> str:
    if rssi >= SIGNAL_THRESHOLDS["excellent"]:
        return f"Excellent ({rssi} dBm) — AP probablement proche"
    elif rssi >= SIGNAL_THRESHOLDS["good"]:
        return f"Bon ({rssi} dBm)"
    elif rssi >= SIGNAL_THRESHOLDS["fair"]:
        return f"Moyen ({rssi} dBm)"
    elif rssi >= SIGNAL_THRESHOLDS["poor"]:
        return f"Faible ({rssi} dBm)"
    else:
        return f"Très faible ({rssi} dBm) — AP éloigné ou murs épais"


def _lookup_vendor(bssid: str) -> str:
    """Lookup du fabricant via les 3 premiers octets du BSSID."""
    prefix = bssid[:8].lower()
    return KNOWN_VENDORS.get(prefix, "Fabricant inconnu")


def _is_suspicious_ssid(ssid: str) -> bool:
    ssid_lower = ssid.lower()
    for pattern in SUSPICIOUS_SSID_PATTERNS:
        if re.search(pattern, ssid_lower):
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Scan dossier
# ──────────────────────────────────────────────────────────────────────────────

def scan_directory(directory: str) -> list[dict]:
    """Parcourt un dossier et analyse tous les fichiers WiFi trouvés."""
    severity_matrix = load_severity_matrix()
    raw_networks    = []
    directory_path  = Path(directory)

    # Extensions supportées
    extensions = {
        ".txt":  parse_wifi_log_txt,
        ".log":  parse_wifi_log_txt,
        ".csv":  parse_wifi_csv,
        ".json": parse_wifi_json,
    }

    found_files = []
    for ext, parser in extensions.items():
        files = list(directory_path.rglob(f"*wifi*{ext}")) + \
                list(directory_path.rglob(f"*scan*{ext}")) + \
                list(directory_path.rglob(f"*ap*{ext}")) + \
                list(directory_path.rglob(f"*marauder*{ext}"))
        found_files.extend([(f, parser) for f in files])

    # Dédoublonnage
    seen = set()
    unique_files = []
    for f, p in found_files:
        if f not in seen:
            seen.add(f)
            unique_files.append((f, p))

    if not unique_files:
        print(f"[INFO] Aucun fichier WiFi trouvé dans {directory}")
        return []

    print(f"[INFO] {len(unique_files)} fichier(s) WiFi trouvé(s)")

    for filepath, parser in unique_files:
        networks = parser(str(filepath))
        for net in networks:
            net["source_file"] = os.path.basename(filepath)
            net["timestamp"]   = datetime.now().isoformat()
        raw_networks.extend(networks)

    if not raw_networks:
        return []

    # Liste de tous les SSIDs pour détection Evil Twin
    all_ssids = [n.get("ssid", "") for n in raw_networks]

    findings = []
    for network in raw_networks:
        finding = analyze_network(network, severity_matrix, all_ssids)
        findings.append(finding)
        _print_finding_summary(finding)

    return findings


def _print_finding_summary(f: dict):
    sev     = f.get("severity", "?")
    score   = f.get("score", 0)
    ssid    = f.get("ssid", "<hidden>") or "<hidden>"
    bssid   = f.get("bssid", "?")
    sec     = f.get("security", "?")
    signal  = f.get("rssi", 0)
    evil    = " ⚠EVIL TWIN" if f.get("is_evil_twin") else ""
    print(f"  [{sev:8s}] {score:4.1f} | {ssid:<25s} | {bssid} | {sec:<12s} | {signal} dBm{evil}")


# ──────────────────────────────────────────────────────────────────────────────
# Point d'entrée standalone
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage : python wifi_parser.py <dossier_ou_fichier>")
        sys.exit(1)

    target = sys.argv[1]
    severity_matrix = load_severity_matrix()

    if os.path.isdir(target):
        results = scan_directory(target)
    elif os.path.isfile(target):
        ext = Path(target).suffix.lower()
        parsers_map = {
            ".txt": parse_wifi_log_txt,
            ".log": parse_wifi_log_txt,
            ".csv": parse_wifi_csv,
            ".json": parse_wifi_json,
        }
        parser = parsers_map.get(ext, parse_wifi_log_txt)
        raw_nets = parser(target)
        all_ssids = [n.get("ssid", "") for n in raw_nets]
        results = [analyze_network(n, severity_matrix, all_ssids) for n in raw_nets]
        for r in results:
            r["source_file"] = os.path.basename(target)
            r["timestamp"]   = datetime.now().isoformat()
            _print_finding_summary(r)
    else:
        print(f"[ERREUR] Chemin introuvable : {target}")
        sys.exit(1)

    print(f"\n[RÉSULTAT] {len(results)} réseau(x) WiFi analysé(s)")
