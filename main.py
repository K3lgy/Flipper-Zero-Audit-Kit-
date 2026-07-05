#!/usr/bin/env python3
"""
main.py — Point d'entrée CLI du kit d'audit physique Flipper Zero
Kapelgy — Audit de sécurité physique

Usage :
    python main.py --input ./sd_card --client "Acme SA" --auditor "Jean Dupont"
    python main.py --input ./sd_card --client "Acme SA" --output ./rapports/audit.pdf
    python main.py --demo
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

# Ajout du répertoire parent dans le path pour les imports relatifs
sys.path.insert(0, str(Path(__file__).parent))

from parsers.rfid_parser    import scan_directory as scan_rfid
from parsers.subghz_parser  import scan_directory as scan_subghz
from parsers.wifi_parser    import scan_directory as scan_wifi
from parsers.badusb_parser  import scan_directory as scan_badusb
from report.generate_report import generate_report


# ──────────────────────────────────────────────────────────────────────────────
# Données de démonstration
# ──────────────────────────────────────────────────────────────────────────────

DEMO_RFID_FINDINGS = [
    {
        "source_file": "badge_salle_serveur.nfc",
        "source_path": "/demo/badge_salle_serveur.nfc",
        "format": "nfc",
        "timestamp": datetime.now().isoformat(),
        "card_type_raw": "Mifare Classic 1K",
        "card_type_normalized": "Mifare Classic 1K",
        "uid": "DE AD BE EF",
        "uid_bytes": 4,
        "atqa": "00 04",
        "sak": "08",
        "blocks_read": 64,
        "default_keys_detected": True,
        "manufacturer_block": "DE AD BE EF 22 08 04 00 62 63 64 65 66 67 68 69",
        "severity": "CRITIQUE",
        "score": 9.8,
        "vuln_description": "MIFARE Classic 1K — algorithme CRYPTO1 cassé depuis 2008 (attaque Darkside/Nested), clonage trivial. Clés par défaut FFFFFFFFFFFF détectées.",
        "recommendation": "Migrer vers MIFARE DESFire EV2 avec SAM ou HID iClass SE",
        "cve_ref": "CVE-2008-0149",
        "color": "red",
        "is_cloneable": True,
        "attack_vectors": [
            "Attaque Darkside (récupération clé secteur 0 en ~1 min)",
            "Attaque Nested (récupération de toutes les clés une fois une clé connue)",
            "Clonage complet du badge avec le Flipper ou un téléphone NFC",
        ],
        "additional_risks": [
            "⚠️ CLÉS PAR DÉFAUT DÉTECTÉES — Lecture complète du badge sans attaque préalable"
        ],
    },
    {
        "source_file": "badge_parking.rfid",
        "source_path": "/demo/badge_parking.rfid",
        "format": "rfid",
        "timestamp": datetime.now().isoformat(),
        "card_type_raw": "EM4100",
        "card_type_normalized": "EM4100",
        "uid": "01 23 45 67 89",
        "uid_bytes": 5,
        "atqa": None,
        "sak": None,
        "blocks_read": 0,
        "default_keys_detected": False,
        "manufacturer_block": None,
        "severity": "CRITIQUE",
        "score": 9.1,
        "vuln_description": "Badge EM4100 — technologie 125kHz sans chiffrement, clonable en <5 secondes avec n'importe quel lecteur bas coût",
        "recommendation": "Remplacer par des badges MIFARE DESFire EV2/EV3 ou HID iClass SE",
        "cve_ref": "CWE-287",
        "color": "red",
        "is_cloneable": True,
        "attack_vectors": [
            "Lecture longue portée (jusqu'à 30cm) avec amplificateur RF",
            "Clonage en quelques secondes avec writer T5577",
            "Pas de mécanisme d'anti-replay",
        ],
        "additional_risks": [],
    },
]

DEMO_SUBGHZ_FINDINGS = [
    {
        "source_file": "portail_parking.sub",
        "source_path": "/demo/portail_parking.sub",
        "format": "sub",
        "timestamp": datetime.now().isoformat(),
        "is_raw_capture": False,
        "frequency_hz": 433920000,
        "frequency_mhz": 433.92,
        "frequency_context": "Europe — télécommandes, garage, alarmes",
        "preset": "FuriHalSubGhzPresetOok650Async",
        "modulation": "OOK 650 baud/s (ASK) — le plus courant",
        "protocol": "Nice FLO",
        "protocol_type": "fixed_code",
        "protocol_usage": "Systèmes Nice (portails, volets, barrières)",
        "key": "00 00 00 00 00 A1 B2 C3",
        "bits": "24",
        "raw_samples_count": 0,
        "raw_duration_ms": 0,
        "capture_note": "portail parking",
        "is_replay_vulnerable": True,
        "severity": "CRITIQUE",
        "score": 9.3,
        "vuln_description": "Protocole à code fixe — le signal est identique à chaque transmission, rejouable indéfiniment après capture",
        "recommendation": "Remplacer par un système à code tournant (rolling code) — KeeLoq, AUT64 ou équivalent",
        "cve_ref": "CWE-294",
        "color": "red",
        "attack_vectors": [
            "Capture du signal à distance (portée Flipper : jusqu'à ~50m en champ libre)",
            "Relecture immédiate avec le Flipper — aucun outil supplémentaire requis",
            "Signal identique à 100% — indétectable par les systèmes standards",
        ],
        "additional_risks": [],
    },
]

DEMO_WIFI_FINDINGS = [
    {
        "source_file": "scan_wifi_bureau.txt",
        "source_path": "/demo/scan_wifi_bureau.txt",
        "format": "txt",
        "timestamp": datetime.now().isoformat(),
        "bssid": "AA:BB:CC:DD:EE:FF",
        "ssid": "RESEAU-INVITE-OPEN",
        "channel": 6,
        "security": "OPEN",
        "rssi": -62,
        "pmf": False,
        "hidden": False,
        "security_type": "open_network",
        "vendor": "Cisco Meraki",
        "signal_quality": "Bon (-62 dBm)",
        "is_evil_twin": False,
        "severity": "CRITIQUE",
        "score": 9.5,
        "vuln_description": "Réseau ouvert sans chiffrement — tout le trafic est interceptable en clair",
        "recommendation": "Supprimer immédiatement ce réseau. Si réseau invité requis : WPA2 + portail captif + isolation client",
        "cve_ref": "CWE-311",
        "color": "red",
        "attack_vectors": [
            "Capture passive de tout le trafic (Wireshark, tcpdump)",
            "Injection de paquets sans association préalable",
            "MITM trivial — redirection DNS, injection HTTP",
        ],
        "additional_risks": [
            "PMF (802.11w) non activé — vulnérable aux attaques de déauthentification"
        ],
    },
    {
        "source_file": "scan_wifi_bureau.txt",
        "source_path": "/demo/scan_wifi_bureau.txt",
        "format": "txt",
        "timestamp": datetime.now().isoformat(),
        "bssid": "11:22:33:44:55:66",
        "ssid": "CorpNet-WiFi",
        "channel": 11,
        "security": "WPA2",
        "rssi": -58,
        "pmf": False,
        "hidden": False,
        "security_type": "wpa2_personal",
        "vendor": "Aruba Networks",
        "signal_quality": "Bon (-58 dBm)",
        "is_evil_twin": False,
        "severity": "MOYEN",
        "score": 4.5,
        "vuln_description": "WPA2-Personal (PSK) — sécurisé si passphrase forte, mais la PSK partagée est un risque",
        "recommendation": "Migrer vers WPA2/WPA3-Enterprise avec RADIUS. Vérifier la robustesse de la PSK.",
        "cve_ref": "CWE-521",
        "color": "orange",
        "attack_vectors": [
            "Capture du handshake 4-way + attaque dictionnaire/brute-force offline",
            "Attaque PMKID (sans handshake complet)",
        ],
        "additional_risks": [
            "PMF (802.11w) non activé — vulnérable aux attaques de déauthentification"
        ],
    },
]

DEMO_BADUSB_FINDINGS = [
    {
        "source_file": "badusb_rh_poste3.txt",
        "source_path": "/demo/badusb_rh_poste3.txt",
        "format": "badusb_log",
        "timestamp": datetime.now().isoformat(),
        "target_host": "WKSRH-003",
        "target_user": "marie.dupont",
        "target_os": "Windows 10 Pro 22H2",
        "execution_status": "SUCCESS",
        "av_status": "Windows Defender: Enabled",
        "lock_screen": "Disabled",
        "usb_policy": "NORESTRICTION",
        "uac_level": "5",
        "notes": "Poste RH bureau 3 — PC déverrouillé pendant pause café",
        "payload_name": "demo_sysinfo",
        "execution_timestamp": datetime.now().isoformat(),
        "collected_data": {
            "hostname": "WKSRH-003",
            "username": "marie.dupont",
            "domain": "CORP",
            "os_version": "Windows 10 Pro 22H2",
            "ip_addresses": "192.168.1.45",
            "installed_av": "Windows Defender",
            "open_ports": "",
        },
        "severity": "CRITIQUE",
        "score": 9.0,
        "vuln_description": "Exécution de code via périphérique USB non autorisé — poste vulnérable sans contrôle USB ni politique de verrouillage",
        "recommendation": "Déployer une politique USB via GPO/MDM (whitelist par VID/PID). Activer le verrouillage automatique. Former les utilisateurs.",
        "cve_ref": "CWE-284",
        "color": "red",
        "attack_vectors": [
            "Extraction d'informations système (hostname, IP, utilisateurs, processus)",
            "Persistance possible : ajout de tâche planifiée ou clé de registre",
            "Téléchargement et exécution de payload secondaire depuis Internet",
        ],
        "additional_risks": [
            "Verrouillage automatique désactivé — poste accessible sans authentification après inactivité",
            "Politique USB : Aucune restriction USB — tout périphérique accepté [CRITIQUE]",
        ],
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Fonctions principales
# ──────────────────────────────────────────────────────────────────────────────

def run_scan(input_dir: str, verbose: bool = False) -> tuple[list, list, list, list]:
    """Lance les 4 parseurs sur le dossier d'entrée."""
    print(f"\n{'='*60}")
    print(f"  AUDIT PHYSIQUE FLIPPER ZERO — Kapelgy")
    print(f"  Dossier analysé : {input_dir}")
    print(f"{'='*60}\n")

    print("▶ Analyse RFID / NFC...")
    rfid = scan_rfid(input_dir)
    print(f"  → {len(rfid)} finding(s)\n")

    print("▶ Analyse Sub-GHz...")
    subghz = scan_subghz(input_dir)
    print(f"  → {len(subghz)} finding(s)\n")

    print("▶ Analyse WiFi...")
    wifi = scan_wifi(input_dir)
    print(f"  → {len(wifi)} finding(s)\n")

    print("▶ Analyse Bad USB...")
    badusb = scan_badusb(input_dir)
    print(f"  → {len(badusb)} finding(s)\n")

    total = len(rfid) + len(subghz) + len(wifi) + len(badusb)
    print(f"{'─'*60}")
    print(f"  TOTAL : {total} finding(s) identifié(s)")
    print(f"{'─'*60}\n")

    return rfid, subghz, wifi, badusb


def run_demo() -> tuple[list, list, list, list]:
    """Retourne les données de démonstration."""
    print("\n" + "="*60)
    print("  MODE DÉMONSTRATION — Données fictives")
    print("  (Utilisez --input <dossier> pour analyser de vrais fichiers)")
    print("="*60 + "\n")
    return DEMO_RFID_FINDINGS, DEMO_SUBGHZ_FINDINGS, DEMO_WIFI_FINDINGS, DEMO_BADUSB_FINDINGS


def print_stats(rfid, subghz, wifi, badusb):
    """Affiche un résumé des findings dans le terminal."""
    from collections import Counter
    all_f = rfid + subghz + wifi + badusb
    counts = Counter(f.get("severity", "MOYEN") for f in all_f)

    print("  ┌─────────────────────────────────────────────────┐")
    print("  │           SYNTHÈSE DES FINDINGS                 │")
    print("  ├──────────┬────────┬────────┬────────┬──────────┤")
    print("  │ CRITIQUE │ ÉLEVÉ  │  MOYEN │ FAIBLE │  TOTAL   │")
    print("  ├──────────┼────────┼────────┼────────┼──────────┤")
    print(f"  │   {counts.get('CRITIQUE',0):^6d}   │  {counts.get('ELEVE',0):^4d}  │  {counts.get('MOYEN',0):^4d}  │  {counts.get('FAIBLE',0):^4d}  │   {len(all_f):^5d}  │")
    print("  └──────────┴────────┴────────┴────────┴──────────┘\n")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Flipper Zero Audit Kit — Générateur de rapport de sécurité physique",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  # Analyse d'une carte SD Flipper + rapport PDF
  python main.py --input /media/flipper/SD_CARD --client "Acme SA"

  # Avec tous les paramètres
  python main.py --input ./sd_card \\
                 --client "Acme SA" \\
                 --auditor "Jean Dupont" \\
                 --output ./rapports/audit_acme_2026.pdf \\
                 --ref "AUDIT-2026-001"

  # Mode démonstration (pas besoin de fichiers Flipper)
  python main.py --demo --client "Démo Client"

  # Export JSON des findings en plus du PDF
  python main.py --input ./sd_card --client "Acme SA" --json
        """
    )

    parser.add_argument(
        "--input", "-i",
        help="Dossier contenant les fichiers exportés depuis la carte SD du Flipper Zero",
        metavar="DOSSIER",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Utiliser des données de démonstration (sans fichiers Flipper)",
    )
    parser.add_argument(
        "--client", "-c",
        default="Client",
        help="Nom du client pour le rapport (défaut : 'Client')",
        metavar="NOM",
    )
    parser.add_argument(
        "--auditor", "-a",
        default="Kapelgy",
        help="Nom de l'auditeur (défaut : 'Kapelgy')",
        metavar="NOM",
    )
    parser.add_argument(
        "--output", "-o",
        help="Chemin de sortie du rapport PDF (défaut : ./rapport_audit_<date>.pdf)",
        metavar="FICHIER.pdf",
    )
    parser.add_argument(
        "--ref",
        help="Référence de la mission (ex: AUDIT-2026-001)",
        metavar="REF",
    )
    parser.add_argument(
        "--context",
        help="Contexte de la mission (texte libre pour le résumé exécutif)",
        metavar="TEXTE",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Exporter également les findings en JSON",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Affichage détaillé",
    )

    return parser.parse_args()


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    # Vérification des arguments
    if not args.input and not args.demo:
        print("[ERREUR] Spécifiez --input <dossier> ou --demo")
        print("         Utilisez --help pour l'aide complète")
        sys.exit(1)

    if args.input and not os.path.isdir(args.input):
        print(f"[ERREUR] Dossier introuvable : {args.input}")
        sys.exit(1)

    # Lancement de l'analyse
    if args.demo:
        rfid, subghz, wifi, badusb = run_demo()
    else:
        rfid, subghz, wifi, badusb = run_scan(args.input, args.verbose)

    # Résumé terminal
    print_stats(rfid, subghz, wifi, badusb)

    # Chemins de sortie
    date_str = datetime.now().strftime("%Y%m%d_%H%M")
    client_slug = args.client.lower().replace(" ", "_").replace("/", "-")

    if args.output:
        pdf_path = args.output
    else:
        pdf_path = f"rapport_audit_{client_slug}_{date_str}.pdf"

    # Informations du document
    doc_info = {
        "client":     args.client,
        "auditor":    args.auditor,
        "audit_date": datetime.now().strftime("%d/%m/%Y"),
        "ref":        args.ref or f"AUDIT-{date_str}",
        "version":    "1.0",
        "context":    args.context or (
            f"Cet audit de sécurité physique a été réalisé avec un Flipper Zero "
            f"pour le compte de {args.client} dans le cadre d'une évaluation de la "
            f"posture de sécurité physique. L'objectif est d'identifier les vecteurs "
            f"d'attaque exploitables par un attaquant disposant d'un accès aux locaux "
            f"(insider, visiteur, prestataire)."
        ),
    }

    # Génération du PDF
    print("▶ Génération du rapport PDF...")
    output_path = generate_report(
        rfid_findings=rfid,
        subghz_findings=subghz,
        wifi_findings=wifi,
        badusb_findings=badusb,
        output_path=pdf_path,
        doc_info=doc_info,
    )

    # Export JSON optionnel
    if args.json:
        all_findings = rfid + subghz + wifi + badusb
        json_path = pdf_path.replace(".pdf", "_findings.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(all_findings, f, ensure_ascii=False, indent=2, default=str)
        print(f"[✓] Findings JSON : {json_path}")

    print(f"\n{'='*60}")
    print(f"  Rapport disponible : {os.path.abspath(pdf_path)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
