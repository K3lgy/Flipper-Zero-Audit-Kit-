"""
badusb_parser.py — Parseur de logs d'exécution Bad USB (Flipper Zero)
Lit les fichiers de résultats générés par les payloads Bad USB
et produit des findings de sécurité pour le rapport.

Format attendu des logs (généré par le payload PowerShell/bash) :
  TARGET_HOST=NOM_MACHINE
  TARGET_USER=nom_utilisateur
  TARGET_OS=Windows 10 Pro 22H2
  EXECUTION_STATUS=SUCCESS
  UAC_LEVEL=ConsentPromptBehaviorAdmin=5
  AV_STATUS=Windows Defender: Enabled
  LOCK_SCREEN=Enabled
  USB_POLICY=NoRestriction
  TIMESTAMP=2026-07-05T14:23:11
  NOTES=Poste RH bureau 3
"""

import os
import re
import json
from datetime import datetime
from pathlib import Path


SEVERITY_MATRIX_PATH = Path(__file__).parent.parent / "findings" / "severity_matrix.json"

# Statuts d'exécution
EXECUTION_STATUSES = {
    "SUCCESS":      ("CRITIQUE", 9.0, "Exécution réussie — code arbitraire exécuté sans restriction"),
    "PARTIAL":      ("ELEVE",    7.0, "Exécution partielle — certaines commandes bloquées (AV/EDR)"),
    "BLOCKED":      ("FAIBLE",   2.0, "Exécution bloquée — politique USB ou AV efficace"),
    "AUTORUN_ONLY": ("MOYEN",    5.0, "AutoRun uniquement — HID non filtré mais exécution limitée"),
    "UNKNOWN":      ("MOYEN",    5.0, "Résultat indéterminé — vérification manuelle requise"),
}

# Niveaux UAC Windows
UAC_LEVELS = {
    "0": ("CRITIQUE", "UAC désactivé — élévation de privilèges sans invite utilisateur possible"),
    "1": ("CRITIQUE", "UAC niveau 1 — élévation silencieuse pour apps signées Microsoft"),
    "2": ("ELEVE",    "UAC niveau 2 — invite uniquement pour apps non Microsoft"),
    "3": ("MOYEN",    "UAC niveau 3 — invite pour toute élévation sur bureau sécurisé"),
    "4": ("MOYEN",    "UAC niveau 4 — invite toujours (réglage par défaut Windows)"),
    "5": ("MOYEN",    "UAC niveau 5 (défaut Windows) — invite pour modifications système"),
}

# Politiques USB
USB_POLICIES = {
    "NORESTRICTION": ("CRITIQUE", "Aucune restriction USB — tout périphérique accepté"),
    "READONLY":      ("MOYEN",    "USB en lecture seule — HID non filtré, clavier accepté"),
    "BLOCKED":       ("FAIBLE",   "USB bloqué par GPO/MDM — bonne pratique"),
    "WHITELIST":     ("FAIBLE",   "USB whitelist par VID/PID — contrôle strict"),
    "UNKNOWN":       ("MOYEN",    "Politique USB non déterminée"),
}


def load_severity_matrix() -> dict:
    with open(SEVERITY_MATRIX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["badusb"]


def parse_badusb_log(filepath: str) -> dict | None:
    """Parse un fichier log de résultat Bad USB."""
    result = {
        "source_file": os.path.basename(filepath),
        "source_path": filepath,
        "format":      "badusb_log",
        "timestamp":   datetime.now().isoformat(),
        "raw_fields":  {},
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"[ERREUR] Impossible de lire {filepath} : {e}")
        return None

    # Parse KEY=VALUE
    raw = {}
    for line in content.splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            raw[key.strip().upper()] = value.strip()

    result["raw_fields"]     = raw
    result["target_host"]    = raw.get("TARGET_HOST", "Inconnu")
    result["target_user"]    = raw.get("TARGET_USER", "Inconnu")
    result["target_os"]      = raw.get("TARGET_OS", "Inconnu")
    result["execution_status"] = raw.get("EXECUTION_STATUS", "UNKNOWN").upper()
    result["av_status"]      = raw.get("AV_STATUS", "Non déterminé")
    result["lock_screen"]    = raw.get("LOCK_SCREEN", "Non déterminé")
    result["usb_policy"]     = raw.get("USB_POLICY", "UNKNOWN").upper()
    result["uac_level"]      = _extract_uac_level(raw.get("UAC_LEVEL", ""))
    result["notes"]          = raw.get("NOTES", "")
    result["payload_name"]   = raw.get("PAYLOAD", os.path.basename(filepath).replace(".txt", ""))

    # Timestamp de l'exécution
    ts = raw.get("TIMESTAMP", "")
    result["execution_timestamp"] = ts if ts else datetime.now().isoformat()

    # Données collectées par le payload
    result["collected_data"] = {
        "hostname":     raw.get("HOSTNAME", raw.get("TARGET_HOST", "")),
        "username":     raw.get("USERNAME", raw.get("TARGET_USER", "")),
        "domain":       raw.get("DOMAIN", ""),
        "os_version":   raw.get("OS_VERSION", raw.get("TARGET_OS", "")),
        "ip_addresses": raw.get("IP_ADDRESSES", ""),
        "installed_av": raw.get("AV_PRODUCT", ""),
        "open_ports":   raw.get("OPEN_PORTS", ""),
    }

    return result


def _extract_uac_level(uac_str: str) -> str:
    """Extrait le niveau UAC depuis une chaîne comme 'ConsentPromptBehaviorAdmin=5'."""
    match = re.search(r"=(\d)", uac_str)
    if match:
        return match.group(1)
    if uac_str.isdigit():
        return uac_str
    return "Unknown"


def analyze_badusb(log_data: dict, severity_matrix: dict) -> dict:
    """Enrichit les données Bad USB avec l'analyse de criticité."""

    exec_status = log_data.get("execution_status", "UNKNOWN")
    usb_policy  = log_data.get("usb_policy", "UNKNOWN")
    uac_level   = log_data.get("uac_level", "Unknown")
    av_status   = log_data.get("av_status", "")

    # Criticité basée sur le statut d'exécution
    status_severity, status_score, status_desc = EXECUTION_STATUSES.get(
        exec_status, EXECUTION_STATUSES["UNKNOWN"]
    )

    # Clé severity_matrix
    matrix_key = "execution_success" if exec_status == "SUCCESS" else "autorun_disabled"
    severity_info = severity_matrix.get(matrix_key, {
        "severity": status_severity,
        "score": status_score,
        "description": status_desc,
        "recommendation": "Appliquer une politique USB stricte",
        "cve_ref": "CWE-284",
        "color": "orange",
    })

    finding = {
        **log_data,
        "severity":         severity_info.get("severity", status_severity),
        "score":            severity_info.get("score", status_score),
        "vuln_description": f"{status_desc}. {severity_info.get('description', '')}".strip(". "),
        "recommendation":   severity_info.get("recommendation", ""),
        "cve_ref":          severity_info.get("cve_ref"),
        "color":            severity_info.get("color", "orange"),
        "attack_vectors":   [],
        "additional_risks": [],
    }

    # Vecteurs d'attaque selon le statut
    if exec_status == "SUCCESS":
        finding["attack_vectors"] = [
            "Extraction d'informations système (hostname, IP, utilisateurs, processus)",
            "Persistance possible : ajout de tâche planifiée ou clé de registre",
            "Téléchargement et exécution de payload secondaire depuis Internet",
            "Vol de tokens/cookies depuis les navigateurs (si non chiffrés)",
            "Pivot réseau depuis le poste compromis",
        ]

    # Risques UAC
    uac_sev, uac_desc = UAC_LEVELS.get(uac_level, ("MOYEN", f"UAC niveau {uac_level}"))
    if uac_level in ("0", "1", "2"):
        finding["additional_risks"].append(
            f"UAC faible : {uac_desc} [{uac_sev}]"
        )

    # Risques politique USB
    usb_sev, usb_desc = USB_POLICIES.get(usb_policy.replace(" ", ""), ("MOYEN", "Politique USB inconnue"))
    if usb_policy in ("NORESTRICTION", "UNKNOWN"):
        finding["additional_risks"].append(
            f"Politique USB : {usb_desc} [{usb_sev}]"
        )

    # Antivirus
    av_lower = av_status.lower()
    if "disabled" in av_lower or "off" in av_lower or av_status == "":
        finding["additional_risks"].append(
            "⚠️ Antivirus DÉSACTIVÉ ou absent — aucune protection contre les payloads malveillants"
        )
    elif "enabled" in av_lower or "on" in av_lower:
        finding["additional_risks"].append(
            f"Antivirus actif ({av_status}) — payload basique détectable, contournement possible par obfuscation"
        )

    # Écran de verrouillage
    lock = log_data.get("lock_screen", "").upper()
    if "DISABLED" in lock or lock == "":
        finding["additional_risks"].append(
            "Verrouillage automatique désactivé — poste accessible sans authentification après inactivité"
        )

    return finding


def scan_directory(directory: str) -> list[dict]:
    """Scan un dossier pour les logs Bad USB."""
    severity_matrix = load_severity_matrix()
    findings = []
    directory_path = Path(directory)

    # Recherche par patterns de noms
    patterns = ["*badusb*", "*bad_usb*", "*payload*result*", "*usb*log*", "*hid*result*"]
    found_files = set()
    for pattern in patterns:
        for f in directory_path.rglob(pattern):
            if f.suffix in (".txt", ".log"):
                found_files.add(f)

    if not found_files:
        print(f"[INFO] Aucun log Bad USB trouvé dans {directory}")
        return []

    print(f"[INFO] {len(found_files)} log(s) Bad USB trouvé(s)")

    for filepath in found_files:
        raw = parse_badusb_log(str(filepath))
        if raw:
            finding = analyze_badusb(raw, severity_matrix)
            findings.append(finding)
            _print_finding_summary(finding)

    return findings


def _print_finding_summary(f: dict):
    sev    = f.get("severity", "?")
    score  = f.get("score", 0)
    host   = f.get("target_host", "?")
    user   = f.get("target_user", "?")
    status = f.get("execution_status", "?")
    src    = f.get("source_file", "?")
    print(f"  [{sev:8s}] {score:4.1f} | Host: {host:<20s} | User: {user:<15s} | {status} | {src}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage : python badusb_parser.py <dossier_ou_fichier.txt>")
        sys.exit(1)

    target = sys.argv[1]
    severity_matrix = load_severity_matrix()

    if os.path.isdir(target):
        results = scan_directory(target)
    elif os.path.isfile(target):
        raw = parse_badusb_log(target)
        if raw:
            results = [analyze_badusb(raw, severity_matrix)]
            _print_finding_summary(results[0])
        else:
            results = []
    else:
        print(f"[ERREUR] Chemin introuvable : {target}")
        sys.exit(1)

    print(f"\n[RÉSULTAT] {len(results)} finding(s) Bad USB analysé(s)")
