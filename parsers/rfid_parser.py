"""
rfid_parser.py — Parseur de fichiers RFID/NFC Flipper Zero
Formats supportés : .nfc (MIFARE, NFC-A/B/V) et .rfid (125kHz EM4100, HID, etc.)
"""

import os
import json
import re
from datetime import datetime
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_MATRIX_PATH = Path(__file__).parent.parent / "findings" / "severity_matrix.json"

# Mapping nom Flipper → clé severity_matrix
CARD_TYPE_MAP = {
    # 125 kHz
    "EM4100":              "EM4100",
    "EM-Marin":            "EM4100",
    "HID 26bit":           "HID Prox",
    "HID Generic":         "HID Prox",
    "Indala":              "HID Prox",
    "Paradox":             "EM4100",
    "Viking":              "EM4100",
    "Noralsy":             "EM4100",
    "Jablotron":           "EM4100",
    "Pyramid":             "EM4100",
    "Keri":                "EM4100",
    "Gallagher":           "EM4100",
    "PAC/Stanley":         "EM4100",
    "IoProx":              "EM4100",
    "Nexwatch":            "EM4100",
    "FDX-A":               "EM4100",
    "FDX-B":               "EM4100",
    "Hitag 1":             "EM4100",
    "Hitag 2":             "EM4100",
    "Hitag S":             "EM4100",
    # 13.56 MHz
    "Mifare Classic 1K":   "Mifare Classic 1K",
    "Mifare Classic 4K":   "Mifare Classic 4K",
    "Mifare Ultralight":   "Mifare Ultralight",
    "Mifare Ultralight C": "Mifare Ultralight",
    "NTAG203":             "Mifare Ultralight",
    "NTAG213":             "Mifare Ultralight",
    "NTAG215":             "Mifare Ultralight",
    "NTAG216":             "Mifare Ultralight",
    "Mifare DESFire":      "Mifare DESFire",
    "ISO14443-4 (7b UID)": "Mifare DESFire",
    "iClass 2k":           "HID iClass",
    "iClass 16k":          "HID iClass",
    "iClass SE":           "HID iClass SE",
    "SEOS":                "HID iClass SE",
    "Unknown": "Unknown",
}

CLONEABLE_TYPES = {
    "EM4100", "HID Prox", "Mifare Classic 1K",
    "Mifare Classic 4K", "Mifare Ultralight",
}


# ──────────────────────────────────────────────────────────────────────────────
# Chargement de la matrice de criticité
# ──────────────────────────────────────────────────────────────────────────────

def load_severity_matrix() -> dict:
    with open(SEVERITY_MATRIX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["rfid"]


# ──────────────────────────────────────────────────────────────────────────────
# Parseurs de fichiers
# ──────────────────────────────────────────────────────────────────────────────

def parse_nfc_file(filepath: str) -> dict | None:
    """Parse un fichier .nfc exporté par le Flipper Zero."""
    result = {
        "source_file": os.path.basename(filepath),
        "source_path": filepath,
        "format": "nfc",
        "timestamp": datetime.now().isoformat(),
        "raw_fields": {},
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[ERREUR] Impossible de lire {filepath} : {e}")
        return None

    # Vérification entête
    if not lines:
        return None
    if "Flipper NFC" not in lines[0] and "Flipper RFID" not in lines[0]:
        # Tentative quand même (fichiers exportés par tierce application)
        pass

    raw = {}
    for line in lines:
        line = line.strip()
        if ":" in line:
            key, _, value = line.partition(":")
            raw[key.strip()] = value.strip()

    result["raw_fields"] = raw

    # Type de carte
    device_type = raw.get("Device type", raw.get("Card type", "Unknown"))
    result["card_type_raw"] = device_type

    # Normalisation vers clé severity_matrix
    mapped = "Unknown"
    for k, v in CARD_TYPE_MAP.items():
        if k.lower() in device_type.lower():
            mapped = v
            break
    result["card_type_normalized"] = mapped

    # UID
    uid = raw.get("UID", raw.get("Data", "N/A"))
    result["uid"] = uid
    result["uid_bytes"] = len(uid.replace(" ", "")) // 2 if uid != "N/A" else 0

    # Détails techniques
    result["atqa"]  = raw.get("ATQA", None)
    result["sak"]   = raw.get("SAK", None)
    result["version"] = raw.get("Version", None)

    # Analyse des blocs (MIFARE Classic)
    blocks = {}
    for key, val in raw.items():
        if re.match(r"^Block\s+\d+$", key, re.IGNORECASE):
            block_num = int(re.search(r"\d+", key).group())
            blocks[block_num] = val
    result["blocks_read"] = len(blocks)
    result["blocks_data"] = blocks

    # Détection clés par défaut MIFARE Classic (FFFFFFFFFFFF / 000000000000)
    result["default_keys_detected"] = False
    block_values = list(blocks.values())
    for bv in block_values:
        bv_clean = bv.replace(" ", "").lower()
        if "ffffffffffff" in bv_clean or "000000000000" in bv_clean:
            result["default_keys_detected"] = True
            break

    # Données brutes blocs secteur 0 (fabricant)
    if 0 in blocks:
        result["manufacturer_block"] = blocks[0]
    else:
        result["manufacturer_block"] = None

    return result


def parse_rfid_file(filepath: str) -> dict | None:
    """Parse un fichier .rfid (125kHz LF) exporté par le Flipper Zero."""
    result = {
        "source_file": os.path.basename(filepath),
        "source_path": filepath,
        "format": "rfid",
        "timestamp": datetime.now().isoformat(),
        "raw_fields": {},
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[ERREUR] Impossible de lire {filepath} : {e}")
        return None

    raw = {}
    for line in lines:
        line = line.strip()
        if ":" in line:
            key, _, value = line.partition(":")
            raw[key.strip()] = value.strip()

    result["raw_fields"] = raw

    key_type = raw.get("Key type", raw.get("Card type", "Unknown"))
    result["card_type_raw"] = key_type

    mapped = "Unknown"
    for k, v in CARD_TYPE_MAP.items():
        if k.lower() in key_type.lower():
            mapped = v
            break
    result["card_type_normalized"] = mapped

    data = raw.get("Data", "N/A")
    result["uid"]       = data
    result["uid_bytes"] = len(data.replace(" ", "")) // 2 if data != "N/A" else 0

    # Champs LF spécifiques
    result["atqa"]  = None
    result["sak"]   = None
    result["version"] = raw.get("Version", None)
    result["blocks_read"]     = 0
    result["blocks_data"]     = {}
    result["default_keys_detected"] = False
    result["manufacturer_block"]    = None

    return result


# ──────────────────────────────────────────────────────────────────────────────
# Analyse et enrichissement
# ──────────────────────────────────────────────────────────────────────────────

def analyze_card(card_data: dict, severity_matrix: dict) -> dict:
    """Enrichit les données carte avec l'analyse de criticité."""

    card_type = card_data.get("card_type_normalized", "Unknown")
    severity_info = severity_matrix.get(card_type, severity_matrix["Unknown"])

    finding = {
        **card_data,
        "severity":         severity_info["severity"],
        "score":            severity_info["score"],
        "vuln_description": severity_info["description"],
        "recommendation":   severity_info["recommendation"],
        "cve_ref":          severity_info.get("cve_ref"),
        "color":            severity_info.get("color", "orange"),
        "is_cloneable":     card_type in CLONEABLE_TYPES,
        "attack_vectors":   [],
        "additional_risks": [],
    }

    # Vecteurs d'attaque spécifiques
    if card_type in ("EM4100", "HID Prox"):
        finding["attack_vectors"] = [
            "Lecture longue portée (jusqu'à 30cm) avec amplificateur RF",
            "Clonage en quelques secondes avec writer T5577",
            "Pas de mécanisme d'anti-replay",
        ]
    elif card_type in ("Mifare Classic 1K", "Mifare Classic 4K"):
        finding["attack_vectors"] = [
            "Attaque Darkside (récupération clé secteur 0 en ~1 min)",
            "Attaque Nested (récupération de toutes les clés une fois une clé connue)",
            "Clonage complet du badge avec le Flipper ou un téléphone NFC",
        ]
        if card_data.get("default_keys_detected"):
            finding["additional_risks"].append(
                "⚠️ CLÉS PAR DÉFAUT DÉTECTÉES (FFFFFFFFFFFF/000000000000) — "
                "Lecture complète du badge sans attaque préalable"
            )

    elif card_type == "Mifare Ultralight":
        finding["attack_vectors"] = [
            "Lecture du contenu sans authentification",
            "Modification des données (si OTP non configuré)",
            "Clonage avec téléphone Android NFC",
        ]

    # Risque clés par défaut
    if card_data.get("default_keys_detected") and "default" not in " ".join(finding["additional_risks"]).lower():
        finding["additional_risks"].append(
            "Clés MIFARE par défaut détectées — configuration initiale jamais sécurisée"
        )

    return finding


# ──────────────────────────────────────────────────────────────────────────────
# Scan d'un dossier
# ──────────────────────────────────────────────────────────────────────────────

def scan_directory(directory: str) -> list[dict]:
    """Parcourt un dossier et parse tous les fichiers .nfc et .rfid trouvés."""
    severity_matrix = load_severity_matrix()
    findings = []
    directory = Path(directory)

    nfc_files  = list(directory.rglob("*.nfc"))
    rfid_files = list(directory.rglob("*.rfid"))
    all_files  = nfc_files + rfid_files

    if not all_files:
        print(f"[INFO] Aucun fichier .nfc/.rfid trouvé dans {directory}")
        return []

    print(f"[INFO] {len(all_files)} fichier(s) RFID/NFC trouvé(s)")

    for filepath in all_files:
        filepath_str = str(filepath)
        if filepath.suffix == ".nfc":
            raw = parse_nfc_file(filepath_str)
        else:
            raw = parse_rfid_file(filepath_str)

        if raw:
            finding = analyze_card(raw, severity_matrix)
            findings.append(finding)
            _print_finding_summary(finding)

    return findings


def _print_finding_summary(f: dict):
    sev    = f.get("severity", "?")
    score  = f.get("score", 0)
    card   = f.get("card_type_normalized", "?")
    uid    = f.get("uid", "?")
    src    = f.get("source_file", "?")
    clone  = "✓ Clonable" if f.get("is_cloneable") else "✗ Non clonable"
    print(f"  [{sev:8s}] {score:4.1f} | {card:<25s} | UID: {uid:<20s} | {clone} | {src}")


# ──────────────────────────────────────────────────────────────────────────────
# Point d'entrée standalone
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage : python rfid_parser.py <dossier_ou_fichier>")
        sys.exit(1)

    target = sys.argv[1]
    if os.path.isdir(target):
        results = scan_directory(target)
    elif os.path.isfile(target):
        severity_matrix = load_severity_matrix()
        ext = Path(target).suffix
        raw = parse_nfc_file(target) if ext == ".nfc" else parse_rfid_file(target)
        if raw:
            results = [analyze_card(raw, severity_matrix)]
            _print_finding_summary(results[0])
        else:
            results = []
    else:
        print(f"[ERREUR] Chemin introuvable : {target}")
        sys.exit(1)

    print(f"\n[RÉSULTAT] {len(results)} finding(s) RFID/NFC analysé(s)")
