"""
subghz_parser.py — Parseur de fichiers Sub-GHz Flipper Zero
Formats supportés : .sub (key files et raw captures)
Détecte les protocoles à code fixe vs code tournant et évalue le risque de rejeu.
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

# Protocoles à code fixe (replay attack triviale)
FIXED_CODE_PROTOCOLS = {
    "Princeton", "Nice Flo 12bit", "Nice Flo 24bit", "Nice FLO",
    "CAME 12bit", "CAME 24bit", "CAME", "CAME ATOMO", "CAME TWEE",
    "Holtek", "Holtek_HT12E", "Clemsa", "Doitrand", "Dooya",
    "Intertechno", "Keeloq", "Linear", "Linear_Delta3",
    "Magellan", "Megacode", "Nero Radio", "Nero Sketch",
    "SecPlus v1", "GangQi", "Gate TX", "BETT", "Sogno",
    "SMC5326", "Starline", "Star Line", "Unilarm",
    "Power Smart", "RAW",
}

# Protocoles à code tournant (rolling code — plus sécurisé)
ROLLING_CODE_PROTOCOLS = {
    "KeeLoq", "HCS200", "HCS300", "HCS301", "AUT64",
    "BFT Mitto", "Faac SLH", "Faac SLH (Sea)",
    "SecPlus v2", "ALUTECH AT-4N", "Somfy Telis",
    "Nice Smilo", "Beninca", "ERREKA ROLL",
}

# Fréquences et leur usage typique
FREQUENCY_CONTEXTS = {
    315000000:  "USA/Japon — télécommandes, garage, alarmes",
    433920000:  "Europe — télécommandes, garage, alarmes, capteurs IoT",
    434420000:  "Europe — variante télécommandes",
    868350000:  "Europe — systèmes domotique, alarmes, LPWan",
    868950000:  "Europe — variante LPWan/domotique",
    915000000:  "USA — IoT, LoRa",
    925000000:  "Asie — IoT",
}

# Usages typiques par protocole
PROTOCOL_USAGES = {
    "Princeton":       "Télécommandes génériques, barrières, portails",
    "Nice Flo":        "Systèmes Nice (portails, volets, barrières)",
    "Nice FLO":        "Systèmes Nice (portails, volets, barrières)",
    "CAME":            "Systèmes CAME (portails, volets roulants)",
    "Holtek":          "Télécommandes bon marché, contrôle d'accès bas de gamme",
    "Keeloq":          "Télécommandes voiture, portails (implémentation variable)",
    "KeeLoq":          "Télécommandes voiture, portails (rolling code)",
    "SecPlus v1":      "Contrôleurs de garage Security+ (ancienne génération)",
    "SecPlus v2":      "Contrôleurs de garage Security+ (nouvelle génération)",
    "Starline":        "Alarmes voiture Starline",
    "Star Line":       "Alarmes voiture Starline",
    "Faac SLH":        "Motorisations FAAC (portails, barrières)",
    "BFT Mitto":       "Télécommandes BFT",
    "RAW":             "Signal brut — protocole non décodé",
}


# ──────────────────────────────────────────────────────────────────────────────
# Chargement matrice
# ──────────────────────────────────────────────────────────────────────────────

def load_severity_matrix() -> dict:
    with open(SEVERITY_MATRIX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["subghz"]


# ──────────────────────────────────────────────────────────────────────────────
# Parseur .sub
# ──────────────────────────────────────────────────────────────────────────────

def parse_sub_file(filepath: str) -> dict | None:
    """Parse un fichier .sub (Sub-GHz) du Flipper Zero."""
    result = {
        "source_file": os.path.basename(filepath),
        "source_path": filepath,
        "format": "sub",
        "timestamp": datetime.now().isoformat(),
        "raw_fields": {},
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
    except Exception as e:
        print(f"[ERREUR] Impossible de lire {filepath} : {e}")
        return None

    if not lines:
        return None

    # Déterminer si c'est un Key File ou un RAW File
    first_line = lines[0].strip()
    is_raw = "RAW" in first_line

    raw = {}
    raw_data_lines = []
    in_raw_data = False

    for line in lines:
        line = line.strip()
        if line.startswith("RAW_Data:"):
            in_raw_data = True
            raw_data_lines.append(line.replace("RAW_Data:", "").strip())
            continue
        if in_raw_data and re.match(r"^[-\d\s]+$", line):
            raw_data_lines.append(line)
            continue
        else:
            in_raw_data = False

        if ":" in line and not in_raw_data:
            key, _, value = line.partition(":")
            raw[key.strip()] = value.strip()

    result["raw_fields"] = raw
    result["is_raw_capture"] = is_raw

    # Fréquence
    freq_str = raw.get("Frequency", "0")
    try:
        frequency = int(freq_str)
    except ValueError:
        frequency = 0
    result["frequency_hz"]  = frequency
    result["frequency_mhz"] = round(frequency / 1_000_000, 3)
    result["frequency_context"] = FREQUENCY_CONTEXTS.get(
        frequency,
        f"Fréquence non standard ({frequency / 1_000_000:.3f} MHz)"
    )

    # Preset (modulation)
    preset = raw.get("Preset", "Unknown")
    result["preset"] = preset
    result["modulation"] = _decode_preset(preset)

    # Protocole
    protocol = raw.get("Protocol", "RAW" if is_raw else "Unknown")
    result["protocol"] = protocol
    result["protocol_usage"] = PROTOCOL_USAGES.get(protocol, "Usage non référencé")

    # Code / clé
    result["key"]  = raw.get("Key", None)
    result["bits"] = raw.get("Bit", raw.get("Bits", None))

    # Données RAW
    if raw_data_lines:
        all_samples = []
        for line in raw_data_lines:
            samples = [int(x) for x in line.split() if x.lstrip("-").isdigit()]
            all_samples.extend(samples)
        result["raw_samples_count"]    = len(all_samples)
        result["raw_duration_ms"]      = _estimate_duration_ms(all_samples)
        result["raw_positive_pulses"]  = sum(1 for s in all_samples if s > 0)
        result["raw_negative_pulses"]  = sum(1 for s in all_samples if s < 0)
    else:
        result["raw_samples_count"]   = 0
        result["raw_duration_ms"]     = 0
        result["raw_positive_pulses"] = 0
        result["raw_negative_pulses"] = 0

    # Répétitions enregistrées (si présentes dans le nom du fichier)
    result["capture_note"] = _extract_capture_note(os.path.basename(filepath))

    return result


def _decode_preset(preset: str) -> str:
    presets = {
        "FuriHalSubGhzPresetOok270Async": "OOK 270 baud/s (ASK)",
        "FuriHalSubGhzPresetOok650Async": "OOK 650 baud/s (ASK) — le plus courant",
        "FuriHalSubGhzPreset2FSKDev238Async": "2-FSK 238 Hz déviation",
        "FuriHalSubGhzPreset2FSKDev476Async": "2-FSK 476 Hz déviation",
        "FuriHalSubGhzPresetMSK99_97KbAsync": "MSK 99.97 Kbaud/s",
        "FuriHalSubGhzPresetGFSK9_99KbAsync": "GFSK 9.99 Kbaud/s",
    }
    for key, val in presets.items():
        if key in preset:
            return val
    return preset


def _estimate_duration_ms(samples: list) -> float:
    """Estime la durée totale du signal en ms (unités en µs)."""
    total_us = sum(abs(s) for s in samples)
    return round(total_us / 1000, 2)


def _extract_capture_note(filename: str) -> str:
    """Extrait une note contextuelle depuis le nom du fichier."""
    name = filename.replace(".sub", "")
    # Normalise les underscores/tirets en espaces pour lisibilité
    return name.replace("_", " ").replace("-", " ").strip()


# ──────────────────────────────────────────────────────────────────────────────
# Analyse
# ──────────────────────────────────────────────────────────────────────────────

def analyze_signal(signal_data: dict, severity_matrix: dict) -> dict:
    """Enrichit les données signal avec l'analyse de criticité."""

    protocol = signal_data.get("protocol", "Unknown")
    is_raw   = signal_data.get("is_raw_capture", False)

    # Détermination du type de protocole
    if protocol in ROLLING_CODE_PROTOCOLS:
        proto_type = "rolling_code"
    elif protocol in FIXED_CODE_PROTOCOLS or is_raw:
        proto_type = "fixed_code" if not is_raw else "raw_capture"
    else:
        proto_type = "unknown_protocol"

    severity_info = severity_matrix.get(proto_type, severity_matrix["unknown_protocol"])

    finding = {
        **signal_data,
        "protocol_type":    proto_type,
        "is_replay_vulnerable": proto_type in ("fixed_code", "raw_capture"),
        "severity":         severity_info["severity"],
        "score":            severity_info["score"],
        "vuln_description": severity_info["description"],
        "recommendation":   severity_info["recommendation"],
        "cve_ref":          severity_info.get("cve_ref"),
        "color":            severity_info.get("color", "orange"),
        "attack_vectors":   [],
        "additional_risks": [],
    }

    # Vecteurs d'attaque
    if proto_type == "fixed_code":
        finding["attack_vectors"] = [
            f"Capture du signal à distance (portée Flipper : jusqu'à ~50m en champ libre)",
            f"Relecture immédiate avec le Flipper — aucun outil supplémentaire requis",
            f"Signal identique à 100% — indétectable par les systèmes de contrôle d'accès standards",
            f"Attaque possible autant de fois que voulu (pas d'expiration du code)",
        ]
    elif proto_type == "raw_capture":
        finding["attack_vectors"] = [
            "Signal brut capturé et rejoué avec succès",
            "Protocole non encore décodé — analyse SDR recommandée pour qualification complète",
            "Rejoué tel quel — efficacité confirmée par le test terrain",
        ]
    elif proto_type == "rolling_code":
        finding["attack_vectors"] = [
            "Résistant au simple rejeu (code change à chaque appui)",
            "Vulnérable aux attaques de désynchronisation avancées (hors scope Flipper standard)",
            "Risque résiduel : RollJam si implémentation non conforme (ex: anciens KeeLoq)",
        ]
        finding["additional_risks"].append(
            "Vérifier la version du firmware de la télécommande — "
            "certaines implémentations KeeLoq sont vulnérables à RollJam (Samy Kamkar, 2015)"
        )

    # Risque fréquence non standard
    if signal_data.get("frequency_hz", 0) not in FREQUENCY_CONTEXTS:
        finding["additional_risks"].append(
            f"Fréquence non standard ({signal_data.get('frequency_mhz')} MHz) — "
            "pourrait être un système propriétaire à sécurité renforcée ou au contraire non audité"
        )

    return finding


# ──────────────────────────────────────────────────────────────────────────────
# Scan dossier
# ──────────────────────────────────────────────────────────────────────────────

def scan_directory(directory: str) -> list[dict]:
    """Parcourt un dossier et analyse tous les fichiers .sub trouvés."""
    severity_matrix = load_severity_matrix()
    findings = []
    directory = Path(directory)

    sub_files = list(directory.rglob("*.sub"))

    if not sub_files:
        print(f"[INFO] Aucun fichier .sub trouvé dans {directory}")
        return []

    print(f"[INFO] {len(sub_files)} fichier(s) Sub-GHz trouvé(s)")

    for filepath in sub_files:
        raw = parse_sub_file(str(filepath))
        if raw:
            finding = analyze_signal(raw, severity_matrix)
            findings.append(finding)
            _print_finding_summary(finding)

    return findings


def _print_finding_summary(f: dict):
    sev      = f.get("severity", "?")
    score    = f.get("score", 0)
    protocol = f.get("protocol", "?")
    freq     = f.get("frequency_mhz", 0)
    replay   = "⚠ REJOUABLE" if f.get("is_replay_vulnerable") else "✓ Rolling code"
    src      = f.get("source_file", "?")
    print(f"  [{sev:8s}] {score:4.1f} | {protocol:<20s} | {freq:7.3f} MHz | {replay} | {src}")


# ──────────────────────────────────────────────────────────────────────────────
# Point d'entrée standalone
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage : python subghz_parser.py <dossier_ou_fichier.sub>")
        sys.exit(1)

    target = sys.argv[1]
    severity_matrix = load_severity_matrix()

    if os.path.isdir(target):
        results = scan_directory(target)
    elif os.path.isfile(target):
        raw = parse_sub_file(target)
        if raw:
            results = [analyze_signal(raw, severity_matrix)]
            _print_finding_summary(results[0])
        else:
            results = []
    else:
        print(f"[ERREUR] Chemin introuvable : {target}")
        sys.exit(1)

    print(f"\n[RÉSULTAT] {len(results)} signal(aux) Sub-GHz analysé(s)")
