# 🔐 Flipper Zero Audit Kit

Kit d'audit de sécurité physique basé sur le Flipper Zero.
Parse les exports de la carte SD et génère un rapport PDF professionnel.

---

## Structure du projet

```
flipper_audit/
├── main.py                          # Point d'entrée CLI principal
├── requirements.txt
├── findings/
│   └── severity_matrix.json         # Base de données des criticités
├── parsers/
│   ├── rfid_parser.py               # .nfc / .rfid (badges 125kHz et 13.56MHz)
│   ├── subghz_parser.py             # .sub (signaux Sub-GHz 433/868 MHz)
│   ├── wifi_parser.py               # Logs WiFi (module ESP32 Marauder)
│   └── badusb_parser.py             # Logs de résultats Bad USB
├── report/
│   └── generate_report.py           # Générateur PDF ReportLab
├── payloads/
│   ├── badusb_demo_windows.txt      # Payload de démonstration Windows
│   └── badusb_demo_linux.txt        # Payload de démonstration Linux
└── samples/                         # Fichiers d'exemple pour tests
    ├── badge_salle_serveur.nfc
    ├── badge_parking.rfid
    ├── portail_parking.sub
    ├── wifi_scan_bureau.txt
    └── badusb_rh_poste3.txt
```

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Utilisation

### Mode démonstration (sans fichiers Flipper)
```bash
python main.py --demo --client "Acme SA"
```

### Analyse d'une carte SD réelle
```bash
python main.py --input /media/flipper/SD_CARD --client "Acme SA"
```

### Toutes les options
```bash
python main.py \
  --input ./sd_card \
  --client "Acme SA" \
  --auditor "Jean Dupont" \
  --ref "AUDIT-2026-001" \
  --output ./rapports/audit_acme.pdf \
  --json \
  --verbose
```

### Tester sur les fichiers d'exemple
```bash
python main.py --input ./samples --client "Client Test" --demo-samples
```

---

## Organisation de la carte SD Flipper

Pour que les parseurs trouvent automatiquement les fichiers, respectez
cette structure sur la carte SD :

```
SD_CARD/
├── NFC/                   → Fichiers .nfc lus par rfid_parser
├── RFID/                  → Fichiers .rfid lus par rfid_parser
├── subghz/
│   ├── saved/             → Fichiers .sub (key files)
│   └── capture/           → Fichiers .sub (raw captures)
└── badusb/
    └── results/           → Logs .txt générés par vos payloads
```

Les fichiers WiFi (logs Marauder) peuvent être dans n'importe quel
sous-dossier — le parseur les détecte par nom de fichier.

---

## Formats de fichiers supportés

| Format   | Extension | Description                                |
|----------|-----------|--------------------------------------------|
| NFC      | `.nfc`    | Badges 13.56 MHz (MIFARE, DESFire, iClass) |
| RFID     | `.rfid`   | Badges 125 kHz (EM4100, HID Prox, Indala)  |
| Sub-GHz  | `.sub`    | Signaux RF (télécommandes, alarmes)         |
| WiFi TXT | `.txt`    | Logs Marauder ou format libre              |
| WiFi CSV | `.csv`    | Export airodump-ng ou Marauder             |
| WiFi JSON| `.json`   | Export JSON Marauder                       |
| Bad USB  | `.txt`    | Logs de résultats (préfixe `badusb_*`)     |

---

## Criticités et scoring

| Niveau   | Score | Exemples                                        |
|----------|-------|-------------------------------------------------|
| CRITIQUE | 8-10  | Badge EM4100 clonable, réseau ouvert, WEP       |
| ÉLEVÉ    | 6-7.9 | WPA-TKIP, Mifare Ultralight, signal RAW rejoué  |
| MOYEN    | 4-5.9 | WPA2-PSK, PMF absent, protocole rolling code    |
| FAIBLE   | 1-3.9 | DESFire EV2, WPA2-Enterprise, protocole sécurisé|

---

## Intégration workflow terrain

```
Terrain                    Bureau
───────                    ──────
1. Scanner badges    →   2. Copier SD card
3. Capturer signaux  →   4. python main.py --input ./sd_card
5. Tester WiFi       →   6. Rapport PDF auto-généré
```

---

## Avertissement légal

Ce kit est destiné exclusivement à des missions d'audit de sécurité
réalisées avec une autorisation écrite explicite du propriétaire des
systèmes testés. Toute utilisation non autorisée est illégale et engage
la responsabilité pénale de son auteur.
