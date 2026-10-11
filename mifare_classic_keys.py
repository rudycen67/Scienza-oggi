#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mifare_classic_keys.py
======================================================================
Libreria per l'IMPORTAZIONE DI CHIAVI e la LETTURA/TRADUZIONE DI DUMP
di carte MIFARE Classic.

----------------------------------------------------------------------
COSA FA QUESTO PROGRAMMA
----------------------------------------------------------------------
Il programma non calcola e non indovina le chiavi: lavora con chiavi
GIÀ NOTE e con dump GIÀ ACQUISITI. In particolare:

  1) IMPORTA chiavi da file di diversi formati (JSON, JSON "statico" e
     formato binario grezzo), riconoscendo automaticamente il formato;
  2) LEGGE e TRADUCE un dump di carta (file binario .mfc/.mfd oppure
     file testuale in formato MIFARE Classic Tool), estraendo:
         - UID della carta (letto dal settore 0, blocco 0);
         - chiavi KeyA / KeyB (lette dall'ultimo blocco di ogni settore,
           il cosiddetto "sector trailer");
         - i dati di ogni blocco;
         - gli "access bits" (permessi di lettura/scrittura per blocco);
         - il MIFARE Application Directory (MAD), se presente.

----------------------------------------------------------------------
GUIDA ALLA LETTURA (anche per strumenti automatici / altre AI)
----------------------------------------------------------------------
Nei commenti, la dicitura "LEGGE QUI:" indica esattamente il punto in
cui viene estratta un'informazione (quale settore / blocco / byte) e di
che genere è. Serve a rendere immediato il flusso dei dati.

LAYOUT FISICO DI UNA CARTA MIFARE CLASSIC (indispensabile da capire):
  - La carta è divisa in SETTORI. Ogni settore è diviso in BLOCCHI.
  - Ogni BLOCCO è lungo 16 byte.
  - MIFARE Classic 1K  = 16 settori da 4 blocchi            (16 chiavi)
  - MIFARE Classic 4K  = primi 32 settori da 4 blocchi
                         + ultimi 8 settori da 16 blocchi   (40 chiavi)
  - L'ULTIMO blocco di ogni settore è il "sector trailer" e contiene:
        byte  0..5   -> Key A  (6 byte)
        byte  6..8   -> access bits (3 byte)
        byte  9      -> GPB (General Purpose Byte)
        byte 10..15  -> Key B  (6 byte)
  - Il blocco 0 del settore 0 è la "manufacturer data": contiene l'UID.
======================================================================
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ======================================================================
# COSTANTI DI BASE
# ======================================================================

CLASSIC_KEY_LEN = 6           # lunghezza in byte di una chiave MIFARE Classic
AES_KEY_LEN = 16              # lunghezza di una chiave AES (varianti estese)
BLOCK_LEN = 16               # ogni blocco è 16 byte
MIFARE_SECTOR_COUNT_MAX = 40 # una 4K ha al massimo 40 settori


# ----------------------------------------------------------------------
# CHIAVI "WELL-KNOWN" (note / standard, non segrete)
# Vengono provate sempre come ultimo tentativo di fallback.
#   ffffffffffff -> default di fabbrica MIFARE
#   000000000000 -> tutti zeri (default su alcune carte)
#   a0a1a2a3a4a5 -> chiave standard del MIFARE Application Directory (MAD)
#   d3f7d3f7d3f7 -> chiave standard per NDEF su MIFARE Classic
# ----------------------------------------------------------------------
WELL_KNOWN_KEYS = [
    ("ffffffffffff", "well-known-ff"),
    ("000000000000", "well-known-zero"),
    ("a0a1a2a3a4a5", "well-known-mad"),
    ("d3f7d3f7d3f7", "well-known-ndef"),
]


# ======================================================================
# 1) RICONOSCIMENTO DEL FORMATO DEL FILE DI CHIAVI
# ======================================================================

class KeyFormat(Enum):
    """Formato del file di chiavi riconosciuto."""
    UNKNOWN = "unknown"                    # non riconosciuto
    RAW_MFC = "raw_mfc"                    # formato binario grezzo
    JSON = "json"                          # JSON generico non classificato
    JSON_MFC = "json_mfc"                  # JSON per singola carta CON UID (TagId)
    JSON_MFC_NO_UID = "json_mfc_no_uid"    # JSON per singola carta SENZA UID
    JSON_MFC_STATIC = "json_mfc_static"    # JSON "statico" (stesse chiavi su più carte)


def _is_raw_mfc_length(length: int) -> bool:
    """
    Un file binario grezzo è una semplice concatenazione di chiavi da
    6 byte. Quindi la sua dimensione deve essere:
      - > 0
      - multiplo di 6
      - al massimo 40 settori * 6 byte * 2 (KeyA+KeyB) = 480 byte
    """
    return (
        length > 0
        and length % CLASSIC_KEY_LEN == 0
        and length <= MIFARE_SECTOR_COUNT_MAX * CLASSIC_KEY_LEN * 2
    )


def detect_key_format(data: bytes) -> KeyFormat:
    """
    Riconosce il formato di un file di chiavi.

    LEGGE QUI:
      - il PRIMO byte: se è '{' si presume JSON, altrimenti formato grezzo;
      - scorre dal fondo cercando la '}' finale per confermare il JSON;
      - se il JSON è valido, legge il campo "KeyType" per distinguere
        "MifareClassic" da "MifareClassicStatic", e il campo "TagId" per
        distinguere con/senza UID.
    """
    if len(data) == 0:
        return KeyFormat.UNKNOWN

    # PUNTO CHIAVE: primo carattere. Se non è '{' non è JSON.
    if data[0:1] != b"{":
        return KeyFormat.RAW_MFC if _is_raw_mfc_length(len(data)) else KeyFormat.UNKNOWN

    # Cerca la '}' di chiusura partendo dalla fine, saltando spazi/newline.
    found_close = False
    for i in range(len(data) - 1, -1, -1):
        c = data[i]
        if c <= 0:  # byte non valido in testo -> non è JSON
            return KeyFormat.RAW_MFC if _is_raw_mfc_length(len(data)) else KeyFormat.UNKNOWN
        if c in (ord("\n"), ord("\r"), ord("\t"), ord(" ")):
            continue
        if c == ord("}"):
            found_close = True
            break
        # un carattere diverso da '}' alla fine -> non JSON
        return KeyFormat.RAW_MFC if _is_raw_mfc_length(len(data)) else KeyFormat.UNKNOWN

    if not found_close:
        return KeyFormat.RAW_MFC if _is_raw_mfc_length(len(data)) else KeyFormat.UNKNOWN

    # Prova a fare il parse vero e proprio del JSON.
    try:
        obj = json.loads(data.decode("utf-8", errors="strict"))
    except Exception:
        return KeyFormat.RAW_MFC if _is_raw_mfc_length(len(data)) else KeyFormat.UNKNOWN

    # LEGGE QUI: il campo "KeyType" (genere di file di chiavi).
    key_type = obj.get("KeyType")
    if key_type == "MifareClassic":
        # LEGGE QUI: "TagId" -> se vuoto/assente è "senza UID".
        tag_id = obj.get("TagId")
        if not tag_id:
            return KeyFormat.JSON_MFC_NO_UID
        return KeyFormat.JSON_MFC
    if key_type == "MifareClassicStatic":
        return KeyFormat.JSON_MFC_STATIC

    return KeyFormat.JSON


# ======================================================================
# 2) MODELLO DI UNA SINGOLA CHIAVE DI SETTORE
# ======================================================================

class KeyType(Enum):
    """Tipo di chiave: KeyA, KeyB, sconosciuta o multipla."""
    UNKNOWN = "Unknown"
    A = "KeyA"
    B = "KeyB"
    MULTIPLE = "Multiple"

    def inverse(self) -> "KeyType":
        # inverte A<->B
        return KeyType.A if self == KeyType.B else KeyType.B

    def canon(self) -> "KeyType":
        # forma "canonica": B resta B, tutto il resto diventa A
        return KeyType.B if self == KeyType.B else KeyType.A


@dataclass
class ClassicSectorKey:
    """
    Una singola chiave applicabile a un settore.

    Campi:
      - key:    i 6 (o 16) byte della chiave;
      - type:   KeyA / KeyB / Unknown;
      - bundle: etichetta del "gruppo" di chiavi. Le chiavi dello stesso
                bundle vengono provate per prime se una del bundle ha già
                funzionato: così l'autenticazione risulta più veloce.
    """
    key: bytes
    type: KeyType = KeyType.UNKNOWN
    bundle: str = ""

    def __post_init__(self) -> None:
        # Validazione lunghezza.
        if len(self.key) not in (CLASSIC_KEY_LEN, AES_KEY_LEN):
            raise ValueError(
                f"La chiave deve essere di {CLASSIC_KEY_LEN} o {AES_KEY_LEN} "
                f"byte, trovati {len(self.key)}"
            )

    @property
    def key_hex(self) -> str:
        return self.key.hex()

    def to_json(self, sector: int) -> dict:
        """
        Serializza la chiave in oggetto JSON.
        SCRIVE QUI: i campi "type", "key", "sector", "bundle".
        """
        out: Dict[str, object] = {}
        if self.type == KeyType.A:
            out["type"] = "KeyA"
        elif self.type == KeyType.B:
            out["type"] = "KeyB"
        out["key"] = self.key_hex
        out["sector"] = sector
        if self.bundle:
            out["bundle"] = self.bundle
        return out

    @staticmethod
    def from_hex(hex_str: str, key_type: KeyType = KeyType.UNKNOWN,
                 bundle: str = "") -> "ClassicSectorKey":
        return ClassicSectorKey(bytes.fromhex(hex_str), key_type, bundle)


# ----------------------------------------------------------------------
# Funzione di diversificazione chiavi (KDF) basata sull'UID.
# Alcune carte non usano una chiave fissa: la chiave reale viene DERIVATA
# dall'UID della carta a partire da una chiave di base. Questa è una delle
# funzioni di derivazione più diffuse.
# ----------------------------------------------------------------------
def diversify_key_by_uid(base_key: bytes, tag_id: bytes,
                         key_type: KeyType = KeyType.UNKNOWN) -> ClassicSectorKey:
    """
    Deriva la chiave reale mettendo in XOR la chiave di base con un pattern
    costruito dai 4 byte dell'UID.

    LEGGE QUI: l'UID (tag_id) della carta per costruire il pattern.
    """
    if len(tag_id) < 4:
        raise ValueError("La diversificazione richiede un UID di almeno 4 byte")

    pattern = bytes([
        tag_id[1] ^ tag_id[2] ^ tag_id[3],
        tag_id[1],
        tag_id[2],
        (tag_id[0] + tag_id[1] + tag_id[2] + tag_id[3]) & 0xFF ^ tag_id[3],
        0,
        0,
    ])
    derived = bytes(a ^ b for a, b in zip(base_key, pattern))
    return ClassicSectorKey(derived, key_type, bundle="diversified")


# ======================================================================
# 3) IMPORT DELLE CHIAVI DAI VARI FORMATI DI FILE
# ======================================================================

@dataclass
class ClassicCardKeys:
    """
    Insieme di chiavi per UNA carta (o chiavi statiche valide per molte carte).

    - uid:   UID della carta (solo per il formato JSON con TagId), oppure
             None per i formati "senza UID" / "statico";
    - keys:  dizionario { numero_settore -> lista di ClassicSectorKey };
    - is_static: True se file di chiavi "statico";
    - description: etichetta leggibile (solo per i file statici).
    """
    uid: Optional[str]
    keys: Dict[int, List[ClassicSectorKey]]
    is_static: bool = False
    description: Optional[str] = None

    def is_empty(self) -> bool:
        return len(self.keys) == 0

    @property
    def key_type(self) -> Optional[KeyType]:
        """
        Tipo complessivo delle chiavi: None se vuoto, un singolo tipo se
        tutte uguali, MULTIPLE se misto.
        """
        distinct = {k.type for ks in self.keys.values() for k in ks}
        if not distinct:
            return None
        if len(distinct) == 1:
            return next(iter(distinct))
        return KeyType.MULTIPLE

    def get_candidates(self, sector: int, tag_id: bytes = b"") -> List[ClassicSectorKey]:
        """
        Restituisce le chiavi candidate per un settore, seguite dalle
        chiavi "well-known".
        """
        out = list(self.keys.get(sector, []))
        out += [ClassicSectorKey.from_hex(h, KeyType.A, b) for h, b in WELL_KNOWN_KEYS]
        return out


# ----- 3a) formato JSON per singola carta -----------------------------
def keys_from_json(obj: dict) -> ClassicCardKeys:
    """
    Legge un file JSON "MifareClassic" (con o senza TagId).

    LEGGE QUI:
      - "TagId"  -> UID (opzionale) a cui le chiavi sono associate;
      - "keys[]" -> ogni elemento ha "type" (KeyA/KeyB), "key" (6 byte in
                    esadecimale) e, opzionalmente, "sector".
        Se "sector" manca, l'indice nell'array È il numero di settore.
    """
    uid = obj.get("TagId") or None
    keys: Dict[int, List[ClassicSectorKey]] = {}

    for idx, entry in enumerate(obj.get("keys", [])):
        parsed = _classic_key_from_json_entry(entry)
        if parsed is None:
            continue
        # Se manca "sector", si usa la posizione nell'array (idx).
        sector = entry.get("sector", idx)
        keys.setdefault(sector, []).append(parsed)

    return ClassicCardKeys(uid=uid, keys=keys, is_static=False)


# ----- 3b) formato JSON "statico" -------------------------------------
def static_keys_from_json(obj: dict) -> ClassicCardKeys:
    """
    Legge un file JSON "MifareClassicStatic" (stesse chiavi per più carte).

    LEGGE QUI:
      - "Description" -> etichetta leggibile;
      - "keys[]"      -> qui "sector" è OBBLIGATORIO; ogni chiave può avere
                         anche "bundle" e "transform".
    """
    description = obj.get("Description")
    keys: Dict[int, List[ClassicSectorKey]] = {}

    for entry in obj.get("keys", []):
        parsed = _classic_key_from_json_entry(entry)
        if parsed is None:
            continue
        if "sector" not in entry:
            raise ValueError("File statico: manca il campo 'sector' in una chiave")
        keys.setdefault(entry["sector"], []).append(parsed)

    return ClassicCardKeys(uid=None, keys=keys, is_static=True, description=description)


def _classic_key_from_json_entry(entry: dict) -> Optional[ClassicSectorKey]:
    """
    Converte un singolo oggetto JSON in una ClassicSectorKey.

    LEGGE QUI:
      - "type"      -> "KeyA"/"KeyB"/assente (Unknown);
      - "transform" -> "none" (default) oppure una funzione di
                       diversificazione basata sull'UID;
      - "key"       -> i byte esadecimali (per "none" devono essere 6 byte);
      - "bundle"    -> gruppo di appartenenza (opzionale).
    """
    t = entry.get("type")
    if t == "KeyA":
        key_type = KeyType.A
    elif t == "KeyB":
        key_type = KeyType.B
    else:
        key_type = KeyType.UNKNOWN

    transform = entry.get("transform", "none")
    bundle = entry.get("bundle", "")

    if transform == "none":
        key_data = bytes.fromhex(entry["key"])
        # La chiave deve essere esattamente di 6 byte.
        if len(key_data) != CLASSIC_KEY_LEN:
            raise ValueError(
                f"Attesi {CLASSIC_KEY_LEN} byte nella chiave, trovati {len(key_data)}"
            )
        return ClassicSectorKey(key_data, key_type, bundle)

    if transform in ("diversified", "touchngo"):
        # Chiave "algoritmica": qui si conserva la chiave base; la chiave
        # reale va calcolata con diversify_key_by_uid(base, uid) al momento d'uso.
        base = bytes.fromhex(entry["key"])
        return ClassicSectorKey(base, key_type, bundle="diversified")

    # transform sconosciuto -> ignorato.
    return None


# ----- 3c) formato binario grezzo -------------------------------------
def keys_from_raw(data: bytes,
                  key_type: KeyType = KeyType.UNKNOWN) -> ClassicCardKeys:
    """
    Legge il formato binario grezzo.

    LEGGE QUI:
      - semplice concatenazione di chiavi da 6 byte, una per settore, in
        ordine di settore. Settore i -> byte [i*6 : i*6+6].
    """
    if len(data) % CLASSIC_KEY_LEN != 0:
        raise ValueError("Il file grezzo deve avere dimensione multipla di 6 byte")

    keys: Dict[int, List[ClassicSectorKey]] = {}
    num_sectors = len(data) // CLASSIC_KEY_LEN
    for i in range(num_sectors):
        start = i * CLASSIC_KEY_LEN
        chunk = data[start:start + CLASSIC_KEY_LEN]
        keys[i] = [ClassicSectorKey(chunk, key_type, bundle="from-dump")]

    return ClassicCardKeys(uid=None, keys=keys, is_static=False)


# ----- 3d) dispatcher: riconosce il formato e chiama il parser giusto -
def import_keys(data: bytes,
                raw_key_type: KeyType = KeyType.UNKNOWN) -> ClassicCardKeys:
    """
    Punto d'ingresso unico: rileva il formato e importa le chiavi.
    """
    fmt = detect_key_format(data)

    if fmt in (KeyFormat.JSON_MFC, KeyFormat.JSON_MFC_NO_UID):
        return keys_from_json(json.loads(data.decode("utf-8")))
    if fmt == KeyFormat.JSON_MFC_STATIC:
        return static_keys_from_json(json.loads(data.decode("utf-8")))
    if fmt == KeyFormat.RAW_MFC:
        return keys_from_raw(data, raw_key_type)
    if fmt == KeyFormat.JSON:
        # JSON generico: si prova comunque come file per singola carta.
        return keys_from_json(json.loads(data.decode("utf-8")))

    raise ValueError(f"Formato del file di chiavi non riconosciuto: {fmt}")


# ======================================================================
# 4) INTERPRETAZIONE DEGLI "ACCESS BITS"
#    Dicono, per ogni blocco, chi può leggere/scrivere/incrementare.
# ======================================================================

class ClassicAccessBits:
    """
    I 3 byte di access bits (byte 6,7,8 del sector trailer) codificano, in
    modo ridondante, i permessi di ogni blocco del settore.
    """

    def __init__(self, raw3: bytes):
        """
        LEGGE QUI: i 3 byte di access bits.
          C1 = nibble alto del byte 1
          C2 = nibble basso del byte 2
          C3 = nibble alto del byte 2
        """
        if len(raw3) != 3:
            raise ValueError("Gli access bits sono esattamente 3 byte")
        self.C1 = (raw3[1] & 0xF0) >> 4
        self.C2 = raw3[2] & 0x0F
        self.C3 = (raw3[2] & 0xF0) >> 4

    def _slot(self, slot: int) -> int:
        """Ricompone i 3 bit (C1 C2 C3) di un dato 'slot' (blocco)."""
        return (
            (((self.C1 >> slot) & 0x1) << 2)
            | (((self.C2 >> slot) & 0x1) << 1)
            | ((self.C3 >> slot) & 0x1)
        )

    @property
    def is_key_b_readable(self) -> bool:
        # KeyB è leggibile (quindi inutilizzabile come chiave) per certi slot.
        return self._slot(3) in (0, 1, 2)

    def slot_value(self, slot: int) -> int:
        """Valore (0..7) dei 3 bit di accesso dello slot indicato (pubblico)."""
        return self._slot(slot)

    def permessi_blocco_dati(self, slot: int) -> Optional[dict]:
        """
        Traduce i 3 bit di accesso di un BLOCCO DATI nei permessi concreti.
        Restituisce un dizionario con chiavi: read, write, increment, decrement.
        Ogni valore è una fra: "mai", "KeyA", "KeyB", "KeyA|KeyB".

        LOGICA: con KeyB leggibile, KeyB non può più essere usata come chiave,
        quindi i permessi "KeyA|KeyB" diventano solo "KeyA" e i "KeyB" "mai".
        """
        ab = "KeyA" if self.is_key_b_readable else "KeyA|KeyB"
        b = "mai" if self.is_key_b_readable else "KeyB"
        mai = "mai"
        tabella = {
            0: (ab, ab, ab, ab),
            1: (ab, mai, mai, ab),
            2: (ab, mai, mai, mai),
            3: (b, b, mai, mai),
            4: (ab, b, mai, mai),
            5: (b, mai, mai, mai),
            6: (ab, b, b, ab),
            7: (mai, mai, mai, mai),
        }
        v = tabella.get(self.slot_value(slot))
        if v is None:
            return None
        return {"read": v[0], "write": v[1], "increment": v[2], "decrement": v[3]}

    @staticmethod
    def is_valid(raw3: bytes) -> bool:
        """
        Verifica la ridondanza degli access bits: i bit invertiti
        memorizzati devono corrispondere.
        """
        if len(raw3) != 3:
            return False
        c123inv = (raw3[0] & 0xFF) | ((raw3[1] & 0x0F) << 8)
        c123 = ((raw3[1] & 0xF0) >> 4) | ((raw3[2] & 0xFF) << 4)
        return c123inv == (~c123 & 0xFFF)


# ======================================================================
# 5) MODELLO DELLA CARTA LETTA (blocchi/settori)
# ======================================================================

@dataclass
class ClassicSector:
    """Un settore letto: lista di blocchi + le chiavi usate."""
    index: int
    blocks: List[bytes]
    key_a: Optional[bytes] = None
    key_b: Optional[bytes] = None
    authorized: bool = True   # False se non si è riusciti ad autenticare

    @property
    def trailer(self) -> bytes:
        """L'ultimo blocco del settore (sector trailer)."""
        return self.blocks[-1]

    @property
    def access_bits(self) -> Optional[ClassicAccessBits]:
        """LEGGE QUI: byte 6..8 del trailer -> access bits."""
        if not self.authorized or not self.blocks:
            return None
        try:
            return ClassicAccessBits(self.trailer[6:9])
        except Exception:
            return None


@dataclass
class ClassicCard:
    """Una carta completa: UID + lista di settori."""
    uid: bytes
    sectors: List[ClassicSector] = field(default_factory=list)

    def sector(self, i: int) -> ClassicSector:
        return self.sectors[i]

    def block(self, sector_idx: int, block_idx: int) -> bytes:
        return self.sectors[sector_idx].blocks[block_idx]


# ----------------------------------------------------------------------
# Estrazione dell'UID dal blocco 0.
# Il blocco 0 del settore 0 contiene l'UID. Può essere a 4 o 7 byte.
# ----------------------------------------------------------------------
def block0_to_uid(block0: bytes) -> bytes:
    """
    LEGGE QUI: blocco 0 (manufacturer data).
      - se block0[0]==0x04 e i byte 8..9 valgono 0x0400/0x4400 -> UID a 7 byte;
      - altrimenti UID a 4 byte.
    """
    if block0[0] == 0x04 and int.from_bytes(block0[8:10], "big") in (0x0400, 0x4400):
        return block0[0:7]
    return block0[0:4]


# ======================================================================
# 6) IMPORT DEL DUMP BINARIO .mfc / .mfd
# ======================================================================

def read_mfc_dump(data: bytes) -> ClassicCard:
    """
    Legge un dump binario: sequenza continua di blocchi da 16 byte.
      - settori 0..31  -> 4 blocchi ciascuno
      - settori 32..39 -> 16 blocchi ciascuno (solo carte 4K)

    LEGGE QUI, per ogni settore:
      - blocco 0 del settore 0 -> UID (manufacturer data);
      - ultimo blocco (trailer) -> KeyA (byte 0..5) e KeyB (byte 10..15);
      - tutti i blocchi -> dati.
    """
    sectors: List[ClassicSector] = []
    uid: Optional[bytes] = None
    max_sector = 0
    offset = 0

    for sector_num in range(MIFARE_SECTOR_COUNT_MAX):
        # I settori dal 32 in su hanno 16 blocchi, gli altri 4.
        block_count = 16 if sector_num >= 32 else 4
        need = BLOCK_LEN * block_count

        sector_data = data[offset:offset + need]
        # Fine del file (dump più corto di una 4K completa).
        if len(sector_data) == 0 and sector_num != 0:
            break
        if len(sector_data) != need:
            raise ValueError(
                f"Lettura incompleta al settore {sector_num} "
                f"({len(sector_data)} byte)"
            )
        offset += need

        # LEGGE QUI: UID dal blocco 0 del settore 0.
        if sector_num == 0:
            uid = block0_to_uid(sector_data[0:16])

        # LEGGE QUI: il trailer (ultimo blocco) per estrarre le chiavi.
        lb = BLOCK_LEN * (block_count - 1)   # offset del trailer nel settore
        key_a = sector_data[lb + 0: lb + 6]
        key_b = sector_data[lb + 10: lb + 16]

        # Tutti i blocchi del settore.
        blocks = [sector_data[i * 16:(i * 16) + 16] for i in range(block_count)]

        sectors.append(ClassicSector(
            index=sector_num, blocks=blocks,
            key_a=key_a, key_b=key_b, authorized=True,
        ))
        max_sector = sector_num

    # Arrotonda alla dimensione standard della carta (1K/2K/4K).
    if max_sector <= 15:
        max_sector = 15   # 1K
    elif max_sector <= 31:
        max_sector = 31   # 2K
    else:
        max_sector = 39   # 4K

    # Settori mancanti -> non autorizzati.
    while len(sectors) <= max_sector:
        i = len(sectors)
        sectors.append(ClassicSector(index=i, blocks=[], authorized=False))

    if uid is None:
        raise ValueError("Impossibile determinare l'UID (settore 0 mancante)")

    return ClassicCard(uid=uid, sectors=sectors)


# ======================================================================
# 7) IMPORT DEL DUMP TESTUALE (formato MIFARE Classic Tool)
# ======================================================================

def read_mct_dump(text: str) -> ClassicCard:
    """
    Legge un dump in formato testuale a settori.

    Formato:
        +Sector: 0
        <blocco0 in esadecimale>
        <blocco1 ...>
        ...
        <trailer>            <- qui ci sono le chiavi
      I blocchi non letti sono rappresentati da 32 trattini "----...".

    LEGGE QUI, nel trailer di ogni settore:
      - KeyA = primi 12 caratteri esadecimali (6 byte);
      - KeyB = ultimi 12 caratteri esadecimali (6 byte);
      - se la riga inizia/finisce con '-', la rispettiva chiave è ignota.
    """
    sectors: List[ClassicSector] = []
    cur_sector = -1
    max_sector = -1
    cur_blocks: List[bytes] = []
    last_line: Optional[str] = None

    def flush():
        nonlocal cur_sector, cur_blocks, last_line
        if cur_sector < 0:
            return
        # Riempi eventuali settori saltati come non autorizzati.
        while len(sectors) < cur_sector:
            i = len(sectors)
            sectors.append(ClassicSector(index=i, blocks=[], authorized=False))

        # Estrai le chiavi dal trailer (last_line).
        key_a = None
        key_b = None
        if last_line and not last_line.startswith("-"):
            key_a = bytes.fromhex(last_line[0:12])
        if last_line and not last_line.endswith("-"):
            key_b = bytes.fromhex(last_line[20:32])

        authorized = not (key_a is None and key_b is None)
        sectors.append(ClassicSector(
            index=cur_sector, blocks=list(cur_blocks),
            key_a=key_a, key_b=key_b, authorized=authorized,
        ))

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("+Sector:"):
            flush()
            cur_blocks = []
            cur_sector = int(line[8:].strip())
            max_sector = max(max_sector, cur_sector)
        elif cur_sector >= 0:
            last_line = line
            if line == "-" * 32:
                cur_blocks.append(b"")              # blocco non letto
            else:
                # I trattini nelle chiavi sconosciute vengono messi a 0.
                cur_blocks.append(bytes.fromhex(line.replace("-", "0")))

    flush()

    # UID dal blocco 0 del settore 0, se disponibile.
    if sectors and sectors[0].authorized and sectors[0].blocks:
        uid = block0_to_uid(sectors[0].blocks[0])
    else:
        uid = b"fake"

    if max_sector <= 15:
        max_sector = 15
    elif max_sector <= 31:
        max_sector = 31
    else:
        max_sector = 39
    while len(sectors) <= max_sector:
        i = len(sectors)
        sectors.append(ClassicSector(index=i, blocks=[], authorized=False))

    return ClassicCard(uid=uid, sectors=sectors)


# ======================================================================
# 8) CRC8 NXP + MIFARE APPLICATION DIRECTORY (MAD)
#    Il MAD elenca quali "applicazioni" (AID) stanno in quali settori.
# ======================================================================

CRC8_NXP_POLY = 0x1D
CRC8_NXP_INITIAL = 0xC7


def _crc8_nxp_table() -> List[int]:
    """Costruisce la tabella per il CRC8 (polinomio 0x1D)."""
    ext_poly = CRC8_NXP_POLY | (1 << 8)
    mask = 1 << 7
    table = []
    for v in range(256):
        cur = v
        for _ in range(8):
            if cur & mask:
                cur = (cur << 1) ^ ext_poly
            else:
                cur <<= 1
            cur &= 0xFF
        table.append(cur)
    return table


_CRC8_TABLE = _crc8_nxp_table()


def crc8_nxp(*blocks: bytes) -> int:
    """
    Calcola il CRC8 su uno o più blocchi concatenati (valore iniziale 0xC7).
    """
    crc = CRC8_NXP_INITIAL
    for block in blocks:
        for b in block:
            crc = _CRC8_TABLE[(crc ^ b) & 0xFF]
    return crc


@dataclass
class MadEntry:
    """Una voce del MAD: in quale settore sta quale AID (applicazione)."""
    sector: int
    aid: int


def parse_mad(card: ClassicCard) -> Optional[List[MadEntry]]:
    """
    Legge il MIFARE Application Directory dal settore 0.

    LEGGE QUI:
      - settore 0, blocco 3 (trailer), byte 9 = GPB -> versione MAD;
      - settore 0, blocco 1 byte 0 = CRC memorizzato, byte 1 = info byte;
      - CRC calcolato su blocco1[1..15] + blocco2 e confrontato col CRC letto;
      - gli AID stanno a coppie di 2 byte nei blocchi 1 e 2 del settore 0.
    """
    sector0 = card.sector(0)
    if not sector0.authorized or len(sector0.blocks) < 4:
        return None

    try:
        # GPB nel trailer (blocco 3), byte 9.
        gpb = sector0.blocks[3][9]
        # DA (Directory Available) deve essere 1; i bit RFU devono essere 0.
        if (gpb & 0x80) == 0 or (gpb & 0x3C) != 0:
            return None
        mad_version = gpb & 0x3
        if mad_version not in (1, 2):
            return None

        # Verifica CRC del MAD.
        stored_crc = sector0.blocks[1][0]
        crc = crc8_nxp(sector0.blocks[1][1:16], sector0.blocks[2])
        if stored_crc != crc:
            return None

        # Estrazione degli AID (coppie di 2 byte).
        # blocco 1: coppie da indice 1..7 (la prima è CRC+info, si salta);
        # blocco 2: coppie da indice 0..7.
        entries: List[MadEntry] = []
        for i in range(1, 8):
            aid = int.from_bytes(sector0.blocks[1][i * 2:i * 2 + 2], "big")
            entries.append(MadEntry(sector=i, aid=aid))
        for i in range(0, 8):
            aid = int.from_bytes(sector0.blocks[2][i * 2:i * 2 + 2], "big")
            entries.append(MadEntry(sector=i + 8, aid=aid))
        return entries
    except (IndexError, ValueError):
        return None


# ======================================================================
# 9) UTILITY: HASH SALATO DELLE CHIAVI
#    Permette di riconoscere una carta confrontando un hash salato della
#    chiave con una lista nota, senza memorizzare la chiave in chiaro.
# ======================================================================

def check_key_hash(key: bytes, salt: str, *expected_hashes: str) -> int:
    """
    hash = lowercase(hex(md5(salt + key + salt)))
    Restituisce l'indice dell'hash corrispondente, oppure -1.
    """
    if not expected_hashes:
        return -1
    md5 = hashlib.md5()
    md5.update(salt.encode("ascii"))
    md5.update(key)
    md5.update(salt.encode("ascii"))
    digest = md5.hexdigest()
    try:
        return list(expected_hashes).index(digest)
    except ValueError:
        return -1


# ======================================================================
# 10) ESPORTAZIONE DELLE CHIAVI
#     Da una carta letta si possono riprodurre i vari formati di file chiavi.
# ======================================================================

def export_keys_raw(card: ClassicCard) -> bytes:
    """
    Esporta in formato binario grezzo: concatenazione di KeyA da 6 byte,
    un settore dopo l'altro.
    """
    out = bytearray()
    for sector in card.sectors:
        if sector.key_a:
            out += sector.key_a
        else:
            out += b"\x00" * CLASSIC_KEY_LEN
    return bytes(out)


def export_keys_json(card: ClassicCard, static: bool = False,
                     description: str = "") -> str:
    """
    Esporta in formato JSON (MifareClassic o MifareClassicStatic).
    SCRIVE QUI: una voce per ogni KeyA/KeyB disponibile, con "sector".
    """
    keys = []
    for sector in card.sectors:
        if sector.key_a:
            keys.append({"type": "KeyA", "key": sector.key_a.hex(),
                         "sector": sector.index})
        if sector.key_b:
            keys.append({"type": "KeyB", "key": sector.key_b.hex(),
                         "sector": sector.index})
    doc: Dict[str, object] = {
        "KeyType": "MifareClassicStatic" if static else "MifareClassic",
        "keys": keys,
    }
    if static:
        doc["Description"] = description
    else:
        doc["TagId"] = card.uid.hex()
    return json.dumps(doc, indent=2, sort_keys=True)


# ======================================================================
# 11) DIMOSTRAZIONE / CLI
# ======================================================================

def _demo() -> None:
    """
    Piccola demo che mostra il flusso completo SENZA bisogno di una carta
    fisica: costruisce un dump 1K finto, lo legge, estrae UID/chiavi e
    stampa un settore con i suoi access bits.
    """
    # Costruiamo un dump 1K (16 settori * 4 blocchi * 16 byte = 1024 byte).
    blocks = bytearray()
    # Settore 0, blocco 0: UID a 4 byte 0x01020304 + riempimento.
    block0 = bytes([0x01, 0x02, 0x03, 0x04]) + bytes(12)
    blocks += block0
    blocks += bytes(16)  # blocco 1
    blocks += bytes(16)  # blocco 2
    # Trailer settore 0: KeyA=FFFFFFFFFFFF, access bits di default, KeyB=FF...
    trailer = bytes.fromhex("ffffffffffff" + "ff078069" + "ffffffffffff")
    blocks += trailer
    # Altri 15 settori "vuoti" con trailer di default.
    for _ in range(15):
        blocks += bytes(48) + trailer

    card = read_mfc_dump(bytes(blocks))
    print("UID letto dal settore 0, blocco 0 :", card.uid.hex())
    s0 = card.sector(0)
    print("Settore 0 KeyA (dal trailer)      :", s0.key_a.hex())
    print("Settore 0 KeyB (dal trailer)      :", s0.key_b.hex())
    ab = s0.access_bits
    print("Access bits validi?               :",
          ClassicAccessBits.is_valid(s0.trailer[6:9]))
    print("KeyB leggibile (quindi inusabile)?:", ab.is_key_b_readable if ab else "n/d")

    # Esportiamo le chiavi nei vari formati.
    print("\n--- Esportazione chiavi in JSON (MifareClassic) ---")
    print(export_keys_json(card))
    print("\n--- Esportazione chiavi in formato grezzo (hex) ---")
    print(export_keys_raw(card).hex())

    # Import inverso: rileggiamo il JSON appena prodotto.
    reimported = import_keys(export_keys_json(card).encode("utf-8"))
    print("\nRe-import JSON -> UID:", reimported.uid,
          "| n. settori con chiavi:", len(reimported.keys))


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Importa chiavi MIFARE Classic e legge/traduce dump di carte."
    )
    sub = parser.add_subparsers(dest="cmd")

    p_detect = sub.add_parser("detect", help="Riconosci il formato di un file di chiavi")
    p_detect.add_argument("file")

    p_keys = sub.add_parser("keys", help="Importa e stampa le chiavi di un file")
    p_keys.add_argument("file")

    p_mfc = sub.add_parser("mfc", help="Leggi un dump binario .mfc/.mfd ed estrai le chiavi")
    p_mfc.add_argument("file")
    p_mfc.add_argument("--json", action="store_true", help="Esporta le chiavi in JSON")

    p_mct = sub.add_parser("mct", help="Leggi un dump testuale a settori")
    p_mct.add_argument("file")

    sub.add_parser("demo", help="Esegui la dimostrazione integrata")

    args = parser.parse_args(argv)

    if args.cmd == "detect":
        with open(args.file, "rb") as f:
            print(detect_key_format(f.read()).value)
    elif args.cmd == "keys":
        with open(args.file, "rb") as f:
            ck = import_keys(f.read())
        print(f"UID: {ck.uid}  static={ck.is_static}  "
              f"descrizione={ck.description!r}")
        for sec in sorted(ck.keys):
            for k in ck.keys[sec]:
                print(f"  settore {sec:>2}  {k.type.value:<8} {k.key_hex}  "
                      f"bundle={k.bundle!r}")
    elif args.cmd == "mfc":
        with open(args.file, "rb") as f:
            card = read_mfc_dump(f.read())
        print(f"UID: {card.uid.hex()}  settori: {len(card.sectors)}")
        if args.json:
            print(export_keys_json(card))
    elif args.cmd == "mct":
        with open(args.file, "r", encoding="utf-8") as f:
            card = read_mct_dump(f.read())
        print(f"UID: {card.uid.hex() if isinstance(card.uid, bytes) else card.uid}  "
              f"settori: {len(card.sectors)}")
    elif args.cmd == "demo":
        _demo()
    else:
        parser.print_help()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
