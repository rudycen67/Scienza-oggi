#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mifare_milano.py
======================================================================
Decoder specifico per la carta dei trasporti di MILANO ("RicaricaMi",
circuito ATM / Trenord).

A differenza del motore generale (che mostra i byte grezzi), questo
modulo interpreta quei byte secondo il formato proprietario della carta
e li traduce in informazioni leggibili:
  - tipo di carta (riconoscimento automatico);
  - date di nascita / validità contenute nell'intestazione;
  - VIAGGI (data, ora, mezzo, linea, luogo, timbratura ingresso/uscita);
  - ABBONAMENTI / TITOLI (tipo, validità, corse o giorni rimanenti).

I dati di viaggio sono codificati come CAMPI DI BIT concatenati (schema
in stile EN1545): si legge un campo alla volta, bit dopo bit, usando una
mappa di lunghezze. Le date usano come "giorno zero" il 1° gennaio 1997.

NOTA: alcuni campi del formato restano non documentati pubblicamente;
quelli noti vengono tradotti, gli altri sono ignorati senza bloccare la
lettura.
======================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Dict, List, Optional

import mifare_classic_keys as mfc


# ======================================================================
# 1) LETTURA A LIVELLO DI BIT
# ======================================================================

def get_bits(buffer: bytes, start_bit: int, length: int) -> int:
    """
    Estrae `length` bit dal buffer a partire da `start_bit`, in ordine
    big-endian (il bit più significativo per primo).

    È il mattone fondamentale: tutti i campi della carta vengono letti
    con questa funzione, spostandosi di tanti bit quanti ne occupa ogni
    campo.
    """
    if length <= 0:
        return 0
    end_bit = start_bit + length - 1
    s_byte = start_bit // 8
    s_bit = start_bit % 8
    e_byte = end_bit // 8
    e_bit = end_bit % 8

    if s_byte == e_byte:
        return (buffer[e_byte] >> (7 - e_bit)) & (0xFF >> (8 - length))

    ret = (buffer[s_byte] & (0xFF >> s_bit)) << (((e_byte - s_byte - 1) * 8) + (e_bit + 1))
    for i in range(s_byte + 1, e_byte):
        ret |= (buffer[i] & 0xFF) << (((e_byte - i - 1) * 8) + (e_bit + 1))
    ret |= (buffer[e_byte] & 0xFF) >> (7 - e_bit)
    return ret


def int_reversed(b: bytes, off: int, length: int) -> int:
    """Legge `length` byte come intero little-endian (byte invertiti)."""
    val = 0
    for i in range(length):
        val |= b[off + i] << (8 * i)
    return val


# ======================================================================
# 2) FRAMEWORK A CAMPI (concatenazione / bitmap / ripetizioni)
# Ogni "campo" sa leggersi dai bit e scrivere il proprio valore in un
# dizionario `holder`, poi restituisce l'offset del bit successivo.
# ======================================================================

class _Holder:
    """Contenitore dei valori letti: nome-completo -> valore."""
    def __init__(self):
        self.map: Dict[str, object] = {}

    def put_int(self, name: str, path: str, value: int):
        self.map[_full(name, path)] = value

    def put_str(self, name: str, path: str, value: str):
        self.map[_full(name, path)] = value

    def get_int(self, name: str, path: str = "") -> Optional[int]:
        v = self.map.get(_full(name, path))
        return v if isinstance(v, int) else None

    def get_int0(self, name: str, path: str = "") -> int:
        return self.get_int(name, path) or 0

    def contains(self, name: str, path: str = "") -> bool:
        return _full(name, path) in self.map


def _full(name: str, path: str) -> str:
    return name if not path else f"{path}/{name}"


class FixedInteger:
    """Un intero di lunghezza fissa in bit."""
    def __init__(self, name: str, length: int):
        self.name = name
        self.length = length

    def parse(self, b: bytes, off: int, path: str, holder: _Holder) -> int:
        if self.length > 0:
            try:
                holder.put_int(self.name, path, get_bits(b, off, self.length))
            except Exception:
                pass  # campo oltre i dati disponibili: si ignora
        return off + self.length


class FixedHex:
    """Una sequenza di bit conservata come stringa esadecimale."""
    def __init__(self, name: str, length: int):
        self.name = name
        self.length = length

    def parse(self, b: bytes, off: int, path: str, holder: _Holder) -> int:
        try:
            res = ""
            i = self.length
            while i > 0:
                if i >= 8:
                    t = format(get_bits(b, off + i - 8, 8), "x").rjust(2, "0")
                    res = t + res
                    i -= 8
                elif i >= 4:
                    res = format(get_bits(b, off + i - 4, 4), "x") + res
                    i -= 4
                else:
                    res = format(get_bits(b, off, i), "x") + res
                    break
            holder.put_str(self.name, path, res)
        except Exception:
            pass
        return off + self.length


class Container:
    """Concatenazione di più campi, senza dati aggiuntivi."""
    def __init__(self, *fields):
        self.fields = fields

    def parse(self, b: bytes, off: int, path: str, holder: _Holder) -> int:
        for el in self.fields:
            off = el.parse(b, off, path, holder)
        return off


class Repeat:
    """Un contatore di `ctr_len` bit, seguito da altrettante ripetizioni."""
    def __init__(self, ctr_len: int, fld):
        self.ctr_len = ctr_len
        self.field = fld

    def parse(self, b: bytes, off: int, path: str, holder: _Holder) -> int:
        try:
            ctr = get_bits(b, off, self.ctr_len)
        except Exception:
            return off + self.ctr_len
        off += self.ctr_len
        for i in range(ctr):
            off = self.field.parse(b, off, f"{path}/{i}", holder)
        return off


class Bitmap:
    """
    Una maschera di N bit (uno per ogni campo): dove il bit è 1, subito
    dopo compare il campo corrispondente. Permette di omettere i campi
    assenti risparmiando spazio.
    """
    def __init__(self, *fields, reversed: bool = False):
        self.fields = fields
        self.reversed = reversed

    def parse(self, b: bytes, off: int, path: str, holder: _Holder) -> int:
        n = len(self.fields)
        try:
            bitmask = get_bits(b, off, n)
        except Exception:
            return off + n
        off += n
        curbit = (1 << (n - 1)) if self.reversed else 1
        for el in self.fields:
            if bitmask & curbit:
                off = el.parse(b, off, path, holder)
            curbit = (curbit >> 1) if self.reversed else (curbit << 1)
        return off


# --- scorciatoie per campi data/ora (stessi nomi/lunghezze del formato) -
def _date(name: str) -> FixedInteger:      # 14 bit: giorni dal 1997-01-01
    return FixedInteger(name + "Date", 14)

def _time_local(name: str) -> FixedInteger:  # 11 bit: minuti dalla mezzanotte
    return FixedInteger(name + "TimeLocal", 11)

def _date_bcd(name: str) -> FixedInteger:   # 32 bit: data in formato BCD
    return FixedInteger(name + "DateBCD", 32)


def _parse(b: bytes, fields) -> _Holder:
    h = _Holder()
    fields.parse(b, 0, "", h)
    return h


# ======================================================================
# 3) DECODIFICA DELLE DATE (epoca: 1° gennaio 1997)
# ======================================================================

_EPOCH = date(1997, 1, 1)


def giorni_a_data(d: int) -> Optional[date]:
    """Converte il numero di giorni dal 1997-01-01 in una data vera."""
    if d == 0:
        return None
    return _EPOCH + timedelta(days=d)


def minuti_a_ora(m: int) -> str:
    """Converte i minuti dalla mezzanotte in 'HH:MM'."""
    return f"{m // 60:02d}:{m % 60:02d}"


def data_bcd(valore: int) -> Optional[date]:
    """Converte una data in formato BCD (anno<<16 | mese<<8 | giorno)."""
    if valore <= 0:
        return None

    def bcd(x: int) -> int:
        # Converte un valore BCD di lunghezza arbitraria: ogni nibble (4 bit)
        # è una cifra decimale. Es. 0x2024 -> 2024, 0x12 -> 12.
        risultato = 0
        moltiplicatore = 1
        while x > 0:
            risultato += (x & 0x0F) * moltiplicatore
            x >>= 4
            moltiplicatore *= 10
        return risultato

    try:
        # anno = 2 byte BCD, mese e giorno = 1 byte BCD ciascuno.
        return date(bcd(valore >> 16), bcd((valore >> 8) & 0xFF), bcd(valore & 0xFF))
    except ValueError:
        return None


# ======================================================================
# 4) DEFINIZIONE DEI CAMPI DELLA CARTA RICARICAMI
# ======================================================================

# Identificativo che marca la carta come RicaricaMi (ripetuto nel settore 0).
RICARICA_MI_ID = 0x0221

# --- costanti di trasporto e tariffe (dal formato della carta) --------
TRANSPORT_METRO = 1
TRANSPORT_BUS = 2
TRANSPORT_TRAM = 4
TRANSPORT_TRENORD1 = 7
TRANSPORT_TRENORD2 = 9

NOMI_MEZZO = {
    TRANSPORT_METRO: "Metropolitana",
    TRANSPORT_BUS: "Autobus",
    TRANSPORT_TRAM: "Tram",
    TRANSPORT_TRENORD1: "Treno (Trenord 1)",
    TRANSPORT_TRENORD2: "Treno (Trenord 2)",
}

# Linee metro note (numero interno -> nome commerciale).
LINEE_METRO = {101: "M1", 104: "M2", 107: "M5", 301: "M3"}

TARIFFE = {
    0xFFF:  "Biglietto urbano singolo",
    0x100D: "Giornaliero urbano",
    0x1B39: "Urbano 2x6",
    45:     "Abbonamento annuale urbano",
    46:     "Abbonamento mensile urbano",
    7095:   "M1-M3 ordinario singolo",
}
TARIFF_URBAN_2X6 = 0x1B39
TARIFF_SINGLE_URBAN = 0xFFF
TARIFF_DAILY_URBAN = 0x100D

TRANSACTION_TAP_ON = 1
TRANSACTION_TAP_ON_TRANSFER = 2
TRANSACTION_TAP_OFF = 3

# --- struttura di un VIAGGIO (evento di timbratura) -------------------
# I nomi "NeverSeenN" sono segnaposto (lunghezza 0) previsti dalla bitmap.
def _ns(n):  # segnaposto a lunghezza zero
    return FixedInteger(f"NeverSeen{n}", 0)


TRIP_FIELDS = Container(
    _date("EventFirstStamp"),
    _time_local("Event"),
    FixedInteger("EventUnknownA", 2),
    Bitmap(
        _ns(0), _ns(1), _ns(2), FixedInteger("TransactionType", 3),
        _ns(4), FixedInteger("EventResult", 6), _ns(6), _ns(7),
        FixedInteger("EventLocationId", 11), _ns(9), _ns(10), _ns(11),
        FixedInteger("EventUnknownC", 2), _ns(13),
        FixedInteger("EventRouteNumber", 10), FixedInteger("EventUnknownD", 12),
        FixedInteger("TransportTypeA", 1), FixedInteger("EventVehicleId", 13),
        _ns(18), FixedInteger("TransportTypeB", 4),
        _ns(20), FixedInteger("EventUnknownE1", 5),
        FixedInteger("EventUnknownE2", 16), _ns(23),
        _ns(24), _ns(25), _ns(26), FixedInteger("EventContractPointer", 4),
        Bitmap(
            FixedInteger("NeverSeenExtra0", 0), FixedInteger("NeverSeenExtra1", 0),
            FixedInteger("NeverSeenExtra2", 0), FixedInteger("NeverSeenExtra3", 0),
            FixedInteger("NeverSeenExtra4", 0), FixedInteger("NeverSeenExtra5", 0),
            _time_local("EventFirstStamp"), FixedInteger("EventUnknownG", 1),
            FixedInteger("EventFirstLocationId", 11),
            FixedInteger("EventUnknownH1", 1), FixedInteger("EventUnknownH2", 2),
            FixedInteger("TransactionCounter", 4),
            FixedInteger("NeverSeenExtra12", 0),
            Container(FixedInteger("TrainUsed", 1), FixedInteger("TramUsed", 1)),
            FixedInteger("NeverSeenExtra14", 0), FixedInteger("EventUnknownI", 1),
        ),
    ),
)

# --- struttura di un ABBONAMENTO: parte dinamica + parte statica ------
DYN_FIELDS = Container(
    FixedInteger("ContractValidationsInDay", 6),
    _date("ContractLastUse"),
    FixedInteger("ContractUnknownA", 10),
    FixedInteger("ContractTariffB", 16),
    _date("ContractStart"),
    _date("ContractEnd"),
    FixedInteger("ContractUnknownB", 12),
    FixedHex("ContractUnknownC", 40),
)

STAT_FIELDS = Bitmap(
    FixedInteger("ContractTariff", 16),
    FixedInteger("NeverSeen1", 0), FixedInteger("NeverSeen2", 0),
    FixedInteger("NeverSeen3", 0),
    FixedInteger("ContractUnknownD", 16),
    FixedInteger("ContractSerialNumber", 32),
    FixedInteger("NeverSeen6", 0), FixedInteger("NeverSeen7", 0),
    FixedInteger("ContractUnknownE", 2),
    FixedInteger("ContractUnknownF1", 9), FixedInteger("ContractUnknownF2", 8),
    FixedInteger("ContractUnknownF3", 7), FixedInteger("ContractUnknownF4", 8),
)

# --- intestazione (settore 1): dati del titolare / validità ----------
BLOCK_1_0_FIELDS = Container(
    FixedInteger("EnvUnknownA", 9),
    _date_bcd("HolderBirthDate"),
    FixedHex("EnvUnknownB", 47),
    _date("EnvApplicationValidityEnd"),
    FixedInteger("EnvUnknownC", 26),
)
BLOCK_1_1_FIELDS = Container(
    FixedHex("EnvUnknownD", 64),
    _date("EnvApplicationIssue"),
    FixedHex("EnvUnknownE", 49),
)


# ======================================================================
# 5) RICONOSCIMENTO E DECODIFICA
# ======================================================================

def riconosce(card: mfc.ClassicCard) -> bool:
    """
    Verifica se la carta è una RicaricaMi.

    LEGGE QUI: nei blocchi 1 e 2 del settore 0 devono comparire, a coppie
    di 2 byte, ripetizioni dell'identificativo 0x0221.
    """
    try:
        s0 = card.sector(0)
        if not s0.authorized or len(s0.blocks) < 3:
            return False
        for i in (1, 2):
            block = s0.blocks[i]
            inizio = 1 if i == 1 else 0
            for j in range(inizio, 8):
                if int.from_bytes(block[j * 2:j * 2 + 2], "big") != RICARICA_MI_ID:
                    return False
        return True
    except (IndexError, ValueError):
        return False


@dataclass
class Viaggio:
    data: Optional[date]
    ora: str
    mezzo: str
    linea: Optional[str]
    luogo: Optional[int]
    tipo: str  # "ingresso", "uscita", ...
    raw: _Holder = field(default=None, repr=False)


@dataclass
class Abbonamento:
    tariffa: str
    validita_da: Optional[date]
    validita_a: Optional[date]
    rimanenti: Optional[str]


def _blocco(card: mfc.ClassicCard, sec: int, blk: int) -> bytes:
    """Legge un blocco, restituendo 16 zeri se il settore non è leggibile."""
    try:
        s = card.sector(sec)
        if not s.authorized or blk >= len(s.blocks) or not s.blocks[blk]:
            return bytes(16)
        return s.blocks[blk]
    except IndexError:
        return bytes(16)


def _mezzo_e_modo(h: _Holder):
    """Determina il mezzo di trasporto a partire dai campi letti."""
    tb = h.get_int0("TransportTypeB")
    ta = h.get_int0("TransportTypeA")
    if ta != 0 and tb != TRANSPORT_BUS:
        return "Altro"
    if tb == TRANSPORT_BUS:
        if ta == 0:
            return "Tram"
        rn = h.get_int0("EventRouteNumber")
        if 90 <= rn <= 93:
            return "Filobus"
        return "Autobus"
    return NOMI_MEZZO.get(tb, f"Sconosciuto ({tb})")


def _linea(h: _Holder) -> Optional[str]:
    tb = h.get_int0("TransportTypeB")
    rn = h.get_int("EventRouteNumber")
    if rn is None:
        return None
    if tb == TRANSPORT_METRO and rn in LINEE_METRO:
        return LINEE_METRO[rn]
    if rn == 0:
        return None
    return str(rn)


def _tipo_timbratura(h: _Holder) -> str:
    t = h.get_int0("TransactionType")
    if t in (TRANSACTION_TAP_ON, TRANSACTION_TAP_ON_TRANSFER):
        return "ingresso"
    if t == TRANSACTION_TAP_OFF:
        return "uscita"
    return "timbratura"


def _decodifica_viaggio(trip_data: bytes) -> Viaggio:
    h = _parse(trip_data, TRIP_FIELDS)

    # Ricostruzione data/ora: la data è quella del "primo timbro"; se l'ora
    # dell'evento è precedente a quella del primo timbro, il giorno avanza.
    first_date = h.get_int0("EventFirstStampDate")
    first_time = h.get_int0("EventFirstStampTimeLocal")
    ev_time = h.get_int0("EventTimeLocal")
    d = first_date + 1 if ev_time < first_time else first_date

    luogo = h.get_int("EventLocationId")
    mezzo = _mezzo_e_modo(h)
    if mezzo == "Autobus" and luogo == 999:
        luogo = None

    return Viaggio(
        data=giorni_a_data(d),
        ora=minuti_a_ora(ev_time),
        mezzo=mezzo,
        linea=_linea(h),
        luogo=luogo,
        tipo=_tipo_timbratura(h),
        raw=h,
    )


def _seleziona_slot(sub0: bytes, sub1: bytes) -> int:
    """
    Sceglie quale dei due slot di un abbonamento è il più recente,
    confrontando prima la data (bit 6..19) e poi il contatore (bit 0..5).
    """
    date0 = get_bits(sub0, 6, 14)
    date1 = get_bits(sub1, 6, 14)
    if date0 > date1:
        return 0
    if date0 < date1:
        return 1
    tap0 = get_bits(sub0, 0, 6)
    tap1 = get_bits(sub1, 0, 6)
    if tap0 > tap1:
        return 0
    if tap1 > tap0:
        return 1
    if all(x == 0 for x in sub1):
        return 0
    if all(x == 0 for x in sub0):
        return 1
    return 0 if sub0 >= sub1 else 1


def _decodifica_abbonamento(data: bytes, counter: bytes, xdata: bytes) -> Abbonamento:
    h = _parse(data, DYN_FIELDS)
    STAT_FIELDS.parse(xdata, 0, "", h)  # aggiunge i campi statici allo stesso holder
    cnt = int_reversed(counter, 0, 4)

    tariffa_id = h.get_int0("ContractTariff")
    nome = TARIFFE.get(tariffa_id, f"Titolo sconosciuto (0x{tariffa_id:x})")

    da = giorni_a_data(h.get_int0("ContractStartDate"))
    a = giorni_a_data(h.get_int0("ContractEndDate"))
    # L'"Urbano 2x6" vale 6 giorni dalla data di inizio.
    if tariffa_id == TARIFF_URBAN_2X6 and h.get_int0("ContractStartDate") != 0 and da:
        a = da + timedelta(days=6)

    # Corse / giorni rimanenti, secondo il tipo di titolo.
    num_validati = h.get_int0("ContractValidationsInDay")
    rimanenti: Optional[str] = None
    if tariffa_id == TARIFF_SINGLE_URBAN:
        rimanenti = f"{cnt} corse rimanenti"
    elif tariffa_id == TARIFF_URBAN_2X6:
        giorni = 6 if (num_validati == 0 and cnt == 6) else cnt - 1
        in_giornata = 2 - num_validati
        rimanenti = f"{giorni} giorni rimanenti, {in_giornata} corse oggi"
    elif tariffa_id == TARIFF_DAILY_URBAN:
        rimanenti = f"{cnt} giorni rimanenti"

    return Abbonamento(tariffa=nome, validita_da=da, validita_a=a, rimanenti=rimanenti)


def leggi_milano(card: mfc.ClassicCard):
    """
    Estrae viaggi e abbonamenti da una carta RicaricaMi già letta.
    Restituisce (viaggi, abbonamenti, intestazione).
    """
    # --- viaggi (6 slot nei settori a partire dal blocco 32) ----------
    viaggi: List[Viaggio] = []
    for i in range(6):
        base = 0xA * 3 + 2 + i * 2          # 32, 34, 36, ...
        d0 = _blocco(card, base // 3, base % 3)
        d1 = _blocco(card, (base + 1) // 3, (base + 1) % 3)
        trip_data = d0 + d1
        if any(x != 0 for x in trip_data):
            viaggi.append(_decodifica_viaggio(trip_data))

    # --- abbonamenti (settori 6,7,8 + un caso speciale nel settore 9) --
    abbonamenti: List[Abbonamento] = []
    for i in range(3):
        sec = i + 6
        b0 = _blocco(card, sec, 0)
        b1 = _blocco(card, sec, 1)
        b2 = _blocco(card, sec, 2)
        if all(x == 0 for x in b0) and all(x == 0 for x in b1) and all(x == 0 for x in b2):
            continue
        sel = _seleziona_slot(b0, b1)
        sub_data = (b0, b1)[sel]
        counter = _blocco(card, i + 2, sel)
        xdata = _blocco(card, i + 2, 2)
        abbonamenti.append(_decodifica_abbonamento(sub_data, counter, xdata))

    sec9 = (_blocco(card, 9, 1), _blocco(card, 9, 2))
    if any(x != 0 for x in sec9[0]) or any(x != 0 for x in sec9[1]):
        sel = _seleziona_slot(sec9[0], sec9[1])
        abbonamenti.append(_decodifica_abbonamento(
            sec9[sel], _blocco(card, 5, 1), _blocco(card, 5, 2)))

    # --- intestazione (settore 1): data di nascita e validità ---------
    intestazione: Dict[str, Optional[date]] = {}
    try:
        h = _parse(_blocco(card, 1, 0), BLOCK_1_0_FIELDS)
        BLOCK_1_1_FIELDS.parse(_blocco(card, 1, 1), 0, "", h)
        intestazione["data_nascita"] = data_bcd(h.get_int0("HolderBirthDateDateBCD"))
        intestazione["validita_fine"] = giorni_a_data(h.get_int0("EnvApplicationValidityEndDate"))
        intestazione["emissione"] = giorni_a_data(h.get_int0("EnvApplicationIssueDate"))
    except Exception:
        pass

    return viaggi, abbonamenti, intestazione


# ======================================================================
# 6) TESTO LEGGIBILE
# ======================================================================

def descrivi(card: mfc.ClassicCard) -> Optional[str]:
    """
    Se la carta è una RicaricaMi, restituisce una descrizione leggibile
    (viaggi e abbonamenti). Altrimenti None.
    """
    if not riconosce(card):
        return None

    viaggi, abbonamenti, intest = leggi_milano(card)
    r: List[str] = []
    r.append("╔══════════════════════════════════════════════════════╗")
    r.append("║   CARTA MILANO — RICARICAMI (ATM / Trenord)            ║")
    r.append("╚══════════════════════════════════════════════════════╝")
    r.append("")

    # Intestazione.
    if intest:
        if intest.get("data_nascita"):
            r.append(f"Data di nascita titolare : {intest['data_nascita'].isoformat()}")
        if intest.get("emissione"):
            r.append(f"Emissione carta          : {intest['emissione'].isoformat()}")
        if intest.get("validita_fine"):
            r.append(f"Validità carta fino al   : {intest['validita_fine'].isoformat()}")
        r.append("")

    # Abbonamenti / titoli.
    r.append("── TITOLI / ABBONAMENTI ──────────────────────────────")
    if abbonamenti:
        for i, a in enumerate(abbonamenti, 1):
            r.append(f"  {i}. {a.tariffa}")
            if a.validita_da:
                r.append(f"       valido dal : {a.validita_da.isoformat()}")
            if a.validita_a:
                r.append(f"       valido al  : {a.validita_a.isoformat()}")
            if a.rimanenti:
                r.append(f"       residuo    : {a.rimanenti}")
    else:
        r.append("  (nessun titolo attivo rilevato)")
    r.append("")

    # Viaggi.
    r.append("── ULTIMI VIAGGI ─────────────────────────────────────")
    if viaggi:
        for i, v in enumerate(viaggi, 1):
            data_s = v.data.isoformat() if v.data else "??"
            linea_s = f" linea {v.linea}" if v.linea else ""
            luogo_s = f" — fermata/stazione #{v.luogo}" if v.luogo else ""
            r.append(f"  {i}. {data_s} {v.ora}  [{v.tipo}]  {v.mezzo}{linea_s}{luogo_s}")
    else:
        r.append("  (nessun viaggio registrato)")
    r.append("")
    r.append("Nota: alcuni campi del formato non sono pubblicamente")
    r.append("documentati; i valori mostrati sono quelli interpretabili")
    r.append("con certezza.")
    return "\n".join(r)
