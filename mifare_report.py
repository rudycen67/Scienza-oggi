#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mifare_report.py
======================================================================
Genera un REPORT ESPLICATIVO di una carta MIFARE Classic già letta.

A differenza della semplice traduzione in esadecimale, qui ogni dato è
accompagnato da:
  - COSA è stato letto (quale settore / blocco / byte);
  - COSA SIGNIFICA (il ruolo di quel dato);
  - QUALE ALGORITMO / PROCEDIMENTO è stato usato per interpretarlo.

Sono disponibili due formati:
  - report_testo(card)  -> file di testo ordinato e leggibile;
  - report_html(card)   -> pagina HTML in stile "explorer", con sezioni
                           espandibili, pensata per essere aperta nel browser.
======================================================================
"""

from __future__ import annotations

import html
from typing import Optional, List

import mifare_classic_keys as mfc

# Decoder per carte specifiche (opzionale: se assente, si procede senza).
try:
    import mifare_milano as milano
except Exception:  # pragma: no cover
    milano = None


# ======================================================================
# TESTI DIDATTICI RIUTILIZZABILI
# Spiegano i concetti una volta sola, poi vengono richiamati nel report.
# ======================================================================

SPIEGAZIONE_GENERALE = """\
Una carta MIFARE Classic è una memoria divisa in SETTORI; ogni settore è
diviso in BLOCCHI da 16 byte ciascuno.
  - MIFARE Classic 1K : 16 settori da 4 blocchi  (16 chiavi)
  - MIFARE Classic 4K : 32 settori da 4 blocchi + 8 settori da 16 blocchi

L'ULTIMO blocco di ogni settore è il "sector trailer" e NON contiene dati
utente, ma le credenziali del settore:
  byte  0..5  -> Key A (6 byte)       chiave di autenticazione A
  byte  6..8  -> access bits (3 byte) permessi di lettura/scrittura
  byte  9     -> GPB                   byte di uso generale
  byte 10..15 -> Key B (6 byte)       chiave di autenticazione B

Il blocco 0 del settore 0 è speciale ("manufacturer data") e contiene
l'UID, cioè il numero di serie univoco della carta."""

ALGO_UID = """\
PROCEDIMENTO (estrazione UID):
  1. Si legge il blocco 0 del settore 0.
  2. Se il primo byte è 0x04 e i byte 8..9 valgono 0x0400 o 0x4400, l'UID
     è "lungo" e occupa i primi 7 byte del blocco.
  3. Altrimenti l'UID è "corto" e occupa i primi 4 byte del blocco.
  Non c'è nessuna cifratura: l'UID è in chiaro."""

ALGO_CHIAVI = """\
PROCEDIMENTO (lettura chiavi del settore):
  Le chiavi si trovano sempre nell'ultimo blocco del settore (il trailer):
     Key A = byte 0..5,  Key B = byte 10..15.
  In un dump già acquisito sono presenti direttamente; su carta reale si
  devono invece fornire per autenticarsi. Nota: se gli access bits rendono
  "Key B leggibile", allora Key B NON è più utilizzabile come chiave."""

ALGO_ACCESS = """\
PROCEDIMENTO (decodifica access bits):
  I 3 byte di access bits codificano, in modo ridondante, i permessi di
  ogni blocco. Si estraggono tre nibble C1, C2, C3:
     C1 = nibble alto del byte 1
     C2 = nibble basso del byte 2
     C3 = nibble alto del byte 2
  Per ogni blocco "slot" si ricompone il valore a 3 bit:
     valore = (bit C1 << 2) | (bit C2 << 1) | (bit C3)
  Il valore 0..7 ottenuto indica, tramite una tabella standard, chi può
  leggere/scrivere/incrementare/decrementare quel blocco.
  La VALIDITÀ si verifica controllando che i bit memorizzati in forma
  invertita siano effettivamente il complemento di quelli diretti."""

ALGO_MAD = """\
PROCEDIMENTO (MIFARE Application Directory):
  Il MAD elenca quale "applicazione" (AID) risiede in quale settore.
  1. Si legge il byte GPB nel trailer del settore 0: deve avere il bit
     "Directory Available" attivo e indica la versione (1 o 2).
  2. Si calcola un CRC8 (polinomio 0x1D, valore iniziale 0xC7) sui dati
     della directory e lo si confronta con il CRC memorizzato.
  3. Se il CRC coincide, si estraggono gli AID a coppie di 2 byte dai
     blocchi 1 e 2 del settore 0."""


# ======================================================================
# REPORT TESTUALE ELEGANTE
# ======================================================================

def _box(titolo: str, larghezza: int = 70) -> List[str]:
    """Disegna un titolo dentro una cornice con caratteri di box-drawing."""
    t = f" {titolo} "
    pad = larghezza - 2 - len(t)
    sx = pad // 2
    dx = pad - sx
    return [
        "╔" + "═" * (larghezza - 2) + "╗",
        "║" + " " * sx + t + " " * dx + "║",
        "╚" + "═" * (larghezza - 2) + "╝",
    ]


def _dimensione(n: int) -> str:
    if n <= 16:
        return "MIFARE Classic 1K"
    if n <= 32:
        return "MIFARE Classic 2K"
    return "MIFARE Classic 4K"


def report_testo(card: mfc.ClassicCard,
                 chiavi: Optional[mfc.ClassicCardKeys] = None) -> str:
    """Genera il report esplicativo in formato testo ordinato e leggibile."""
    r: List[str] = []
    r += _box("REPORT CARTA MIFARE CLASSIC")
    r.append("")
    r.append("Questo documento spiega, passo per passo, cosa è stato letto")
    r.append("dalla carta, cosa significa ogni dato e con quale procedimento")
    r.append("è stato interpretato.")
    r.append("")

    # --- lettura specifica della carta (se riconosciuta) -------------
    if milano is not None:
        try:
            milano_txt = milano.descrivi(card)
        except Exception:
            milano_txt = None
        if milano_txt:
            r += _box("LETTURA DELLA CARTA (DATI TRADOTTI)")
            r.append("")
            r.append(milano_txt)
            r.append("")

    # --- come è fatta la carta ---------------------------------------
    r.append("┌─ COME È FATTA UNA CARTA MIFARE CLASSIC " + "─" * 30)
    for riga in SPIEGAZIONE_GENERALE.splitlines():
        r.append("│ " + riga)
    r.append("└" + "─" * 69)
    r.append("")

    # --- riepilogo ----------------------------------------------------
    uid_hex = card.uid.hex() if isinstance(card.uid, (bytes, bytearray)) else str(card.uid)
    r += _box("1) IDENTITÀ DELLA CARTA (UID)")
    r.append(f"  Dato letto    : UID = {uid_hex}")
    r.append(f"  Dove          : settore 0, blocco 0 (manufacturer data)")
    r.append(f"  Significato   : numero di serie univoco della carta")
    r.append(f"  Tipo carta    : {_dimensione(len(card.sectors))} "
             f"({len(card.sectors)} settori)")
    r.append("")
    for riga in ALGO_UID.splitlines():
        r.append("  " + riga)
    r.append("")

    # --- MAD ----------------------------------------------------------
    mad = mfc.parse_mad(card)
    r += _box("2) DIRECTORY DELLE APPLICAZIONI (MAD)")
    if mad:
        r.append("  È presente un MIFARE Application Directory valido.")
        r.append("  Associazione settore -> applicazione (AID):")
        for voce in mad:
            if voce.aid != 0:
                r.append(f"     settore {voce.sector:>2}  ->  AID 0x{voce.aid:04x}")
    else:
        r.append("  Nessun MAD valido rilevato (la carta potrebbe non usarlo,")
        r.append("  oppure il settore 0 non è leggibile).")
    r.append("")
    for riga in ALGO_MAD.splitlines():
        r.append("  " + riga)
    r.append("")

    # --- dettaglio settori --------------------------------------------
    r += _box("3) DETTAGLIO DEI SETTORI")
    r.append("")
    for sec in card.sectors:
        r.append("┌─ SETTORE %-2d " % sec.index + "─" * 55)

        if not sec.authorized:
            r.append("│ Stato: NON LETTO (chiave non disponibile per questo settore).")
            if chiavi is not None and sec.index in chiavi.keys:
                for k in chiavi.keys[sec.index]:
                    r.append(f"│ Chiave candidata dal file chiavi: {k.type.value} {k.key_hex}")
            r.append("└" + "─" * 69)
            r.append("")
            continue

        n_blocchi = len(sec.blocks)
        r.append(f"│ Stato: LETTO correttamente ({n_blocchi} blocchi).")
        r.append("│")

        # Spiegazione del trailer (chiavi).
        r.append("│ CREDENZIALI (dal sector trailer, ultimo blocco):")
        if sec.key_a:
            r.append(f"│   Key A  (byte 0..5)   = {sec.key_a.hex()}")
        if sec.key_b:
            r.append(f"│   Key B  (byte 10..15) = {sec.key_b.hex()}")

        # Access bits dettagliati.
        ab = sec.access_bits
        if ab is not None:
            valido = mfc.ClassicAccessBits.is_valid(sec.trailer[6:9])
            r.append(f"│   Access bits (byte 6..8) = {sec.trailer[6:9].hex()} "
                     f"[{'validi' if valido else 'NON validi'}]")
            r.append(f"│   Key B leggibile: {'sì (quindi non usabile come chiave)' if ab.is_key_b_readable else 'no'}")
            r.append("│   Permessi dei blocchi dati (chi può fare cosa):")
            # Per ogni blocco dati (escluso il trailer), la tabella permessi.
            for b_idx in range(n_blocchi):
                if b_idx == n_blocchi - 1:
                    continue  # il trailer è l'ultimo blocco
                slot = b_idx if n_blocchi == 4 else b_idx // 5
                p = ab.permessi_blocco_dati(slot)
                if p:
                    r.append(f"│     blocco {b_idx}: "
                             f"lettura={p['read']}, scrittura={p['write']}, "
                             f"incr={p['increment']}, decr={p['decrement']}")

        r.append("│")
        r.append("│ DATI DEI BLOCCHI (esadecimale):")
        for i, blocco in enumerate(sec.blocks):
            etich = "  (trailer)" if i == n_blocchi - 1 else ""
            if not blocco:
                r.append(f"│   blocco {i}: [non letto]{etich}")
            else:
                r.append(f"│   blocco {i}: {' '.join(f'{x:02x}' for x in blocco)}{etich}")
        r.append("└" + "─" * 69)
        r.append("")

    # --- appendice algoritmi ------------------------------------------
    r += _box("4) PROCEDIMENTI E ALGORITMI USATI")
    r.append("")
    for blocco in (ALGO_UID, ALGO_CHIAVI, ALGO_ACCESS, ALGO_MAD):
        for riga in blocco.splitlines():
            r.append("  " + riga)
        r.append("")

    # --- glossario ----------------------------------------------------
    r += _box("5) GLOSSARIO")
    glossario = [
        ("UID", "Identificativo univoco della carta (numero di serie)."),
        ("Settore", "Gruppo di blocchi con una propria coppia di chiavi."),
        ("Blocco", "Unità di memoria da 16 byte."),
        ("Sector trailer", "Ultimo blocco del settore: contiene chiavi e permessi."),
        ("Key A / Key B", "Le due chiavi di autenticazione del settore."),
        ("Access bits", "Bit che definiscono i permessi di ogni blocco."),
        ("GPB", "General Purpose Byte: byte di uso generale nel trailer."),
        ("MAD", "Directory che mappa i settori alle applicazioni (AID)."),
        ("AID", "Identificativo di un'applicazione presente sulla carta."),
    ]
    for termine, definizione in glossario:
        r.append(f"  {termine:<16}: {definizione}")
    r.append("")
    r.append("Fine del report.")
    return "\n".join(r)


# ======================================================================
# REPORT HTML IN STILE "EXPLORER"
# ======================================================================

def report_html(card: mfc.ClassicCard,
                chiavi: Optional[mfc.ClassicCardKeys] = None) -> str:
    """
    Genera una pagina HTML autonoma (un solo file) con:
      - intestazione e riepilogo;
      - ogni settore come voce espandibile (stile explorer);
      - spiegazioni e algoritmi integrati.
    La pagina non richiede connessione: stile e logica sono incorporati.
    """
    def esc(x) -> str:
        return html.escape(str(x))

    uid_hex = card.uid.hex() if isinstance(card.uid, (bytes, bytearray)) else str(card.uid)
    mad = mfc.parse_mad(card)

    parti: List[str] = []
    parti.append("""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Report carta MIFARE Classic</title>
<style>
  :root{
    --bg:#0f1115; --panel:#171a21; --panel2:#1e222b; --ink:#e6e9ef;
    --muted:#9aa4b2; --accent:#4da3ff; --ok:#49c17a; --warn:#e0a84a;
    --line:#2a2f3a; --mono:"Consolas","SFMono-Regular","Menlo",monospace;
  }
  @media (prefers-color-scheme: light){
    :root{ --bg:#f5f7fa; --panel:#ffffff; --panel2:#f0f3f8; --ink:#1b1f27;
           --muted:#5b6472; --accent:#1769c7; --line:#dfe4ec; }
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
       font-family:"Segoe UI",system-ui,-apple-system,Roboto,sans-serif;
       line-height:1.5;padding:24px;}
  .wrap{max-width:1000px;margin:0 auto;}
  h1{font-size:24px;margin:0 0 4px}
  .sub{color:var(--muted);margin-bottom:20px}
  .card{background:var(--panel);border:1px solid var(--line);
        border-radius:12px;padding:16px 18px;margin:14px 0;}
  .grid{display:grid;grid-template-columns:160px 1fr;gap:6px 14px}
  .grid div:nth-child(odd){color:var(--muted)}
  .mono{font-family:var(--mono)}
  .pill{display:inline-block;padding:2px 8px;border-radius:999px;
        font-size:12px;background:var(--panel2);border:1px solid var(--line);
        color:var(--muted);margin-left:6px}
  details{background:var(--panel);border:1px solid var(--line);
          border-radius:10px;margin:8px 0;overflow:hidden}
  details>summary{cursor:pointer;padding:12px 16px;list-style:none;
          display:flex;align-items:center;gap:10px;
          background:var(--panel2);user-select:none}
  details>summary::-webkit-details-marker{display:none}
  summary .tri{transition:transform .15s;color:var(--accent)}
  details[open] summary .tri{transform:rotate(90deg)}
  .body{padding:14px 16px}
  .ok{color:var(--ok)} .warn{color:var(--warn)} .muted{color:var(--muted)}
  table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}
  th,td{border:1px solid var(--line);padding:5px 8px;text-align:left}
  th{background:var(--panel2);color:var(--muted);font-weight:600}
  .blk{font-family:var(--mono);font-size:13px;white-space:pre;
       background:var(--panel2);border:1px solid var(--line);
       border-radius:8px;padding:8px 10px;margin:4px 0;overflow-x:auto}
  .algo{background:var(--panel2);border-left:3px solid var(--accent);
        border-radius:6px;padding:10px 14px;margin:10px 0;
        font-family:var(--mono);font-size:13px;white-space:pre-wrap}
  .legend td:first-child{font-weight:600;white-space:nowrap}
  footer{color:var(--muted);text-align:center;margin-top:24px;font-size:13px}
</style>
</head>
<body><div class="wrap">
""")

    # Intestazione + riepilogo.
    parti.append(f"""
  <h1>Report carta MIFARE Classic</h1>
  <div class="sub">Lettura, significato dei dati e procedimento di
      interpretazione — apri le sezioni per esplorare.</div>
  <div class="card">
    <div class="grid">
      <div>UID</div><div class="mono">{esc(uid_hex)}
          <span class="pill">settore 0 · blocco 0</span></div>
      <div>Tipo carta</div><div>{esc(_dimensione(len(card.sectors)))}</div>
      <div>Settori</div><div>{len(card.sectors)}</div>
      <div>MAD</div><div>{'presente' if mad else 'non rilevato'}</div>
    </div>
  </div>
""")

    # Lettura specifica (se riconosciuta), in evidenza e aperta.
    if milano is not None:
        try:
            milano_txt = milano.descrivi(card)
        except Exception:
            milano_txt = None
        if milano_txt:
            parti.append(f"""
  <details open>
    <summary><span class="tri">▶</span><b>Lettura della carta (dati tradotti)</b></summary>
    <div class="body"><div class="algo">{esc(milano_txt)}</div></div>
  </details>
""")

    # Sezione "come è fatta".
    parti.append(f"""
  <details open>
    <summary><span class="tri">▶</span><b>Come è fatta la carta</b></summary>
    <div class="body"><div class="algo">{esc(SPIEGAZIONE_GENERALE)}</div></div>
  </details>
""")

    # MAD.
    if mad:
        righe_mad = "".join(
            f"<tr><td class='mono'>settore {v.sector}</td>"
            f"<td class='mono'>0x{v.aid:04x}</td></tr>"
            for v in mad if v.aid != 0
        )
        parti.append(f"""
  <details>
    <summary><span class="tri">▶</span><b>Directory applicazioni (MAD)</b></summary>
    <div class="body">
      <table><tr><th>Settore</th><th>AID</th></tr>{righe_mad}</table>
      <div class="algo">{esc(ALGO_MAD)}</div>
    </div>
  </details>
""")

    # Settori, ognuno espandibile.
    parti.append('<h1 style="font-size:18px;margin-top:22px">Settori</h1>')
    for sec in card.sectors:
        if not sec.authorized:
            extra = ""
            if chiavi is not None and sec.index in chiavi.keys:
                cand = ", ".join(f"{k.type.value} {k.key_hex}" for k in chiavi.keys[sec.index])
                extra = f"<div class='muted'>Chiavi candidate dal file: <span class='mono'>{esc(cand)}</span></div>"
            parti.append(f"""
  <details>
    <summary><span class="tri">▶</span>Settore {sec.index}
        <span class="pill warn">non letto</span></summary>
    <div class="body"><div class="muted">Chiave non disponibile per questo
        settore, impossibile leggerne il contenuto.</div>{extra}</div>
  </details>""")
            continue

        n = len(sec.blocks)
        righe_key = []
        if sec.key_a:
            righe_key.append(f"<div>Key A <span class='pill'>byte 0..5</span></div>"
                             f"<div class='mono'>{esc(sec.key_a.hex())}</div>")
        if sec.key_b:
            righe_key.append(f"<div>Key B <span class='pill'>byte 10..15</span></div>"
                             f"<div class='mono'>{esc(sec.key_b.hex())}</div>")

        ab = sec.access_bits
        acc_html = ""
        if ab is not None:
            valido = mfc.ClassicAccessBits.is_valid(sec.trailer[6:9])
            stato = "<span class='ok'>validi</span>" if valido else "<span class='warn'>non validi</span>"
            keyb = "sì (non usabile come chiave)" if ab.is_key_b_readable else "no"
            righe_perm = ""
            for b_idx in range(n):
                if b_idx == n - 1:
                    continue
                slot = b_idx if n == 4 else b_idx // 5
                p = ab.permessi_blocco_dati(slot)
                if p:
                    righe_perm += (f"<tr><td class='mono'>blocco {b_idx}</td>"
                                   f"<td>{esc(p['read'])}</td><td>{esc(p['write'])}</td>"
                                   f"<td>{esc(p['increment'])}</td><td>{esc(p['decrement'])}</td></tr>")
            acc_html = f"""
      <div class="grid">
        <div>Access bits <span class="pill">byte 6..8</span></div>
            <div class="mono">{esc(sec.trailer[6:9].hex())} — {stato}</div>
        <div>Key B leggibile</div><div>{keyb}</div>
      </div>
      <table><tr><th>Blocco</th><th>Lettura</th><th>Scrittura</th>
          <th>Incr.</th><th>Decr.</th></tr>{righe_perm}</table>"""

        blocchi_html = ""
        for i, blocco in enumerate(sec.blocks):
            etich = " (trailer)" if i == n - 1 else ""
            if not blocco:
                blocchi_html += f"<div class='blk'>blocco {i}: [non letto]{etich}</div>"
            else:
                hexs = " ".join(f"{x:02x}" for x in blocco)
                blocchi_html += f"<div class='blk'>blocco {i}: {esc(hexs)}{etich}</div>"

        parti.append(f"""
  <details>
    <summary><span class="tri">▶</span>Settore {sec.index}
        <span class="pill ok">letto</span>
        <span class="pill">{n} blocchi</span></summary>
    <div class="body">
      <div class="grid">{''.join(righe_key)}</div>
      {acc_html}
      <div style="margin-top:10px;color:var(--muted)">Dati dei blocchi:</div>
      {blocchi_html}
    </div>
  </details>""")

    # Appendice algoritmi.
    parti.append(f"""
  <h1 style="font-size:18px;margin-top:22px">Procedimenti e algoritmi</h1>
  <details><summary><span class="tri">▶</span>Estrazione UID</summary>
    <div class="body"><div class="algo">{esc(ALGO_UID)}</div></div></details>
  <details><summary><span class="tri">▶</span>Lettura chiavi</summary>
    <div class="body"><div class="algo">{esc(ALGO_CHIAVI)}</div></div></details>
  <details><summary><span class="tri">▶</span>Decodifica access bits</summary>
    <div class="body"><div class="algo">{esc(ALGO_ACCESS)}</div></div></details>
  <details><summary><span class="tri">▶</span>MIFARE Application Directory</summary>
    <div class="body"><div class="algo">{esc(ALGO_MAD)}</div></div></details>
""")

    # Glossario.
    gloss = [
        ("UID", "Identificativo univoco della carta."),
        ("Settore", "Gruppo di blocchi con una propria coppia di chiavi."),
        ("Blocco", "Unità di memoria da 16 byte."),
        ("Sector trailer", "Ultimo blocco del settore: chiavi e permessi."),
        ("Key A / Key B", "Le due chiavi di autenticazione del settore."),
        ("Access bits", "Bit che definiscono i permessi di ogni blocco."),
        ("GPB", "General Purpose Byte nel trailer."),
        ("MAD", "Directory che mappa i settori alle applicazioni."),
        ("AID", "Identificativo di un'applicazione sulla carta."),
    ]
    righe_g = "".join(f"<tr><td>{esc(t)}</td><td>{esc(d)}</td></tr>" for t, d in gloss)
    parti.append(f"""
  <details><summary><span class="tri">▶</span><b>Glossario</b></summary>
    <div class="body"><table class="legend">{righe_g}</table></div></details>
  <footer>Report generato automaticamente dalla lettura del dump.</footer>
</div></body></html>""")

    return "".join(parti)
