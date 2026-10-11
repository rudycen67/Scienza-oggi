#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mifare_reader_gui.py
======================================================================
Interfaccia grafica per leggere e tradurre un dump di carta MIFARE
Classic, con selezione dei file tramite la classica finestra "Apri file"
del sistema operativo (Windows / macOS / Linux).

Tutta la logica di lettura è nel modulo `mifare_classic_keys`: questo
file aggiunge solo la finestra e la presentazione dei risultati.

USO:
  - Avvio con doppio clic (su Windows) oppure:  python mifare_reader_gui.py
  - Pulsante "Apri dump..."   -> seleziona il file del dump della carta
       (binario .mfc/.mfd oppure testuale a settori .txt).
  - Pulsante "Apri chiavi..." -> (opzionale) seleziona un file di chiavi
       (JSON, JSON statico o binario grezzo). Le chiavi del file vengono
       mostrate ed eventualmente usate dove il dump non le contiene.
  - Il contenuto tradotto compare subito nell'area di testo e può essere
       salvato con "Salva report...".

Nota: il dump binario contiene GIÀ le chiavi (nel sector trailer). Il
file chiavi separato serve quando il dump non le riporta, oppure per
confrontare/integrare le chiavi disponibili.
======================================================================
"""

from __future__ import annotations

import os
from typing import Optional, List

# I moduli con la logica di lettura e con il report devono stare nella
# stessa cartella di questo file.
import mifare_classic_keys as mfc
import mifare_report as report
import mifare_milano as milano

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext


# ======================================================================
# 1) FUNZIONI DI CARICAMENTO (collegano i file scelti al motore)
# ======================================================================

def carica_dump(percorso: str) -> mfc.ClassicCard:
    """
    Carica un dump dal percorso scelto.

    LEGGE QUI:
      - decide in base all'estensione/contenuto se è un dump binario o
        un dump testuale a settori, poi delega al motore.
    """
    with open(percorso, "rb") as f:
        raw = f.read()

    testo = _prova_testo(raw)
    # Un dump testuale a settori contiene la riga "+Sector:".
    if testo is not None and "+Sector:" in testo:
        return mfc.read_mct_dump(testo)
    # Altrimenti lo trattiamo come dump binario.
    return mfc.read_mfc_dump(raw)


def carica_chiavi(percorso: str) -> mfc.ClassicCardKeys:
    """Carica un file di chiavi riconoscendone automaticamente il formato."""
    with open(percorso, "rb") as f:
        return mfc.import_keys(f.read())


def _prova_testo(raw: bytes) -> Optional[str]:
    """Prova a decodificare i byte come testo UTF-8; None se è binario."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


# ======================================================================
# 2) TRADUZIONE DEL DUMP IN TESTO LEGGIBILE
# ======================================================================

def traduci_carta(card: mfc.ClassicCard,
                  chiavi: Optional[mfc.ClassicCardKeys] = None) -> str:
    """
    Produce la rappresentazione testuale completa della carta letta.

    MOSTRA QUI, nell'ordine:
      - UID e dimensione della carta;
      - l'eventuale MIFARE Application Directory (MAD);
      - per ogni settore: chiavi KeyA/KeyB, access bits, e i blocchi in hex.
    """
    righe: List[str] = []
    righe.append("=" * 64)
    righe.append("  CONTENUTO CARTA MIFARE CLASSIC")
    righe.append("=" * 64)

    # --- UID e tipo carta ---------------------------------------------
    uid_hex = card.uid.hex() if isinstance(card.uid, (bytes, bytearray)) else str(card.uid)
    righe.append(f"UID (settore 0, blocco 0) : {uid_hex}")
    righe.append(f"Numero di settori         : {len(card.sectors)}")
    righe.append(f"Dimensione stimata        : {_dimensione(len(card.sectors))}")
    righe.append("")

    # --- MIFARE Application Directory (se presente) -------------------
    mad = mfc.parse_mad(card)
    if mad:
        righe.append("-" * 64)
        righe.append("  MIFARE APPLICATION DIRECTORY (MAD)")
        righe.append("-" * 64)
        for voce in mad:
            if voce.aid != 0:
                righe.append(f"  settore {voce.sector:>2}  ->  AID 0x{voce.aid:04x}")
        righe.append("")

    # --- chiavi del file esterno (se fornito) -------------------------
    if chiavi is not None and not chiavi.is_empty():
        righe.append("-" * 64)
        righe.append("  CHIAVI DAL FILE SELEZIONATO")
        righe.append("-" * 64)
        righe.append(f"  UID associato : {chiavi.uid}")
        righe.append(f"  tipo file     : {'statico' if chiavi.is_static else 'per carta'}")
        for sec in sorted(chiavi.keys):
            for k in chiavi.keys[sec]:
                righe.append(f"  settore {sec:>2}  {k.type.value:<8} {k.key_hex}")
        righe.append("")

    # --- dettaglio settore per settore --------------------------------
    righe.append("-" * 64)
    righe.append("  DETTAGLIO SETTORI")
    righe.append("-" * 64)
    for sec in card.sectors:
        righe.append(f"\n### Settore {sec.index}")
        if not sec.authorized:
            righe.append("   [NON AUTORIZZATO: chiavi non disponibili per questo settore]")
            # Se il file chiavi ha candidate per questo settore, le proponiamo.
            if chiavi is not None and sec.index in chiavi.keys:
                for k in chiavi.keys[sec.index]:
                    righe.append(f"   chiave candidata dal file: {k.type.value} {k.key_hex}")
            continue

        # Chiavi lette dal trailer del settore.
        if sec.key_a:
            righe.append(f"   KeyA (trailer) : {sec.key_a.hex()}")
        if sec.key_b:
            righe.append(f"   KeyB (trailer) : {sec.key_b.hex()}")

        # Access bits.
        ab = sec.access_bits
        if ab is not None:
            valido = mfc.ClassicAccessBits.is_valid(sec.trailer[6:9])
            righe.append(f"   Access bits    : {sec.trailer[6:9].hex()} "
                         f"(valido: {'sì' if valido else 'no'}, "
                         f"KeyB leggibile: {'sì' if ab.is_key_b_readable else 'no'})")

        # Blocchi in esadecimale.
        for i, blocco in enumerate(sec.blocks):
            if not blocco:
                righe.append(f"   blocco {i}: [non letto]")
            else:
                righe.append(f"   blocco {i}: {_hex_spaziato(blocco)}")

    righe.append("")
    righe.append("=" * 64)
    return "\n".join(righe)


def _dimensione(n_settori: int) -> str:
    if n_settori <= 16:
        return "MIFARE Classic 1K"
    if n_settori <= 32:
        return "MIFARE Classic 2K"
    return "MIFARE Classic 4K"


def _hex_spaziato(b: bytes) -> str:
    """Esadecimale con spazi ogni byte, per leggibilità."""
    return " ".join(f"{x:02x}" for x in b)


# ======================================================================
# 3) FINESTRA GRAFICA
# ======================================================================

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Lettore MIFARE Classic")
        self.geometry("900x640")
        self.minsize(640, 400)

        self._percorso_dump: Optional[str] = None
        self._percorso_chiavi: Optional[str] = None
        self._card: Optional[mfc.ClassicCard] = None
        self._chiavi: Optional[mfc.ClassicCardKeys] = None

        self._costruisci_interfaccia()

    # ---- costruzione widget -----------------------------------------
    def _costruisci_interfaccia(self):
        # Barra dei pulsanti in alto.
        barra = ttk.Frame(self, padding=8)
        barra.pack(side=tk.TOP, fill=tk.X)

        ttk.Button(barra, text="Apri dump...",
                   command=self._apri_dump).pack(side=tk.LEFT, padx=4)
        ttk.Button(barra, text="Apri chiavi... (opzionale)",
                   command=self._apri_chiavi).pack(side=tk.LEFT, padx=4)
        ttk.Button(barra, text="Salva report...",
                   command=self._salva_report).pack(side=tk.LEFT, padx=4)
        ttk.Button(barra, text="Salva spiegazione (testo)...",
                   command=self._salva_spiegazione_testo).pack(side=tk.LEFT, padx=4)
        ttk.Button(barra, text="Salva spiegazione (HTML)...",
                   command=self._salva_spiegazione_html).pack(side=tk.LEFT, padx=4)
        ttk.Button(barra, text="Pulisci",
                   command=self._pulisci).pack(side=tk.LEFT, padx=4)

        # Etichette coi file selezionati.
        info = ttk.Frame(self, padding=(8, 0))
        info.pack(side=tk.TOP, fill=tk.X)
        self._lbl_dump = ttk.Label(info, text="Dump: (nessuno)")
        self._lbl_dump.pack(side=tk.TOP, anchor="w")
        self._lbl_chiavi = ttk.Label(info, text="Chiavi: (nessuno)")
        self._lbl_chiavi.pack(side=tk.TOP, anchor="w")

        # Area di testo scrollabile coi risultati.
        self._testo = scrolledtext.ScrolledText(
            self, wrap=tk.NONE, font=("Courier New", 10))
        self._testo.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Scrollbar orizzontale.
        xscroll = ttk.Scrollbar(self, orient=tk.HORIZONTAL,
                                command=self._testo.xview)
        self._testo.configure(xscrollcommand=xscroll.set)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)

        # Barra di stato.
        self._stato = ttk.Label(self, text="Pronto. Apri un dump per iniziare.",
                                relief=tk.SUNKEN, anchor="w", padding=4)
        self._stato.pack(side=tk.BOTTOM, fill=tk.X)

    # ---- azioni dei pulsanti ----------------------------------------
    def _apri_dump(self):
        """Finestra 'Apri file' del sistema per scegliere il dump."""
        percorso = filedialog.askopenfilename(
            title="Seleziona il dump della carta",
            filetypes=[
                ("Dump MIFARE", "*.mfc *.mfd *.dump *.bin *.txt"),
                ("Tutti i file", "*.*"),
            ],
        )
        if not percorso:
            return
        try:
            self._card = carica_dump(percorso)
            self._percorso_dump = percorso
            self._lbl_dump.config(text=f"Dump: {os.path.basename(percorso)}")
            self._aggiorna()
            self._stato.config(text=f"Dump caricato: {percorso}")
        except Exception as e:
            messagebox.showerror("Errore nella lettura del dump", str(e))
            self._stato.config(text="Errore nella lettura del dump.")

    def _apri_chiavi(self):
        """Finestra 'Apri file' del sistema per scegliere il file di chiavi."""
        percorso = filedialog.askopenfilename(
            title="Seleziona il file delle chiavi",
            filetypes=[
                ("File di chiavi", "*.json *.keys *.farebotkeys *.bin *.*"),
                ("Tutti i file", "*.*"),
            ],
        )
        if not percorso:
            return
        try:
            self._chiavi = carica_chiavi(percorso)
            self._percorso_chiavi = percorso
            self._lbl_chiavi.config(text=f"Chiavi: {os.path.basename(percorso)}")
            self._aggiorna()
            self._stato.config(text=f"Chiavi caricate: {percorso}")
        except Exception as e:
            messagebox.showerror("Errore nella lettura delle chiavi", str(e))
            self._stato.config(text="Errore nella lettura delle chiavi.")

    def _salva_report(self):
        """Salva il testo tradotto in un file."""
        contenuto = self._testo.get("1.0", tk.END).strip()
        if not contenuto:
            messagebox.showinfo("Niente da salvare", "Apri prima un dump.")
            return
        percorso = filedialog.asksaveasfilename(
            title="Salva il report",
            defaultextension=".txt",
            filetypes=[("File di testo", "*.txt"), ("Tutti i file", "*.*")],
        )
        if not percorso:
            return
        with open(percorso, "w", encoding="utf-8") as f:
            f.write(contenuto)
        self._stato.config(text=f"Report salvato: {percorso}")

    def _salva_spiegazione_testo(self):
        """Genera e salva il report esplicativo in formato testo."""
        if self._card is None:
            messagebox.showinfo("Niente da spiegare", "Apri prima un dump.")
            return
        percorso = filedialog.asksaveasfilename(
            title="Salva la spiegazione (testo)",
            defaultextension=".txt",
            initialfile="spiegazione_carta.txt",
            filetypes=[("File di testo", "*.txt"), ("Tutti i file", "*.*")],
        )
        if not percorso:
            return
        testo = report.report_testo(self._card, self._chiavi)
        with open(percorso, "w", encoding="utf-8") as f:
            f.write(testo)
        self._stato.config(text=f"Spiegazione (testo) salvata: {percorso}")

    def _salva_spiegazione_html(self):
        """Genera e salva il report esplicativo in formato HTML (explorer)."""
        if self._card is None:
            messagebox.showinfo("Niente da spiegare", "Apri prima un dump.")
            return
        percorso = filedialog.asksaveasfilename(
            title="Salva la spiegazione (HTML)",
            defaultextension=".html",
            initialfile="spiegazione_carta.html",
            filetypes=[("Pagina HTML", "*.html"), ("Tutti i file", "*.*")],
        )
        if not percorso:
            return
        pagina = report.report_html(self._card, self._chiavi)
        with open(percorso, "w", encoding="utf-8") as f:
            f.write(pagina)
        self._stato.config(text=f"Spiegazione (HTML) salvata: {percorso}")

    def _pulisci(self):
        self._card = None
        self._chiavi = None
        self._percorso_dump = None
        self._percorso_chiavi = None
        self._lbl_dump.config(text="Dump: (nessuno)")
        self._lbl_chiavi.config(text="Chiavi: (nessuno)")
        self._testo.delete("1.0", tk.END)
        self._stato.config(text="Pulito.")

    # ---- aggiornamento area di testo --------------------------------
    def _aggiorna(self):
        self._testo.delete("1.0", tk.END)
        if self._card is None:
            # Solo chiavi caricate, nessun dump: mostriamo le chiavi.
            if self._chiavi is not None:
                self._testo.insert(tk.END, self._solo_chiavi(self._chiavi))
            return
        # Se la carta è riconosciuta come RicaricaMi (Milano), mostriamo
        # in cima la lettura "tradotta" (viaggi e abbonamenti).
        try:
            milano_txt = milano.descrivi(self._card)
        except Exception:
            milano_txt = None
        if milano_txt:
            self._testo.insert(tk.END, milano_txt + "\n\n\n")
        testo = traduci_carta(self._card, self._chiavi)
        self._testo.insert(tk.END, testo)

    @staticmethod
    def _solo_chiavi(chiavi: mfc.ClassicCardKeys) -> str:
        righe = ["CHIAVI CARICATE (nessun dump selezionato)",
                 f"UID associato : {chiavi.uid}",
                 f"tipo file     : {'statico' if chiavi.is_static else 'per carta'}",
                 ""]
        for sec in sorted(chiavi.keys):
            for k in chiavi.keys[sec]:
                righe.append(f"  settore {sec:>2}  {k.type.value:<8} {k.key_hex}")
        return "\n".join(righe)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
