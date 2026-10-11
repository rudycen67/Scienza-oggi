@echo off
REM ====================================================================
REM  Crea l'eseguibile Windows (LettoreMifare.exe) da questo programma.
REM  Richiede Python 3 installato (con "Add Python to PATH" selezionato).
REM  Doppio clic su questo file e attendi: alla fine trovi l'exe nella
REM  cartella "dist".
REM ====================================================================
echo.
echo [1/3] Installazione dello strumento di compilazione (PyInstaller)...
python -m pip install --upgrade pyinstaller
if errorlevel 1 (
  echo.
  echo ERRORE: Python non trovato. Installa Python 3 da python.org
  echo e assicurati di spuntare "Add Python to PATH" durante l'installazione.
  pause
  exit /b 1
)

echo.
echo [2/3] Creazione dell'eseguibile...
REM --onefile : un solo .exe   --windowed : senza finestra nera del terminale
REM I tre moduli di supporto vengono inclusi automaticamente perche'
REM sono importati da mifare_reader_gui.py, che e' lo script principale.
python -m PyInstaller --onefile --windowed --name LettoreMifare mifare_reader_gui.py

echo.
echo [3/3] Fatto!
echo L'eseguibile si trova in:  dist\LettoreMifare.exe
echo Puoi spostarlo dove vuoi e avviarlo con doppio clic.
echo.
pause
