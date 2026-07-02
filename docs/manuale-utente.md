# Manuale utente

## Obiettivo

`ban_engine` aiuta a individuare tentativi di brute-force SSH e a reagire con un ban firewall. Durante lo sviluppo e la discussione d'esame usare sempre `--dry-run`.

## Comandi principali

```bash
python -m ban_engine scan examples/auth.log --dry-run --threshold 3 --window-minutes 10
python -m ban_engine scan examples/auth.log --dry-run --config examples/config.json
python -m ban_engine status --state-file data/state.json
```

## Parametri

- `log_file`: percorso del file di log da analizzare.
- `--dry-run`: simula il blocco senza modificare il firewall.
- `--threshold`: numero minimo di tentativi falliti.
- `--window-minutes`: finestra temporale in minuti.
- `--config`: file JSON con soglia, finestra e whitelist.
- `--state-file`: file JSON dove registrare i ban effettuati.
