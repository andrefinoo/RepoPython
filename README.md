# Automated Incident Response Ban Engine

Progetto finale di laboratorio per il corso di **Programmazione Python (CYS)**.

Il progetto consiste in una CLI Python che analizza log di autenticazione SSH, individua tentativi di accesso falliti e, quando un indirizzo IP supera una soglia configurabile, genera o applica una regola di blocco tramite backend firewall.

L'obiettivo è realizzare un piccolo motore di incident response ispirato a strumenti come Fail2ban, ma con una struttura didattica chiara, testabile e difendibile all'orale.

---

## Stato del progetto

La struttura del repository è già stata impostata con le cartelle principali richieste:

```text
ProgettoFinalePy/
├── docs/
├── examples/
├── src/
├── tests/
├── .gitignore
├── README.md
└── requirements.txt
```

I prossimi step principali sono:

1. completare il codice dentro `src/`;
2. aggiungere i test dentro `tests/`;
3. completare la documentazione dentro `docs/`;
4. verificare che il progetto parta da clone pulito;
5. preparare la demo per l'orale.

---

## Funzionalità previste

### MVP

- Lettura di file di log SSH.
- Parsing tramite espressioni regolari.
- Estrazione e validazione di indirizzi IPv4 e IPv6.
- Conteggio dei tentativi falliti per singolo IP.
- Blocco automatico al superamento di una soglia configurabile.
- Modalità `dry-run` per simulare i comandi senza modificare il firewall reale.
- Configurazione tramite file JSON.
- Whitelist di IP da non bloccare.
- Persistenza dello storico dei ban.
- Test automatizzati con `pytest`.

### Estensioni possibili

- Supporto a più formati di log.
- Esportazione report in JSON o CSV.
- Finestra temporale configurabile per il rilevamento brute-force.
- Comando per sbloccare IP già bannati.
- Maggiore copertura dei test sugli edge case.

---

## Architettura OOP

Il progetto usa l'ereditarietà per separare il motore di rilevamento dalla tecnologia firewall usata dal sistema operativo.

### Classe base astratta

`FirewallBackend`

Definisce il contratto comune che ogni backend firewall deve rispettare.

Metodi principali:

- `block_ip(ip: str)`
- `unblock_ip(ip: str)`
- `is_blocked(ip: str)`

### Sottoclassi concrete

`LinuxIptablesBackend`

Implementa il blocco tramite comandi Linux basati su `iptables`.

`WindowsFirewallBackend`

Implementa il blocco tramite comandi Windows basati su `netsh advfirewall`.

`DryRunFirewallBackend`

Simula i comandi senza eseguirli. È utile per test, demo e sviluppo sicuro.

### Perché questa gerarchia ha senso

Ogni backend firewall è realmente un tipo di `FirewallBackend`. Il motore centrale non deve sapere se sta lavorando su Linux, Windows o in modalità simulata: chiama sempre gli stessi metodi e lascia alla sottoclasse concreta il compito di implementare il comportamento specifico.

Questo permette di dimostrare polimorfismo reale: lo stesso codice del motore funziona con backend diversi.

---

## Struttura consigliata del codice

```text
src/
└── ban_engine/
    ├── __init__.py
    ├── __main__.py
    ├── cli.py
    ├── config.py
    ├── engine.py
    ├── models.py
    ├── parser.py
    ├── state.py
    └── firewall/
        ├── __init__.py
        ├── base.py
        ├── dry_run.py
        ├── linux.py
        └── windows.py
```

Descrizione dei moduli:

| Modulo | Responsabilità |
|---|---|
| `cli.py` | Gestione degli argomenti da terminale |
| `parser.py` | Parsing dei log SSH tramite regex |
| `engine.py` | Logica principale di rilevamento e ban |
| `config.py` | Caricamento configurazione JSON |
| `state.py` | Persistenza dello storico dei ban |
| `models.py` | Modelli dati del dominio |
| `firewall/base.py` | Classe astratta comune |
| `firewall/linux.py` | Backend Linux |
| `firewall/windows.py` | Backend Windows |
| `firewall/dry_run.py` | Backend simulato per test e demo |

---

## Requisiti

- Python 3.11 o superiore
- `pytest` per i test
- Git
- PyCharm o un altro IDE Python

Il progetto deve poter partire da clone pulito con una sequenza semplice.

---

## Installazione

Clonare il repository:

```bash
git clone https://github.com/andrefinoo/ProgettoFinalePy.git
cd ProgettoFinalePy
```

Creare un ambiente virtuale:

```bash
python -m venv .venv
```

Attivare l'ambiente virtuale.

Su Windows:

```bash
.venv\Scripts\activate
```

Su Linux/macOS:

```bash
source .venv/bin/activate
```

Installare le dipendenze:

```bash
pip install -r requirements.txt
```

---

## Avvio del programma

Mostrare l'help:

```bash
python -m ban_engine --help
```

Eseguire una scansione in modalità sicura:

```bash
python -m ban_engine scan --log examples/auth.log --config examples/config.json --dry-run
```

La modalità `dry-run` è fondamentale durante sviluppo e orale perché mostra i comandi che verrebbero eseguiti senza modificare davvero il firewall.

---

## Esempio di configurazione

File: `examples/config.json`

```json
{
  "threshold": 3,
  "window_minutes": 10,
  "whitelist": [
    "127.0.0.1",
    "::1"
  ],
  "state_file": "ban_state.json"
}
```

Significato dei campi:

| Campo | Significato |
|---|---|
| `threshold` | Numero massimo di tentativi falliti prima del ban |
| `window_minutes` | Finestra temporale di analisi |
| `whitelist` | IP che non devono essere bloccati |
| `state_file` | File JSON per salvare lo storico dei ban |

---

## Esecuzione dei test

Installare le dipendenze e poi lanciare:

```bash
PYTHONPATH=src pytest -q
```

Su PowerShell, se `PYTHONPATH=src` non funziona:

```powershell
$env:PYTHONPATH="src"
pytest -q
```

I test devono coprire almeno:

- parsing dei log;
- validazione IP;
- soglia di ban;
- whitelist;
- comportamento polimorfico dei backend firewall;
- modalità dry-run;
- gestione degli errori più comuni.

---

## Come modificare il progetto su PyCharm

### 1. Aprire il repository

1. Aprire PyCharm.
2. Selezionare `Open`.
3. Scegliere la cartella `ProgettoFinalePy`.
4. Attendere l'indicizzazione del progetto.

### 2. Configurare l'interprete Python

1. Andare su `File > Settings > Project > Python Interpreter`.
2. Selezionare o creare un virtual environment nella cartella `.venv`.
3. Verificare che l'interprete punti alla versione Python 3.11+.

### 3. Installare le dipendenze

Aprire il terminale integrato di PyCharm e lanciare:

```bash
pip install -r requirements.txt
```

### 4. Impostare `src` come sorgente

Se PyCharm non riconosce gli import:

1. clic destro sulla cartella `src`;
2. selezionare `Mark Directory as`;
3. scegliere `Sources Root`.

### 5. Modificare il README

1. Aprire `README.md` dalla sidebar sinistra.
2. Modificare il testo in formato Markdown.
3. Usare l'anteprima Markdown di PyCharm per controllare il risultato.
4. Salvare con `Ctrl + S`.

### 6. Eseguire il programma da PyCharm

Dal terminale integrato:

```bash
python -m ban_engine --help
```

Oppure:

```bash
python -m ban_engine scan --log examples/auth.log --config examples/config.json --dry-run
```

### 7. Eseguire i test da PyCharm

Dal terminale:

```bash
PYTHONPATH=src pytest -q
```

Oppure clic destro sulla cartella `tests` e selezionare `Run pytest in tests`.

---

## Workflow Git consigliato

Prima di modificare:

```bash
git status
```

Dopo una modifica significativa:

```bash
git add .
git commit -m "descrizione chiara della modifica"
git push
```

Esempi di commit utili:

```bash
git commit -m "aggiunge parser per log SSH"
git commit -m "implementa backend firewall dry-run"
git commit -m "aggiunge test per soglia di ban"
git commit -m "documenta architettura OOP"
```

Evitare messaggi generici come:

```bash
git commit -m "update"
git commit -m "fix"
git commit -m "varie"
```

---

## Documentazione richiesta

La cartella `docs/` deve contenere:

```text
docs/
├── proposta.md
├── manuale-utente.md
├── manuale-tecnico.md
├── scelte.md
├── uso-ia.md
└── devlog.md
```

Contenuto atteso:

| File | Contenuto |
|---|---|
| `proposta.md` | Proposta approvata del progetto |
| `manuale-utente.md` | Come usare il programma |
| `manuale-tecnico.md` | Architettura, moduli e classi |
| `scelte.md` | Decisioni tecniche e alternative scartate |
| `uso-ia.md` | Dichiarazione trasparente sull'uso dell'IA |
| `devlog.md` | Diario di bordo settimanale |

---

## Checklist prima della consegna

- [ ] Il repository è pubblico.
- [ ] Il progetto si avvia da clone pulito.
- [ ] `README.md` spiega installazione e uso.
- [ ] Il codice è dentro `src/`.
- [ ] La documentazione è dentro `docs/`.
- [ ] I test sono dentro `tests/`.
- [ ] `requirements.txt` è aggiornato.
- [ ] La CLI mostra correttamente `--help`.
- [ ] La modalità `dry-run` funziona.
- [ ] I test `pytest` passano.
- [ ] La gerarchia OOP è spiegabile all'orale.
- [ ] Il devlog è coerente con la storia Git.
- [ ] L'uso dell'IA è dichiarato in modo granulare.
- [ ] Tutti i membri del gruppo hanno commit a proprio nome.

---

## Preparazione all'orale

Durante l'orale bisogna saper spiegare:

1. cosa fa il programma;
2. come si avvia da clone pulito;
3. come funziona il parsing dei log;
4. come viene validato un IP;
5. quando scatta il ban;
6. come funziona la whitelist;
7. perché è stata usata l'ereditarietà;
8. dove avviene il polimorfismo;
9. come funzionano i test;
10. quali parti sono state supportate dall'IA e quali sono state modificate dal gruppo.

Comandi utili per la demo:

```bash
python -m ban_engine --help
python -m ban_engine scan --log examples/auth.log --config examples/config.json --dry-run
PYTHONPATH=src pytest -q
```

---

## Autori

- Componente 1: da completare
- Componente 2: da completare

Repository GitHub:

```text
https://github.com/andrefinoo/ProgettoFinalePy.git
```

---

## Nota sull'uso dell'IA

L'IA è stata usata come supporto alla progettazione, alla revisione della struttura, alla generazione di checklist operative e alla preparazione della documentazione iniziale.

Il codice e la documentazione finale devono essere verificati, compresi e personalizzati dal gruppo prima della consegna.
