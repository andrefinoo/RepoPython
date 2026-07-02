# Proposta di Progetto: Automated Incident Response Ban Engine

## 1. Gruppo di lavoro

- Componente 1: Andrea Finocchielli
- Componente 2: Alessio Ordazzo
- Repository GitHub: https://github.com/andrefinoo/ProgettoFinalePy.git

## 2. Descrizione del problema

I server esposti pubblicamente ricevono spesso tentativi automatici di accesso non autorizzato, soprattutto tramite SSH. Analizzare manualmente i log e bloccare tempestivamente gli indirizzi IP malevoli è un processo lento, ripetitivo e soggetto a errori.

## 3. Soluzione proposta

Il progetto consiste nello sviluppo di una CLI Python chiamata Automated Incident Response Ban Engine. Il programma analizza file di log SSH, individua tentativi falliti tramite espressioni regolari, valida gli indirizzi IP e, quando un IP supera una soglia configurabile, genera o applica una regola di blocco tramite backend firewall.

## 4. Competenze del corso utilizzate

- File I/O
- JSON
- OOP
- Ereditarietà e polimorfismo
- Regex
- Indirizzi IP
- Subprocess
- Test con pytest
- CLI da terminale

## 5. Gerarchia di ereditarietà prevista

La classe base astratta sarà FirewallBackend.

Metodi principali:

- block_ip(ip: str)
- unblock_ip(ip: str)
- is_blocked(ip: str)

Sottoclassi previste:

- LinuxIptablesBackend
- WindowsFirewallBackend
- DryRunFirewallBackend

Il motore principale userà il backend tramite la classe base, senza conoscere la sottoclasse concreta. In questo modo viene dimostrato il polimorfismo reale.

## 6. Piano di sviluppo

### Fase iniziale

- Impostazione repository
- Creazione README
- Creazione requirements.txt
- Definizione struttura src, docs e tests

### Fase MVP

- Parser dei log SSH
- Configurazione JSON
- Validazione IP
- Motore di rilevamento soglia
- Backend dry-run

### Fase avanzata

- Backend Linux e Windows
- Persistenza dei ban
- Test automatici
- Documentazione tecnica e utente

## 7. Obiettivo a metà percorso

A metà percorso vogliamo avere un programma avviabile da terminale in modalità dry-run, capace di leggere un file auth.log di esempio, individuare gli IP sospetti e mostrare quali regole firewall verrebbero applicate.