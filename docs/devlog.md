# Devlog

## 2026-06-25 — Setup iniziale

Abbiamo creato la struttura del repository con cartelle separate per sorgente, test e documentazione. La decisione principale è stata tenere il motore di detection separato dai backend firewall, così il comportamento di mitigazione può cambiare senza toccare la logica di analisi dei log.

Abbiamo impostato una prima baseline del progetto: CLI, parser SSH, backend dry-run e documentazione minima. Il prossimo step è consolidare i test e rifinire i backend Linux/Windows tramite mock, evitando qualunque comando distruttivo durante lo sviluppo.
