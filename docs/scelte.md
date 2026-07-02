# Scelte implementative

## Perché ereditarietà qui

L'ereditarietà è applicata a `FirewallBackend` perché ogni backend è realmente un tipo di firewall adapter: espone lo stesso contratto operativo (`block_ip`, `unblock_ip`, `is_blocked`) ma lo implementa con comandi diversi. Il motore centrale non deve sapere se sta lavorando su Linux, Windows o in dry-run: usa il polimorfismo e delega alla sottoclasse concreta.

La composizione resta usata dove è più naturale: `IncidentResponseEngine` contiene un parser/configurazione/backend, ma non eredita da essi. Questo mantiene le responsabilità separate ed evita una God class.

## Sicurezza

La modalità `--dry-run` è centrale per evitare modifiche firewall durante test e demo. I backend reali usano `subprocess.run` con liste di argomenti, non stringhe shell, così si riduce il rischio di injection.
