from __future__ import annotations

import argparse
import platform
from pathlib import Path

from .config import EngineConfig
from .engine import IncidentResponseEngine
from .firewall import DryRunBackend, LinuxIptablesBackend, WindowsFirewallBackend, FirewallBackend
from .parser import SSHLogParser
from .state import StateStore


def build_backend(dry_run: bool) -> FirewallBackend:
    if dry_run:
        return DryRunBackend()
    system = platform.system().lower()
    if system == "linux":
        return LinuxIptablesBackend()
    if system == "windows":
        return WindowsFirewallBackend()
    raise RuntimeError(f"Sistema operativo non supportato: {platform.system()}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ban_engine", description="Automated Incident Response Ban Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Analizza un log SSH e applica le mitigazioni")
    scan.add_argument("log_file", type=Path)
    scan.add_argument("--dry-run", action="store_true", help="Non modifica il firewall reale")
    scan.add_argument("--threshold", type=int, default=5)
    scan.add_argument("--window-minutes", type=int, default=10)
    scan.add_argument("--config", type=Path)
    scan.add_argument("--state-file", type=Path, default=Path("data/state.json"))

    status = subparsers.add_parser("status", help="Mostra gli IP già registrati nello stato locale")
    status.add_argument("--state-file", type=Path, default=Path("data/state.json"))
    return parser


def run_scan(args: argparse.Namespace) -> int:
    config = EngineConfig.from_json(args.config) if args.config else EngineConfig(
        threshold=args.threshold,
        window_minutes=args.window_minutes,
    )
    parser = SSHLogParser()
    events = parser.parse_file(args.log_file)
    backend = build_backend(args.dry_run)
    engine = IncidentResponseEngine(backend=backend, config=config, state_store=StateStore(args.state_file))
    offenders = engine.respond(events)

    print(f"Eventi SSH falliti rilevati: {len(events)}")
    if offenders:
        for ip, attempts in offenders.items():
            print(f"IP candidato al ban: {ip} ({attempts} tentativi)")
    else:
        print("Nessun IP oltre soglia.")
    return 0


def run_status(args: argparse.Namespace) -> int:
    records = StateStore(args.state_file).load()
    if not records:
        print("Nessun ban registrato nello stato locale.")
        return 0
    for record in records:
        print(f"{record.ip} | {record.reason} | {record.banned_at}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "status":
        return run_status(args)
    parser.error("Comando non riconosciuto")
    return 2
