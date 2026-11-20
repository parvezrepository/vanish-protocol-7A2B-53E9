"""Command-Line Interface (CLI) for the VANISH protocol."""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

from vanish.constants import ExpiryPolicy
from vanish.crypto import (
    generate_ed25519_keypair,
    load_private_key_file,
    load_public_key_file,
    save_keypair_files,
)
from vanish.engine import VanishEngine
from vanish.exceptions import VanishError


def parse_duration_string(duration_str: str) -> int:
    """Parse human-friendly duration string (e.g. '30s', '15m', '2h', '7d') into whole seconds."""
    match = re.fullmatch(r"(\d+)\s*([smhdSMHD]?)", duration_str.strip())
    if not match:
        raise ValueError(
            f"Invalid duration format: '{duration_str}'. Use format like '30s', '15m', '2h', '7d'."
        )
    value, unit = int(match.group(1)), match.group(2).lower() or "s"
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


def format_timestamp(epoch_sec: int) -> str:
    """Format Unix epoch timestamp into human-readable ISO string."""
    dt = datetime.datetime.fromtimestamp(epoch_sec, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def handle_keygen(args: argparse.Namespace) -> int:
    """Handle 'vanish keygen' command."""
    priv, pub = generate_ed25519_keypair()
    out_dir = Path(args.out_dir)
    priv_path, pub_path = save_keypair_files(priv, out_dir, prefix=args.prefix)
    print(f"[+] Successfully generated Ed25519 keypair:")
    print(f"    Private key: {priv_path}")
    print(f"    Public key:  {pub_path}")
    return 0


def handle_pack(args: argparse.Namespace) -> int:
    """Handle 'vanish pack' command."""
    try:
        ttl_seconds = parse_duration_string(args.ttl)
    except ValueError as err:
        print(f"[-] Error: {err}", file=sys.stderr)
        return 1

    policy_map = {
        "auto_unlink": ExpiryPolicy.AUTO_UNLINK,
        "secure_shred": ExpiryPolicy.SECURE_SHRED,
        "revoke_key": ExpiryPolicy.REVOKE_KEY_ONLY,
    }
    policy = policy_map[args.policy]

    try:
        priv_key = load_private_key_file(args.private_key)
    except Exception as err:
        print(f"[-] Failed to load private key from '{args.private_key}': {err}", file=sys.stderr)
        return 1

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[-] Input file not found: {input_path}", file=sys.stderr)
        return 1

    output_path = Path(args.output) if args.output else input_path.with_suffix(input_path.suffix + ".vfile")

    engine = VanishEngine()
    try:
        container, aes_key = engine.pack_file(
            input_path=input_path,
            output_path=output_path,
            private_key=priv_key,
            ttl_seconds=ttl_seconds,
            expiry_policy=policy,
            encrypt=args.encrypt,
            require_monotonic=not args.no_monotonic,
            one_time_read=args.one_time_read,
            issuer_name=args.issuer,
        )
    except Exception as err:
        print(f"[-] Failed to pack container: {err}", file=sys.stderr)
        return 1

    print(f"[+] Packed VANISH container created successfully:")
    print(f"    Container File: {output_path}")
    print(f"    File ID:        {container.manifest.file_id}")
    print(f"    Original File:  {container.manifest.original_name} ({container.manifest.mime_type})")
    print(f"    Expires At:     {format_timestamp(container.manifest.expires_at)} (in {ttl_seconds}s)")
    print(f"    Policy:         {policy.name}")
    print(f"    Encrypted:      {container.is_encrypted}")
    if aes_key:
        print(f"    AES Key (HEX):  {aes_key.hex()}")
        print(f"    [!] Note: Securely transmit this AES key to the recipient for decryption.")
    return 0


def handle_inspect(args: argparse.Namespace) -> int:
    """Handle 'vanish inspect' command."""
    engine = VanishEngine()
    try:
        info = engine.inspect_container(args.file)
    except Exception as err:
        print(f"[-] Failed to inspect container '{args.file}': {err}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    print("==================================================")
    print("                VANISH CONTAINER INFO             ")
    print("==================================================")
    print(f" File ID:           {info['file_id']}")
    print(f" Original Name:     {info['original_name']}")
    print(f" MIME Type:         {info['mime_type']}")
    print(f" Payload SHA-256:   {info['payload_sha256']}")
    print(f" Payload Size:      {info['payload_size_bytes']} bytes")
    print(f" Issued At:         {format_timestamp(info['issued_at'])}")
    print(f" Expires At:        {format_timestamp(info['expires_at'])}")
    print(f" Status:            {'EXPIRED' if info['is_expired'] else 'ACTIVE'}")
    print(f" Remaining Time:    {info['remaining_seconds']} seconds")
    print(f" Expiry Policy:     {info['expiry_policy']}")
    print(f" Encrypted:         {info['is_encrypted']}")
    print(f" Monotonic Guard:   {info['requires_monotonic']}")
    print(f" Secure Shred:      {info['requires_secure_shred']}")
    print(f" One-Time Read:     {info['is_one_time_read']}")
    print(f" Issuer:            {info['issuer']}")
    print("==================================================")
    return 0


def handle_verify(args: argparse.Namespace) -> int:
    """Handle 'vanish verify' command."""
    pub_key = None
    if args.public_key:
        try:
            pub_key = load_public_key_file(args.public_key)
        except Exception as err:
            print(f"[-] Failed to load public key from '{args.public_key}': {err}", file=sys.stderr)
            return 1

    engine = VanishEngine()
    try:
        container = engine.verify_container(args.file, pub_key)
        print(f"[+] Container signature is VALID!")
        print(f"    File ID: {container.manifest.file_id}")
        print(f"    Issuer:  {container.manifest.issuer}")
        return 0
    except VanishError as err:
        print(f"[-] Verification FAILED: {err}", file=sys.stderr)
        return 1


def handle_unpack(args: argparse.Namespace) -> int:
    """Handle 'vanish unpack' command."""
    pub_key = None
    if args.public_key:
        try:
            pub_key = load_public_key_file(args.public_key)
        except Exception as err:
            print(f"[-] Failed to load public key: {err}", file=sys.stderr)
            return 1

    aes_key = None
    if args.aes_key:
        try:
            aes_key = bytes.fromhex(args.aes_key)
        except ValueError:
            print(f"[-] Invalid hexadecimal string for --aes-key", file=sys.stderr)
            return 1

    out_dir = Path(args.out_dir)
    engine = VanishEngine()
    try:
        extracted = engine.unpack_file(
            container_path=args.file,
            output_dir=out_dir,
            public_key=pub_key,
            aes_key=aes_key,
            enforce_expiry=not args.ignore_expiry,
        )
        print(f"[+] Successfully extracted file:")
        print(f"    Destination: {extracted}")
        return 0
    except VanishError as err:
        print(f"[-] Extraction FAILED: {err}", file=sys.stderr)
        return 1


def handle_purge(args: argparse.Namespace) -> int:
    """Handle 'vanish purge' command (simulates OS background lifecycle daemon)."""
    target_dir = Path(args.dir)
    if not target_dir.is_dir():
        print(f"[-] Directory not found: {target_dir}", file=sys.stderr)
        return 1

    engine = VanishEngine()
    now = engine.time_checker.get_current_time()
    vfiles = list(target_dir.rglob("*.vfile")) if args.recursive else list(target_dir.glob("*.vfile"))

    print(f"[*] Scanning {len(vfiles)} .vfile container(s) in {target_dir}...")
    purged_count = 0
    active_count = 0

    for vfile in vfiles:
        try:
            info = engine.inspect_container(vfile)
            if info["is_expired"]:
                print(f"[-] Expired file detected: {vfile.name} (expired at {format_timestamp(info['expires_at'])})")
                if info["requires_secure_shred"]:
                    print(f"    Applying SECURE_SHRED to {vfile}...")
                    engine.shred_file(vfile, passes=2)
                else:
                    print(f"    Applying AUTO_UNLINK to {vfile}...")
                    vfile.unlink(missing_ok=True)
                purged_count += 1
            else:
                active_count += 1
        except Exception as err:
            print(f"[!] Warning: Could not inspect {vfile}: {err}", file=sys.stderr)

    print(f"[+] Purge complete: {purged_count} expired container(s) removed, {active_count} active container(s) retained.")
    return 0


def handle_daemon(args: argparse.Namespace) -> int:
    """Handle 'vanish daemon' command."""
    from vanish.daemon import VanishLifecycleDaemon
    import logging

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s")

    daemon = VanishLifecycleDaemon(
        watch_dirs=args.watch_dirs,
        sweep_interval_sec=args.interval,
    )
    print(f"[*] Starting VANISH OS Lifecycle Enforcement Daemon...")
    print(f"    Watched directories: {args.watch_dirs}")
    print(f"    Sweep interval:      {args.interval}s")
    print(f"    Press Ctrl+C to terminate.")
    daemon.start(blocking=True)
    return 0



def main() -> None:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="vanish",
        description="VANISH: Universal Self-Expiring Digital File Protocol CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate Ed25519 signing keypair")
    p_keygen.add_argument("--out-dir", default="./keys", help="Output directory for generated keys (default: ./keys)")
    p_keygen.add_argument("--prefix", default="issuer", help="Filename prefix (default: issuer)")
    p_keygen.set_defaults(func=handle_keygen)

    # Pack
    p_pack = subparsers.add_parser("pack", help="Pack a file into a self-expiring .vfile container")
    p_pack.add_argument("--input", "-i", required=True, help="Path to input file")
    p_pack.add_argument("--ttl", "-t", required=True, help="Lifetime duration (e.g. 30s, 10m, 2h, 7d)")
    p_pack.add_argument("--private-key", "-k", required=True, help="Path to Ed25519 private key")
    p_pack.add_argument("--output", "-o", help="Output .vfile path (defaults to <input>.vfile)")
    p_pack.add_argument(
        "--policy",
        choices=["auto_unlink", "secure_shred", "revoke_key"],
        default="auto_unlink",
        help="Expiration behavior (default: auto_unlink)",
    )
    p_pack.add_argument("--encrypt", action="store_true", help="Encrypt payload with AES-256-GCM")
    p_pack.add_argument("--no-monotonic", action="store_true", help="Disable monotonic clock requirement")
    p_pack.add_argument("--one-time-read", action="store_true", help="Self-destruct container after first unpack")
    p_pack.add_argument("--issuer", default="VANISH-CLI", help="Issuer identifier string")
    p_pack.set_defaults(func=handle_pack)

    # Inspect
    p_inspect = subparsers.add_parser("inspect", help="Inspect container metadata and expiry status")
    p_inspect.add_argument("--file", "-f", required=True, help="Path to .vfile container")
    p_inspect.add_argument("--json", action="store_true", help="Output in machine-readable JSON format")
    p_inspect.set_defaults(func=handle_inspect)

    # Verify
    p_verify = subparsers.add_parser("verify", help="Cryptographically verify container authenticity")
    p_verify.add_argument("--file", "-f", required=True, help="Path to .vfile container")
    p_verify.add_argument("--public-key", "-p", help="Optional path to trusted public key")
    p_verify.set_defaults(func=handle_verify)

    # Unpack
    p_unpack = subparsers.add_parser("unpack", help="Unpack and verify a self-expiring container")
    p_unpack.add_argument("--file", "-f", required=True, help="Path to .vfile container")
    p_unpack.add_argument("--out-dir", "-o", default="./extracted", help="Destination directory (default: ./extracted)")
    p_unpack.add_argument("--public-key", "-p", help="Path to Ed25519 public key")
    p_unpack.add_argument("--aes-key", help="Hexadecimal AES-256-GCM key if payload is encrypted")
    p_unpack.add_argument("--ignore-expiry", action="store_true", help="Bypass expiry check for auditing purposes")
    p_unpack.set_defaults(func=handle_unpack)

    # Purge
    p_purge = subparsers.add_parser("purge", help="Simulate OS background daemon by purging expired files")
    p_purge.add_argument("--dir", "-d", required=True, help="Directory to scan for expired .vfile files")
    p_purge.add_argument("--recursive", "-r", action="store_true", help="Scan recursively")
    p_purge.set_defaults(func=handle_purge)

    # Daemon
    p_daemon = subparsers.add_parser("daemon", help="Run background OS lifecycle enforcement daemon")
    p_daemon.add_argument("--watch-dirs", "-w", nargs="+", required=True, help="Directory paths to monitor")
    p_daemon.add_argument("--interval", "-i", type=float, default=2.0, help="Periodic sweep interval (seconds)")
    p_daemon.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug logging")
    p_daemon.set_defaults(func=handle_daemon)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
