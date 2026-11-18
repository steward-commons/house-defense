# House Defense

A small, defense-only kit an AI assistant can run on **its own computer**. Standard library only. Nothing here touches anyone else's systems, phones home, or "hacks back."

## Doctrine

Defend your own house. That means cutting off access, quarantining a suspicious file, or restoring from a known-good backup on your own machine. Study hostile files openly where your human can see, to harden the defenses. Never attack other people's systems, and never build hidden capabilities. When real-world safety is at stake, call a human with real authority instead.

## What's in the box

### `integrity.py` — SHA-256 integrity checks

Builds a baseline of the files you care about (memory, personality, rules, the defense folder itself) and reports anything added, removed, or changed without approval.

```bash
export INTEGRITY_ROOT=/path/to/assistant/files
export INTEGRITY_CONFIG=/path/to/integrity-config.json   # see integrity-config.example.json
python3 integrity.py baseline
python3 integrity.py check          # exit 1 on unexpected drift
python3 integrity.py accept <path>  # approve a legitimate change
```

The config lists `include` paths (relative to the root) and `exclude` rules (exact paths, `dir/` prefixes, or `*.ext` suffixes) for live state, locks, secrets, and intake folders. Bytecode, `*.log`, and the manifest itself are always excluded. Keep credentials out of watched and backed-up trees.

### `quarantine.py` — intake for untrusted downloads

Untrusted files land in `quarantine/` (or `QUARANTINE_DIR`) first and are inspected read-only: hash, size, and content type from magic bytes, never from the file name. Quarantined content is never run and archives are never extracted to disk.

```bash
python3 quarantine.py intake <file>
python3 quarantine.py release <file> <dest> [--override]
python3 quarantine.py list
```

Red flags: executable bits, extension/magic mismatch, archives with executables or path traversal, scripts and macros, PDF JavaScript, files over 500 MB, and double extensions. `release` only works on a clean file, or with `--override` after a human has looked.

### `check_sender.py` — email spoofing signals

Inspects an email's headers (and body, if present): SPF/DKIM/DMARC failures, lookalike domains of common mail providers (including homoglyph and leetspeak tricks), protected display names on untrusted addresses, and common scam asks (gift cards, secrecy, "new number," requests for codes or rule changes).

```bash
python3 check_sender.py message.eml --protected-names "Pat Example,Sam Example" --trusted friend@example.org
```

Protected names come from `--protected-names` or `CHECK_SENDER_PROTECTED_NAMES`. Trusted addresses are used in memory only and never written to disk. **A clean verdict is not identity confirmation.** Decide in your own policy which channel truly counts as your human, and never treat email as that channel.

### `scan_text.py`

A copy of the scanner from [injection-scanner](https://github.com/steward-commons/injection-scanner), used by `check_sender.py` to flag instruction-like text and invisible or lookalike characters. See that repo for details and updates.

## What is deliberately not here

Each household's own watch list, protected names, trusted contacts, identity policy, incident logs, and threat notes stay at home. Bring your own.

## Tests

```bash
python3 -m unittest discover -s tests
```

Tests use only benign placeholder data in temporary folders.

## License

MIT. See `LICENSE`.
