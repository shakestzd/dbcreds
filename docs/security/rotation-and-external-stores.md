# Security: external stores and password rotation

Covers the security-relevant surface added when dbcreds became a management
layer over pluggable stores and databases: the 1Password backend, the database
adapters, and rotation. Written alongside that change rather than after it.

## What data is involved

| Data | Where it lives | Notes |
|------|----------------|-------|
| Database passwords | One credential store only — 1Password, OS keyring, or Windows Credential Manager | Never written to dbcreds' own config files |
| Usernames, hosts, ports, database names | The credential store, and `~/.dbcreds/metadata.json` | Not secret, but identifies infrastructure |
| Environment registry | `~/.dbcreds/environments.json` | Names and database types only |

No customer data or PII passes through dbcreds. The sensitive asset is the
credential itself, plus the infrastructure detail implied by hostnames.

## What could go wrong, and what stops it

### A password is reported saved when it was not

The original failure mode: any backend returning success counted, including
`ConfigFileBackend`, which strips passwords by design. Backends now declare
`stores_secrets`, and only a backend that durably round-trips the secret counts
toward success. If none does, `set_credentials()` raises rather than returning.

### A stale copy shadows the current password

Reads take the first backend that answers. If a high-priority store rejects a
write and a lower-priority one accepts it, the stale high-priority value wins on
every subsequent read — while the write reports success. dbcreds therefore never
falls back to a second secret store after the first fails; it raises and names
the backend that rejected the write.

### Rotation leaves the database and the store disagreeing

`rotate_password()` changes the database first, verifies the new password
authenticates, then records it, and rolls the database back if the store write
fails. It refuses to start when the stored password does not already work, since
that is the state a half-finished rotation leaves behind. Where state is
genuinely unrecoverable, `RotationError` carries the new password so the caller
can surface it rather than lose it.

### Secrets leaking into process arguments or shell history

Command arguments are visible in `ps` and recorded in shell history. The
1Password backend passes secrets to `op` on **stdin** as a JSON template, never
as arguments — the approach 1Password's own CLI documentation recommends. No
dbcreds command accepts a password as an argument; they are prompted for, or
generated.

### SQL injection through a password

Password-change statements are DDL and take no bind parameters, so the value is
embedded in the statement text. Rather than guess at a per-dialect escaping
scheme, adapters **reject** usernames, passwords and host patterns containing
quotes, backslashes, backticks, or control characters. Generated passwords are
drawn from a character set that satisfies this by construction.

### A credential leaking through a connection string

`get_connection_string()` percent-encodes the username and password. Without it,
a password containing `@` or `/` silently changes which host and database the
URI addresses, rather than failing.

### Item titles that cannot be read back

1Password item titles must be valid in an `op://vault/item/field` reference.
A title containing `:` or `/` cannot be read by `op read` or `op run` at all, so
the default title is the environment name and a custom template containing those
characters logs a warning.

## Controls in place

- Secrets are stored in exactly one backend, never copied across stores.
- No secrets in process arguments, shell history, or dbcreds config files.
- No secret is written to logs. Passwords are held in `SecretStr`, which does not
  render its value in tracebacks or `repr()`.
- Generated passwords use `secrets.choice` (CSPRNG), with a guaranteed character
  class mix and a minimum length.
- `dbcreds remove` does not delete from the credential store unless
  `--delete-credentials` is passed, since that store may be shared.
- Rotation is verified end to end before being recorded, and rolled back if not.

## Known gaps

- **Password length is logged by the web interface** (`dbcreds/web/main.py`)
  during update flows. The value is never logged, but the length is a small
  information leak in a shared log.
- **`ssl_mode` is inert.** It is stored and preserved but no adapter enforces
  TLS, so connections are made with driver defaults.
- **No automated dependency, secret, or static analysis scanning.** The project
  has no CI, so the scanning controls in the SDLC's §3.3/§3.4 are not enforced
  here.
