# CLI Reference

The `dbcreds` command provides a rich CLI for managing credentials.

## Commands

::: dbcreds.cli
    options:
      show_source: false
      members: false

## Usage Examples

### Initialize
```bash
dbcreds init
```

### Add Environment
```bash
dbcreds add dev --type postgresql
```

### List Environments
```bash
dbcreds list
```

### Show Details
```bash
dbcreds show dev
```

### Test Connection
```bash
dbcreds test dev
```

### Check Expiry
```bash
dbcreds check
```

### Generate a Password
```bash
# Print a 32-character password
dbcreds generate

# Custom length, piped straight to the clipboard
dbcreds generate --length 48 | pbcopy

# Copy with an auto-clearing clipboard (requires the 'security' extra)
dbcreds generate --copy --clear-after 30
```

Generated passwords use only URI-unreserved characters (`A-Z`, `a-z`, `0-9`,
`-`, `.`, `_`, `~`) so they cannot corrupt the connection strings dbcreds
emits. Pass `--no-uri-safe` for a wider alphabet if the password will never be
embedded in a URI.

Generate and store in one step:

```bash
# New environment with a generated password
dbcreds add dev --generate --host localhost --username myuser

# Rotate an existing environment to a new generated password
dbcreds update dev --generate
```

The generated password is printed once and cannot be recovered from that
output afterwards — read it back with `dbcreds show dev --password`. Generating
a password does not change it on the database; set it there yourself.

### Update Connection Details
```bash
# Change any subset of the connection details
dbcreds update dev --host new-host --port 6543
dbcreds update dev --database newdb --username newuser

# Combine with a rotation
dbcreds update dev --generate --host new-host
```

Only the options you pass are changed; the password, expiry policy, connection
options and every unmentioned field are preserved. `dbcreds update dev` with no
options changes nothing and exits non-zero.

### Use 1Password as the Store

dbcreds manages credentials; it does not have to hold them. With the
[1Password CLI](https://developer.1password.com/docs/cli/) installed, the
`OnePasswordBackend` takes priority over the local keyring, so the secret stays
in one shared, auditable place rather than being copied onto each machine.

```bash
export DBCREDS_OP_VAULT="MyVault"
export DBCREDS_OP_ITEM_TITLE="Doris {env}"   # default: dbcreds:{env}

dbcreds backends        # confirm OnePasswordBackend is first
```

`DBCREDS_OP_ITEM_TITLE` is what lets dbcreds adopt items that already exist
under their own names. Register an environment against one without re-entering
the password:

```bash
dbcreds add prod --type doris --link
```

`--link` reads host, port, database and username straight from the stored item
instead of prompting. The secret is written to only the highest-priority
secret-capable backend, so enabling 1Password does not leave a second copy in
your keyring.

### Rotate a Password

```bash
dbcreds rotate prod
dbcreds rotate prod --length 48 --user-host '10.0.0.%'
```

This changes the password **on the database and in the store**, in that order:
the database is updated first, verified, and only then recorded. If the store
write fails, the database is rolled back, so the two can never disagree. If the
stored password does not already work, the rotation is refused before anything
is generated.

Supported dialects and the statement each uses:

| Type | Statement |
|------|-----------|
| `postgresql` | `ALTER USER "u" WITH PASSWORD '…'` |
| `mysql` | `ALTER USER 'u'@'%' IDENTIFIED BY '…'` — MySQL 8 removed `PASSWORD()` |
| `doris` | `SET PASSWORD FOR u@'%' = PASSWORD('…')` — Doris/Doris |

`--user-host` sets the host part of the account identity for MySQL-family
databases; PostgreSQL ignores it.

### Show Active Backends
```bash
dbcreds backends
```

Lists the credential backends in priority order and names the one that will
actually store passwords. Use this to confirm your OS keychain is in use before
storing a real credential — if no secret-capable backend is available, this
exits non-zero and saving credentials fails loudly rather than silently
discarding the password.
