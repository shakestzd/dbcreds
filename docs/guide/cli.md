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

### Show Active Backends
```bash
dbcreds backends
```

Lists the credential backends in priority order and names the one that will
actually store passwords. Use this to confirm your OS keychain is in use before
storing a real credential — if no secret-capable backend is available, this
exits non-zero and saving credentials fails loudly rather than silently
discarding the password.
