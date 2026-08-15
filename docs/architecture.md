# Architecture

dbcreds is a management layer between two things it does not own: the place a
secret is stored, and the system that secret authenticates to. Neither side
will do the work in the middle — a vault will not change a database password,
and a database will not update your vault.

```
        ┌──────────────────────────────┐
        │        CredentialManager      │   environments, lifecycle operations
        └───────┬───────────────┬──────┘
                │               │
   storage side │               │ application side
                ▼               ▼
    ┌───────────────────┐   ┌──────────────────────┐
    │ CredentialBackend │   │   DatabaseAdapter    │
    ├───────────────────┤   ├──────────────────────┤
    │ OnePasswordBackend│   │ PostgreSQLAdapter    │
    │ KeyringBackend    │   │ MySQLAdapter         │
    │ WindowsCredential │   │ DorisAdapter         │
    │ EnvironmentBackend│   └──────────────────────┘
    │ ConfigFileBackend │
    └───────────────────┘
```

## Storage backends

A backend answers one question: *where does the secret live?* It implements
`get_credential`, `set_credential`, `delete_credential` and `is_available`.

Two properties matter beyond the interface:

- **`stores_secrets`** — whether the backend durably round-trips a password.
  `ConfigFileBackend` strips passwords by design and `EnvironmentBackend` only
  mutates the current process's environment, so both declare `False`. Only a
  backend declaring `True` counts as having stored a credential.
- **Priority** — backends are consulted in order, and reads take the first that
  answers. 1Password is registered ahead of the OS keyring because a shared,
  auditable store should win over a machine-local one.

The secret is written to exactly one backend. Writing it to every secret-capable
backend would create copies that then have to be rotated and revoked
independently, and a stale copy in a higher-priority backend would shadow the
current one on every read.

## Database adapters

An adapter answers the other question: *what does this credential authenticate
to, and how is it changed there?* It knows the driver, the URL scheme, the
default port, and the dialect's password-change statement.

The statement is the part that genuinely differs:

| Adapter | Statement |
|---------|-----------|
| `PostgreSQLAdapter` | `ALTER USER "u" WITH PASSWORD '…'` |
| `MySQLAdapter` | `ALTER USER 'u'@'%' IDENTIFIED BY '…'` |
| `DorisAdapter` | `SET PASSWORD FOR u@'%' = PASSWORD('…')` |

Doris is wire-compatible with MySQL, so it inherits the connection logic, but
MySQL 8 removed `PASSWORD()` while Doris still requires it. That is why it is a
distinct `DatabaseType` rather than an alias for MySQL.

Drivers are imported lazily, so installing dbcreds does not pull in a database
driver the caller never uses.

## Lifecycle operations

These are the operations that need both sides at once, which is why they live in
the manager rather than in either abstraction:

- **verify** — read from the store, connect through the adapter.
- **rotate** — read the current password, confirm it works, generate a new one,
  change it on the database, verify the new one authenticates, record it in the
  store, and read it back to confirm the store returns it. Any failure rolls the
  database back.

Rotation changes the database **before** the store. The reverse order is what
leaves a store holding a password the database never received, which locks you
out until the old value is recovered from the store's history.

## Design constraints worth knowing

- `CredentialManager` is a singleton. The first construction wins, and a later
  call passing a different `config_dir` is ignored with a warning.
- Module imports are kept lazy throughout for CLI startup time; this is why the
  manager imports models and backends inside functions rather than at module
  scope.
- `DatabaseCredentials` carries its own `database_type`, so a stored credential
  can build a connection string without consulting the environment registry.
  The registry stays authoritative when both are present.
