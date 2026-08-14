# Password Rotation

## Rotating to a Generated Password

```bash
# Generate a strong password, store it, and show it once
dbcreds update dev --generate

# Or generate one separately to set on the database first
dbcreds generate --length 48
```

`--generate` implies a password rotation, so `--password` is not needed as well.
The new password is displayed once and then only retrievable via
`dbcreds show dev --password`.

Rotation order matters: dbcreds stores what you tell it, it does not change the
password on the database. Set the new password on the database account first (or
in the same maintenance window), otherwise the stored credential will no longer
match the server.

## Automatic Expiry Tracking

dbcreds tracks password age and expiry:

```python
from dbcreds import get_credentials

creds = get_credentials("dev")
days_left = creds.days_until_expiry()
if creds.is_password_expired():
    print("Password expired!")
```

## Setting Expiry

```bash
# Set 90-day expiry
dbcreds add dev --expires-days 90

# Update expiry
dbcreds update dev --expires-days 180
```

## Checking Status

```bash
# Check all environments
dbcreds check
```
