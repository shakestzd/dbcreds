# dbcreds/cli.py
"""
Command-line interface for dbcreds.

This module provides a rich, user-friendly CLI for managing database
credentials using Typer and Rich.
"""

import os
import sys
import time
from typing import Optional

import typer
from loguru import logger
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from dbcreds import __version__
from dbcreds.core.exceptions import (
    CredentialError,
    CredentialNotFoundError,
    RotationError,
    ValidationError,
)
from dbcreds.core.manager import CredentialManager
from dbcreds.core.models import DatabaseCredentials, DatabaseType
from dbcreds.core.security import DEFAULT_PASSWORD_LENGTH, generate_password

# Configure logger for CLI
logger.remove()  # Remove default handler
logger.add(
    sys.stderr,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
    level="INFO" if not os.getenv("DBCREDS_DEBUG") else "DEBUG",
)

app = typer.Typer(
    name="dbcreds",
    help="Professional database credentials management",
    add_completion=True,
    rich_markup_mode="rich",
)
console = Console()


def _show_generated_password(password: str) -> None:
    """
    Display a generated password once.

    Printed with markup disabled so the password is never parsed as rich markup.
    """
    console.print("\n[bold]Generated password (shown once):[/bold]")
    console.print(f"  {password}", style="green", markup=False, highlight=False)
    console.print(
        "[dim]Set this on the database account itself -- dbcreds only stores it.[/dim]"
    )


def _existing_expiry_days(creds: DatabaseCredentials) -> Optional[int]:
    """
    Recover an environment's configured expiry window, in days.

    Used so an update that does not mention --expires-days keeps the policy the
    environment already had instead of silently resetting it to the default.

    Returns:
        The window in days, or None if no expiry is configured
    """
    if creds.password_expires_at is None or creds.password_updated_at is None:
        return None

    window = creds.password_expires_at - creds.password_updated_at
    return window.days if window.days > 0 else None


def version_callback(value: bool):
    """Show version and exit."""
    if value:
        console.print(f"[bold blue]dbcreds[/bold blue] version [green]{__version__}[/green]")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit",
        callback=version_callback,
        is_eager=True,
    ),
):
    """
    dbcreds - Professional database credentials management.

    Securely store and manage database credentials for multiple environments.
    """
    pass


@app.command()
def init():
    """Initialize dbcreds configuration."""
    console.print("[bold blue]Initializing dbcreds...[/bold blue]")

    manager = CredentialManager()
    console.print(f"✅ Configuration directory: [green]{manager.config_dir}[/green]")

    # list_backends() forces the lazy initialization; reading manager.backends
    # directly here reported 0 backends before they had been set up.
    available = manager.list_backends()
    console.print(f"✅ Available backends: [green]{len(available)}[/green]")

    for name, stores_secrets in available:
        suffix = "" if stores_secrets else " [dim](metadata only)[/dim]"
        console.print(f"  - {name}{suffix}")

    active = manager.get_active_backend_name()
    if active:
        console.print(f"✅ Passwords will be stored in: [green]{active}[/green]")
    else:
        console.print(
            "[bold red]⚠️  No secure credential store available -- "
            "saving credentials will fail rather than drop the password.[/bold red]"
        )

    console.print("\n[bold green]dbcreds initialized successfully![/bold green]")


@app.command()
def add(
    name: str = typer.Argument(..., help="Environment name (e.g., dev, staging, prod)"),
    db_type: DatabaseType = typer.Option(
        DatabaseType.POSTGRESQL,
        "--type",
        "-t",
        help="Database type",
        case_sensitive=False,
    ),
    host: Optional[str] = typer.Option(None, "--host", "-h", help="Database host"),
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Database port"),
    database: Optional[str] = typer.Option(None, "--database", "-d", help="Database name"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Database username"),
    description: Optional[str] = typer.Option(None, "--description", help="Environment description"),
    production: bool = typer.Option(False, "--production", help="Mark as production environment"),
    expires_days: int = typer.Option(90, "--expires-days", help="Password expiry in days"),
    generate: bool = typer.Option(
        False, "--generate", "-g", help="Generate a strong password instead of prompting"
    ),
    length: int = typer.Option(
        DEFAULT_PASSWORD_LENGTH, "--length", help="Password length when using --generate"
    ),
    link: bool = typer.Option(
        False,
        "--link",
        help="Register an environment whose credentials already exist in the "
        "store (e.g. 1Password), instead of prompting for them",
    ),
):
    """Add a new database environment."""
    console.print(f"\n[bold blue]Adding environment: {name}[/bold blue]")

    manager = CredentialManager()

    # Check if environment already exists
    if name.lower() in [env.name for env in manager.list_environments()]:
        console.print(f"[red]Environment '{name}' already exists![/red]")
        if not Confirm.ask("Do you want to update the credentials?"):
            raise typer.Exit()
    else:
        # Add the environment
        try:
            manager.add_environment(name, db_type, description, production)
            console.print(f"✅ Created environment: [green]{name}[/green]")
        except CredentialError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    # The secret is already in the store, so read it rather than asking for it.
    if link:
        try:
            creds = manager.get_credentials(name, check_expiry=False)
        except Exception as e:
            console.print(f"[red]No existing credentials found for '{name}': {e}[/red]")
            console.print(
                "Check the store is reachable and the item name matches "
                "(see DBCREDS_OP_ITEM_TITLE)."
            )
            raise typer.Exit(1)

        console.print(
            f"✅ Linked to existing credentials: [green]{creds.username}@"
            f"{creds.host}:{creds.port}/{creds.database}[/green]"
        )
        return

    # Collect connection details
    if not host:
        host = Prompt.ask("Database host", default="localhost")
    if not port:
        default_ports = {
            DatabaseType.POSTGRESQL: 5432,
            DatabaseType.MYSQL: 3306,
            DatabaseType.ORACLE: 1521,
            DatabaseType.MSSQL: 1433,
        }
        port = IntPrompt.ask("Database port", default=default_ports.get(db_type, 5432))
    if not database:
        database = Prompt.ask("Database name")
    if not username:
        username = Prompt.ask("Username")

    # Get password securely
    if generate:
        try:
            password = generate_password(length)
        except ValidationError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
        _show_generated_password(password)
    else:
        password = Prompt.ask("Password", password=True)
        confirm_password = Prompt.ask("Confirm password", password=True)

        if password != confirm_password:
            console.print("[red]Passwords do not match![/red]")
            raise typer.Exit(1)

    # Store credentials
    try:
        manager.set_credentials(
            name,
            host,
            port,
            database,
            username,
            password,
            expires_days,
        )
        console.print(f"\n✅ Credentials stored for environment: [green]{name}[/green]")

        # Test connection
        if Confirm.ask("Test connection?", default=True):
            test(name)

    except Exception as e:
        console.print(f"[red]Error storing credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def list():
    """List all configured environments."""
    manager = CredentialManager()
    environments = manager.list_environments()

    if not environments:
        console.print("[yellow]No environments configured yet.[/yellow]")
        console.print("Use [bold]dbcreds add[/bold] to add an environment.")
        return

    table = Table(title="Configured Environments", box=box.ROUNDED)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Description", style="green")
    table.add_column("Production", style="red")
    table.add_column("Created", style="blue")

    for env in environments:
        table.add_row(
            env.name,
            env.database_type.value,
            env.description or "-",
            "✓" if env.is_production else "",
            env.created_at.strftime("%Y-%m-%d"),
        )

    console.print(table)


@app.command()
def show(
    name: str = typer.Argument(..., help="Environment name"),
    show_password: bool = typer.Option(False, "--password", help="Show password"),
):
    """Show details for a specific environment."""
    manager = CredentialManager()

    try:
        creds = manager.get_credentials(name)
        env = next((e for e in manager.list_environments() if e.name == name.lower()), None)

        if not env:
            console.print(f"[red]Environment '{name}' not found![/red]")
            raise typer.Exit(1)

        # Create details panel
        details = f"""[bold cyan]Environment:[/bold cyan] {env.name}
[bold cyan]Type:[/bold cyan] {env.database_type.value}
[bold cyan]Description:[/bold cyan] {env.description or 'N/A'}
[bold cyan]Production:[/bold cyan] {'Yes' if env.is_production else 'No'}

[bold yellow]Connection Details:[/bold yellow]
[bold]Host:[/bold] {creds.host}
[bold]Port:[/bold] {creds.port}
[bold]Database:[/bold] {creds.database}
[bold]Username:[/bold] {creds.username}
[bold]Password:[/bold] {'*' * 8 if not show_password else creds.password.get_secret_value()}

[bold yellow]Password Status:[/bold yellow]
[bold]Last Updated:[/bold] {creds.password_updated_at.strftime('%Y-%m-%d %H:%M')}"""

        if creds.password_expires_at:
            days_left = creds.days_until_expiry()
            if days_left is not None:
                if days_left <= 0:
                    details += "\n[bold red]Status: EXPIRED[/bold red]"
                elif days_left <= 14:
                    details += f"\n[bold yellow]Expires in: {days_left} days[/bold yellow]"
                else:
                    details += f"\n[bold green]Expires in: {days_left} days[/bold green]"

        panel = Panel(details, title=f"Environment: {name}", box=box.ROUNDED)
        console.print(panel)

    except CredentialNotFoundError:
        console.print(f"[red]No credentials found for environment '{name}'[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def test(
    name: str = typer.Argument(..., help="Environment name"),
):
    """Test database connection for an environment."""
    manager = CredentialManager()

    with console.status(f"Testing connection to [bold]{name}[/bold]..."):
        try:
            if manager.test_connection(name):
                console.print(f"✅ [green]Connection to '{name}' successful![/green]")
            else:
                console.print(f"❌ [red]Connection to '{name}' failed![/red]")
                raise typer.Exit(1)
        except Exception as e:
            console.print(f"❌ [red]Connection test failed: {e}[/red]")
            raise typer.Exit(1)


@app.command()
def remove(
    name: str = typer.Argument(..., help="Environment name"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
    delete_credentials: bool = typer.Option(
        False,
        "--delete-credentials",
        help="Also delete the stored password from the credential store",
    ),
):
    """Unregister an environment, keeping its stored password by default."""
    manager = CredentialManager()

    if not force:
        if delete_credentials:
            store = manager.get_active_backend_name() or "the credential store"
            console.print(
                f"This deletes the stored password for [bold]{name}[/bold] from "
                f"[bold]{store}[/bold]. If that store is shared, it disappears "
                "for everyone with access, along with its history."
            )
        else:
            console.print(
                f"This unregisters [bold]{name}[/bold] from dbcreds. The stored "
                "password is left untouched."
            )
        if not Confirm.ask("Continue?", default=not delete_credentials):
            console.print("[yellow]Cancelled[/yellow]")
            raise typer.Exit()

    try:
        manager.remove_environment(name, delete_credentials=delete_credentials)
        if delete_credentials:
            console.print(f"✅ [green]Environment '{name}' and its password removed[/green]")
        else:
            console.print(
                f"✅ [green]Environment '{name}' unregistered[/green] "
                "(stored password kept)"
            )
    except CredentialNotFoundError:
        console.print(f"[red]Environment '{name}' not found![/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def update(
    name: str = typer.Argument(..., help="Environment name"),
    password: bool = typer.Option(False, "--password", help="Prompt for a new password"),
    expires_days: Optional[int] = typer.Option(
        None, "--expires-days", help="Update password expiry in days (0 to disable)"
    ),
    generate: bool = typer.Option(
        False, "--generate", "-g", help="Rotate to a newly generated strong password"
    ),
    length: int = typer.Option(
        DEFAULT_PASSWORD_LENGTH, "--length", help="Password length when using --generate"
    ),
    host: Optional[str] = typer.Option(None, "--host", "-h", help="New database host"),
    port: Optional[int] = typer.Option(None, "--port", "-p", help="New database port"),
    database: Optional[str] = typer.Option(None, "--database", "-d", help="New database name"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="New database username"),
):
    """Update credentials for an environment."""
    manager = CredentialManager()

    try:
        # Get existing credentials
        creds = manager.get_credentials(name, check_expiry=False)

        # --generate implies a password rotation, so it does not need --password too.
        rotating = password or generate
        changed_fields = {
            field: value
            for field, value in (
                ("host", host),
                ("port", port),
                ("database", database),
                ("username", username),
            )
            if value is not None
        }

        if not rotating and not changed_fields and expires_days is None:
            console.print(
                "[yellow]Nothing to update.[/yellow]\n"
                "Pass --password or --generate to change the password, "
                "--expires-days to change expiry, or "
                "--host/--port/--database/--username to change connection details."
            )
            raise typer.Exit(1)

        if rotating:
            if generate:
                # A ValidationError here is reported by the handler below; catching
                # it locally would print the message twice.
                new_password = generate_password(length)
                _show_generated_password(new_password)
            else:
                new_password = Prompt.ask("New password", password=True)
                confirm_password = Prompt.ask("Confirm new password", password=True)

                if new_password != confirm_password:
                    console.print("[red]Passwords do not match![/red]")
                    raise typer.Exit(1)

            # A real rotation: let the timestamp default to now.
            password_updated_at = None
        else:
            # Keep the stored secret, and its true rotation date, untouched --
            # stamping "updated now" would misreport when the password last changed.
            new_password = creds.password.get_secret_value()
            password_updated_at = creds.password_updated_at

        # An unspecified expiry keeps whatever policy the environment already had,
        # rather than silently resetting it to the 90-day default. 0 disables it.
        expiry_days = (
            _existing_expiry_days(creds) if expires_days is None else expires_days
        )

        manager.set_credentials(
            name,
            host=changed_fields.get("host", creds.host),
            port=changed_fields.get("port", creds.port),
            database=changed_fields.get("database", creds.database),
            username=changed_fields.get("username", creds.username),
            password=new_password,
            password_expires_days=expiry_days,
            password_updated_at=password_updated_at,
            # Preserved explicitly; set_credentials rebuilds the record from
            # scratch, so anything not passed back in is dropped.
            ssl_mode=creds.ssl_mode,
            **creds.options,
        )

        updated = (["password"] if rotating else []) + sorted(changed_fields)
        if expires_days is not None:
            updated.append("expiry")
        console.print(
            f"✅ [green]Updated {', '.join(updated)} for environment '{name}'[/green]"
        )

    except CredentialNotFoundError:
        console.print(f"[red]Environment '{name}' not found![/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def check():
    """Check for expiring or expired passwords."""
    manager = CredentialManager()
    environments = manager.list_environments()

    if not environments:
        console.print("[yellow]No environments configured.[/yellow]")
        return

    expired = []
    expiring_soon = []
    healthy = []

    with console.status("Checking password expiry..."):
        for env in environments:
            try:
                creds = manager.get_credentials(env.name, check_expiry=False)
                days = creds.days_until_expiry()

                if days is not None:
                    if days <= 0:
                        expired.append((env.name, abs(days)))
                    elif days <= 14:
                        expiring_soon.append((env.name, days))
                    else:
                        healthy.append((env.name, days))
                else:
                    healthy.append((env.name, None))
            except:
                # Skip environments without credentials
                pass

    # Display results
    if expired:
        console.print("\n[bold red]⚠️  Expired Passwords:[/bold red]")
        for name, days in expired:
            console.print(f"  - {name}: expired {days} days ago")

    if expiring_soon:
        console.print("\n[bold yellow]⚠️  Expiring Soon:[/bold yellow]")
        for name, days in expiring_soon:
            console.print(f"  - {name}: {days} days remaining")

    if healthy:
        console.print("\n[bold green]✅ Healthy:[/bold green]")
        for name, days in healthy[:5]:  # Show first 5
            if days:
                console.print(f"  - {name}: {days} days remaining")
            else:
                console.print(f"  - {name}: no expiry set")
        if len(healthy) > 5:
            console.print(f"  ... and {len(healthy) - 5} more")


@app.command()
def rotate(
    name: str = typer.Argument(..., help="Environment name"),
    length: int = typer.Option(
        DEFAULT_PASSWORD_LENGTH, "--length", "-l", help="Generated password length"
    ),
    user_host: str = typer.Option(
        "%",
        "--user-host",
        help="Host part of the account identity for MySQL-family databases, "
        "e.g. the '%' in dbuser@'%'",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    show: bool = typer.Option(
        False, "--show", help="Print the new password instead of asking"
    ),
) -> None:
    """Change a password on the database and in the credential store."""
    manager = CredentialManager()

    if not yes:
        console.print(
            f"This changes the password for [bold]{name}[/bold] on the database "
            "itself, not just in storage."
        )
        if not Confirm.ask("Continue?", default=False):
            console.print("[yellow]Cancelled[/yellow]")
            raise typer.Exit()

    try:
        with console.status(f"Rotating [bold]{name}[/bold]..."):
            new_password = manager.rotate_password(
                name, length=length, user_host=user_host
            )
    except CredentialNotFoundError:
        console.print(f"[red]Environment '{name}' not found![/red]")
        raise typer.Exit(1)
    except RotationError as e:
        console.print(f"[red]Rotation failed: {e}[/red]")
        if e.applied and e.new_password:
            # The database has this password and nothing else does.
            console.print(
                "\n[bold red]The database now uses the password below and this "
                "is the ONLY copy. Save it before closing this terminal.[/bold red]"
            )
            console.print(f"  {e.new_password}", style="yellow", markup=False, highlight=False)
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    console.print(f"✅ [green]Rotated '{name}' -- database and store now agree.[/green]")

    # Applied on the database and saved to the store, so there is nothing to do
    # with the value. Printing it by default would put a working credential into
    # scrollback for no reason.
    if not show and not yes:
        show = Confirm.ask("Show the new password?", default=False)

    if show:
        _show_generated_password(new_password)
    else:
        console.print(
            f"[dim]Read it any time with: dbcreds show {name} --password[/dim]"
        )


@app.command()
def generate(
    length: int = typer.Option(
        DEFAULT_PASSWORD_LENGTH, "--length", "-l", help="Password length"
    ),
    uri_safe: bool = typer.Option(
        True,
        "--uri-safe/--no-uri-safe",
        help="Restrict symbols to characters that are safe in a connection URI",
    ),
    copy: bool = typer.Option(
        False, "--copy", "-c", help="Copy to clipboard instead of printing"
    ),
    clear_after: int = typer.Option(
        45, "--clear-after", help="Seconds before the clipboard is cleared (0 = never)"
    ),
) -> None:
    """Generate a strong random password."""
    try:
        password = generate_password(length, uri_safe=uri_safe)
    except ValidationError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    if not copy:
        # Unstyled so 'dbcreds generate | pbcopy' pipes the exact value.
        typer.echo(password)
        return

    try:
        from dbcreds.core.clipboard import SecureClipboard
    except ImportError:
        console.print(
            "[red]Clipboard support requires the 'security' extra:[/red]\n"
            "  uv tool install --editable . --with pyperclip"
        )
        raise typer.Exit(1)

    clipboard = SecureClipboard()
    # clear_after=0 leaves no background timer: this process owns the wait, and a
    # daemon timer would die at exit without ever clearing.
    if not clipboard.copy_sensitive(password, clear_after=0):
        console.print("[red]Failed to copy to clipboard.[/red]")
        raise typer.Exit(1)

    if clear_after <= 0:
        console.print(
            "✅ Password copied to clipboard.\n"
            "[yellow]It will stay there until you overwrite it.[/yellow]"
        )
        return

    console.print(f"✅ Password copied to clipboard (clears in {clear_after}s).")
    try:
        with console.status(
            f"Clearing clipboard in {clear_after}s... (Ctrl-C to clear now)"
        ):
            time.sleep(clear_after)
    except KeyboardInterrupt:
        pass
    finally:
        clipboard.clear_clipboard(restore_original=True)
    console.print("🧹 Clipboard cleared.")


config_app = typer.Typer(help="Manage dbcreds settings, e.g. which 1Password vault to use.")
app.add_typer(config_app, name="config")


def _split_key(dotted: str) -> tuple:
    """Split 'section.key' into its parts, or exit with guidance."""
    section, _, key = dotted.partition(".")
    if not section or not key:
        console.print(
            f"[red]'{dotted}' is not a setting name.[/red] Use section.key, "
            "e.g. [bold]onepassword.vault[/bold]."
        )
        raise typer.Exit(1)
    return section, key


@config_app.command("show")
def config_show() -> None:
    """Show the current settings and where they are stored."""
    from dbcreds.core.config import config_path, load_config

    path = config_path()
    settings = load_config()

    console.print(f"[dim]{path}[/dim]")
    if not settings:
        console.print(
            "\nNo settings yet. For example:\n"
            "  [bold]dbcreds config set onepassword.vault MyVault[/bold]"
        )
        return

    table = Table(box=box.ROUNDED)
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    for section in sorted(settings):
        for key in sorted(settings[section]):
            table.add_row(f"{section}.{key}", str(settings[section][key]))
    console.print(table)


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Setting name, e.g. onepassword.vault"),
    value: str = typer.Argument(..., help="Value to store"),
) -> None:
    """Store a setting."""
    from dbcreds.core.config import config_path, set_setting

    section, name = _split_key(key)
    set_setting(section, name, value)
    console.print(f"✅ [green]{key}[/green] = {value}  [dim]({config_path()})[/dim]")


@config_app.command("unset")
def config_unset(
    key: str = typer.Argument(..., help="Setting name, e.g. onepassword.vault"),
) -> None:
    """Remove a setting."""
    from dbcreds.core.config import unset_setting

    section, name = _split_key(key)
    if unset_setting(section, name):
        console.print(f"✅ [green]Removed {key}[/green]")
    else:
        console.print(f"[yellow]{key} was not set[/yellow]")


@app.command()
def backends() -> None:
    """Show which credential backends are active and which one stores passwords."""
    manager = CredentialManager()
    available = manager.list_backends()

    if not available:
        console.print("[bold red]No credential backends available![/bold red]")
        raise typer.Exit(1)

    table = Table(title="Credential Backends", box=box.ROUNDED)
    table.add_column("Priority", justify="right", style="dim")
    table.add_column("Backend", style="cyan")
    table.add_column("Stores passwords", justify="center")

    for position, (name, stores_secrets) in enumerate(available, start=1):
        table.add_row(
            str(position),
            name,
            "[green]yes[/green]" if stores_secrets else "[yellow]no (metadata only)[/yellow]",
        )

    console.print(table)

    active = manager.get_active_backend_name()
    if active:
        console.print(f"\n✅ Passwords will be stored in: [bold green]{active}[/bold green]")
    else:
        console.print(
            "\n[bold red]⚠️  No secure credential store is available.[/bold red]\n"
            "Saving credentials will fail rather than silently drop the password."
        )
        raise typer.Exit(1)


@app.command()
def export(
    name: str = typer.Argument(..., help="Environment name"),
    format: str = typer.Option("uri", "--format", "-f", help="Export format (uri, env, json)"),
    include_password: bool = typer.Option(True, "--include-password", help="Include password"),
):
    """Export connection details for an environment."""
    manager = CredentialManager()

    try:
        creds = manager.get_credentials(name)

        if format == "uri":
            uri = creds.get_connection_string(include_password=include_password)
            console.print(uri)
        elif format == "env":
            env_name = name.upper()
            console.print(f"export DBCREDS_{env_name}_HOST={creds.host}")
            console.print(f"export DBCREDS_{env_name}_PORT={creds.port}")
            console.print(f"export DBCREDS_{env_name}_DATABASE={creds.database}")
            console.print(f"export DBCREDS_{env_name}_USERNAME={creds.username}")
            if include_password:
                console.print(f"export DBCREDS_{env_name}_PASSWORD={creds.password.get_secret_value()}")
        elif format == "json":
            import json

            data = {
                "host": creds.host,
                "port": creds.port,
                "database": creds.database,
                "username": creds.username,
            }
            if include_password:
                data["password"] = creds.password.get_secret_value()
            console.print(json.dumps(data, indent=2))
        else:
            console.print(f"[red]Unknown format: {format}[/red]")
            raise typer.Exit(1)

    except CredentialNotFoundError:
        console.print(f"[red]Environment '{name}' not found![/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
