# dbcreds/cli.py
"""
Command-line interface for dbcreds.

This module provides a rich, user-friendly CLI for managing database
credentials using Typer and Rich.
"""

import os
import sys
from typing import Optional

import typer
from loguru import logger
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from dbcreds import __version__
from dbcreds.core.exceptions import CredentialError, CredentialNotFoundError
from dbcreds.core.manager import CredentialManager
from dbcreds.core.models import DatabaseType

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
    console.print(f"✅ Available backends: [green]{len(manager.backends)}[/green]")

    for backend in manager.backends:
        console.print(f"  - {backend.__class__.__name__}")

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
):
    """Remove an environment and its credentials."""
    if not force:
        if not Confirm.ask(f"Are you sure you want to remove environment '{name}'?"):
            console.print("[yellow]Cancelled[/yellow]")
            raise typer.Exit()

    manager = CredentialManager()

    try:
        manager.remove_environment(name)
        console.print(f"✅ [green]Environment '{name}' removed successfully![/green]")
    except CredentialNotFoundError:
        console.print(f"[red]Environment '{name}' not found![/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def update(
    name: str = typer.Argument(..., help="Environment name"),
    password: bool = typer.Option(False, "--password", help="Update password only"),
    expires_days: Optional[int] = typer.Option(None, "--expires-days", help="Update password expiry"),
):
    """Update credentials for an environment."""
    manager = CredentialManager()

    try:
        # Get existing credentials
        creds = manager.get_credentials(name, check_expiry=False)

        if password:
            # Update password only
            new_password = Prompt.ask("New password", password=True)
            confirm_password = Prompt.ask("Confirm new password", password=True)

            if new_password != confirm_password:
                console.print("[red]Passwords do not match![/red]")
                raise typer.Exit(1)

            manager.set_credentials(
                name,
                creds.host,
                creds.port,
                creds.database,
                creds.username,
                new_password,
                expires_days or 90,
            )
            console.print(f"✅ [green]Password updated for environment '{name}'[/green]")
        else:
            console.print("[yellow]Full credential update not implemented yet[/yellow]")

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
