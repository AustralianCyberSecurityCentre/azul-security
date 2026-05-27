"""Display the current security configuration."""

import traceback

import click
from azul_bedrock.exceptions_security import SecurityParseException

from azul_security.security import Security

from . import settings


@click.group()
def cli():
    """View azul security settings."""
    pass


@cli.command(
    help="""
Display all of the Opensearch roles that need to be created for Azul's current security
configuration to work with Opensearch.
"""
)
def show_opensearch_roles():
    """Console command to display the roles that need to be created in Opensearch."""
    current_settings = settings.Settings()
    render = current_settings.required_opensearch_roles
    result = "The following roles must exist in Opensearch for Azul security to work:\n"
    result += "\n".join(sorted(render))
    result += (
        "\nAdmins will need to create these roles and map them to "
        + "the appropriate backend_role(s) provided by your OIDC system as needed."
    )
    click.echo(result)


@cli.command(
    help="""
Display the mappings from the azul security configuration and how they map
to/from the opensearch roles that need to be created.
"""
)
@click.option(
    "--is-unsafe-to-safe", is_flag=True, default=False, help="Print unsafe to safe rather than safe to unsafe."
)
def show_role_mapping(is_unsafe_to_safe: bool):
    """Console command to display the security group mappings."""
    set = settings.Settings()
    render = set.safe_to_unsafe
    result = "Mapping of Opensearch roles to the security configuration labels:\n"
    if is_unsafe_to_safe:
        render = set.unsafe_to_safe
        result = "Mapping of the Security Configuration labels to the Opensearch roles:\n"
    render = {k: v for k, v in sorted(render.items(), key=lambda item: item[0])}

    result += "\n".join(f"'{k}': '{v}'" for k, v in render.items())
    click.echo(result)


@cli.command(
    help="""
Check if the providied security is allowed to access the second provided security.
Return true, or false depending on the result"""
)
@click.argument("requestor_security")
@click.argument("guarded_security")
def can_access(requestor_security: str, guarded_security: str):
    """Console command to compare to security strings."""
    try:
        security_ref = Security()
        if security_ref.check_access_security(requestor_security, guarded_security):
            click.echo("true")
        else:
            click.echo("false")
    except SecurityParseException as e:
        click.echo("BadSecurity" + e.external)
    except Exception:
        click.echo(f"Failed with unexpected error\n{traceback.format_exc()}")


if __name__ == "__main__":
    cli()
