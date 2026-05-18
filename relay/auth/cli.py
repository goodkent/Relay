import click
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from relay.models.organization import Organization
from relay.extensions import db
from relay.models.organization import Organization

@click.group()
def saml_cli() -> None:
    """ SAML operator commands. """

@saml_cli.command("generate-sp-keys")
@click.argument("org_slug")
def generate_sp_keys(org_slug: str) -> None:
    """Generate and store an SP signing key pair for an organization."""
    org = db.session.scalar(db.select(Organization).where(Organization.slug == org_slug))
    if org is None or org.saml_provider is None:
        raise click.ClickException(f"No SAML provider found for org: {org_slug}")

    # Generate 2048-bit RSA key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    ).decode()

    # Self-signed certificate valid for 3 years
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f'relay-sp-{org_slug}')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=3*365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    org.saml_provider.sp_private_key = private_pem
    org.saml_provider.sp_certificate = cert_pem
    db.session.commit()
    click.echo(f'SP key pair generated for {org_slug}')
    click.echo("Upload the SP certificate to your IDP's SP configuration.")
    click.echo(org.saml_provider.sp_certficate)

        