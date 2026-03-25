from __future__ import annotations

import typer

from rsa_cli.services.config_service import ConfigService
from rsa_cli.services.keystore_service import KeyStoreService
from rsa_cli.services.rsa_service import RsaEncryptionService

app = typer.Typer(help="CLI para cifrar y descifrar con RSA usando PKCS#12 (.p12)")


def build_service(config_path: str, env: str, certs_path: str) -> RsaEncryptionService:
    config_service = ConfigService(config_path)
    bucket = config_service.load_bucket(env)
    keystore_service = KeyStoreService(certs_base_path=certs_path)
    return RsaEncryptionService(bucket=bucket, keystore_service=keystore_service)


def _safe_build_service(config: str, env: str, certs_path: str) -> RsaEncryptionService:
    try:
        return build_service(config, env, certs_path)
    except Exception as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc


@app.command()
def encrypt(
    message: str = typer.Option(..., "--message", "-m", help="Texto plano a cifrar"),
    env: str = typer.Option(..., "--env", "-e", help="Ambiente: dev, cer, etc."),
    config: str = typer.Option("config/buckets.yaml", "--config", "-c", help="Ruta del YAML"),
    certs_path: str = typer.Option("appuser/certs", "--certs-path", help="Ruta base de certificados"),
) -> None:
    """Cifra un mensaje y devuelve Base64."""
    service = _safe_build_service(config, env, certs_path)
    encrypted = service.encrypt(message)
    typer.echo(encrypted)


@app.command()
def decrypt(
    ciphertext: str = typer.Option(..., "--ciphertext", "-t", help="Texto cifrado en Base64"),
    env: str = typer.Option(..., "--env", "-e", help="Ambiente: dev, cer, etc."),
    config: str = typer.Option("config/buckets.yaml", "--config", "-c", help="Ruta del YAML"),
    certs_path: str = typer.Option("appuser/certs", "--certs-path", help="Ruta base de certificados"),
) -> None:
    """Descifra un mensaje Base64."""
    service = _safe_build_service(config, env, certs_path)
    decrypted = service.decrypt(ciphertext)
    typer.echo(decrypted)


@app.command()
def inspect(
    env: str = typer.Option(..., "--env", "-e", help="Ambiente: dev, cer, etc."),
    config: str = typer.Option("config/buckets.yaml", "--config", "-c", help="Ruta del YAML"),
    certs_path: str = typer.Option("appuser/certs", "--certs-path", help="Ruta base de certificados"),
) -> None:
    """Verifica que el PKCS#12 y las llaves/certificado puedan cargarse."""
    service = _safe_build_service(config, env, certs_path)
    typer.echo(f"OK - material PKCS#12 cargado correctamente para el ambiente '{env}'")
    typer.echo(f"Public key loaded: {'yes' if service.public_key else 'no'}")
    typer.echo(f"Private key loaded: {'yes' if service.private_key else 'no'}")
    typer.echo(f"Certificate loaded: {'yes' if service.certificate else 'no'}")
    typer.echo(f"Additional certs: {len(service.additional_certificates)}")


if __name__ == "__main__":
    app()
