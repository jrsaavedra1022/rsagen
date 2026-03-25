from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from rsa_cli.models.bucket import Bucket
from rsa_cli.utils.exceptions import KeystoreError


@dataclass(slots=True)
class Pkcs12Material:
    private_key: RSAPrivateKey
    public_key: RSAPublicKey
    certificate: x509.Certificate
    additional_certificates: tuple[x509.Certificate, ...]


class KeyStoreService:
    def __init__(self, certs_base_path: str | Path = "appuser/certs") -> None:
        self.certs_base_path = Path(certs_base_path)

    def _get_keystore_path(self, bucket: Bucket) -> Path:
        return self.certs_base_path / bucket.cert_name

    def load_material(self, bucket: Bucket) -> Pkcs12Material:
        keystore_path = self._get_keystore_path(bucket)

        if not keystore_path.exists():
            raise KeystoreError(f"No se encontró el keystore en la ruta: {keystore_path}")

        try:
            keystore_bytes = keystore_path.read_bytes()
        except OSError as exc:
            raise KeystoreError(f"No fue posible leer el keystore: {keystore_path}") from exc

        password = bucket.key_store_password.encode("utf-8") if bucket.key_store_password else None

        try:
            private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
                keystore_bytes,
                password,
            )
        except ValueError as exc:
            raise KeystoreError(
                f"No fue posible abrir el keystore '{keystore_path}'. "
                "Verifica el password o el formato PKCS#12."
            ) from exc
        except Exception as exc:  # pragma: no cover
            raise KeystoreError(f"Error inesperado al cargar el keystore '{keystore_path}'") from exc

        if private_key is None:
            raise KeystoreError("El keystore PKCS#12 no contiene llave privada")
        if certificate is None:
            raise KeystoreError("El keystore PKCS#12 no contiene certificado principal")
        if not isinstance(private_key, RSAPrivateKey):
            raise KeystoreError("La llave privada cargada no es RSA")

        public_key = certificate.public_key()
        if not isinstance(public_key, RSAPublicKey):
            raise KeystoreError("La llave pública del certificado no es RSA")

        normalized_additional = tuple(additional_certs or ())

        return Pkcs12Material(
            private_key=private_key,
            public_key=public_key,
            certificate=certificate,
            additional_certificates=normalized_additional,
        )
