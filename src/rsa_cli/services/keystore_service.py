from pathlib import Path

import jks
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.backends import default_backend

from rsa_cli.models.bucket import Bucket
from rsa_cli.utils.exceptions import KeystoreError, KeyAliasError


class KeyStoreService:
    def __init__(self, certs_base_path: str | Path = "appuser/certs") -> None:
        self.certs_base_path = Path(certs_base_path)

    def _get_keystore_path(self, bucket: Bucket) -> Path:
        return self.certs_base_path / bucket.cert_name

    def open_keystore(self, bucket: Bucket) -> jks.KeyStore:
        keystore_path = self._get_keystore_path(bucket)

        if not keystore_path.exists():
            raise KeystoreError(f"No se encontró el keystore en la ruta: {keystore_path}")

        try:
            return jks.KeyStore.load(str(keystore_path), bucket.key_store_password)
        except Exception as exc:
            raise KeystoreError(
                f"No fue posible abrir el keystore '{keystore_path}'. "
                f"Verifica password, formato y permisos."
            ) from exc

    def load_private_key(self, bucket: Bucket) -> RSAPrivateKey:
        keystore = self.open_keystore(bucket)
        alias = bucket.private_key_alias

        if alias not in keystore.private_keys:
            raise KeyAliasError(f"No existe la llave privada con alias '{alias}'")

        pk_entry = keystore.private_keys[alias]

        try:
            pk_entry.decrypt(bucket.private_key_password)
            private_key = load_der_private_key(
                pk_entry.pkey,
                password=None,
                backend=default_backend(),
            )
        except Exception as exc:
            raise KeystoreError(
                f"No fue posible desencriptar la llave privada del alias '{alias}'. "
                f"Verifica el password de la llave privada."
            ) from exc

        if not isinstance(private_key, RSAPrivateKey):
            raise KeystoreError(f"La llave privada del alias '{alias}' no es RSA")

        return private_key

    def load_public_key(self, bucket: Bucket) -> RSAPublicKey:
        keystore = self.open_keystore(bucket)
        alias = bucket.public_key_alias

        if alias in keystore.private_keys:
            pk_entry = keystore.private_keys[alias]
            if not pk_entry.cert_chain:
                raise KeystoreError(
                    f"El alias '{alias}' no tiene cadena de certificados asociada"
                )

            cert_der = pk_entry.cert_chain[0][1]
        elif alias in keystore.certs:
            cert_der = keystore.certs[alias].cert
        else:
            raise KeyAliasError(f"No existe certificado o llave con alias '{alias}'")

        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            public_key = cert.public_key()
        except Exception as exc:
            raise KeystoreError(
                f"No fue posible cargar la llave pública desde el alias '{alias}'"
            ) from exc

        if not isinstance(public_key, RSAPublicKey):
            raise KeystoreError(f"La llave pública del alias '{alias}' no es RSA")

        return public_key
