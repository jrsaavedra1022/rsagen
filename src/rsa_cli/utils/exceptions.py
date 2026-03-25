class KeystoreError(Exception):
    """Error al abrir o leer el keystore."""


class KeyAliasError(Exception):
    """Error al buscar alias dentro del keystore."""


class EncryptionError(Exception):
    """Error durante cifrado o descifrado RSA."""
