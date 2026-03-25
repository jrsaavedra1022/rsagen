class KeystoreError(Exception):
    """Error al abrir o leer el keystore PKCS#12."""


class EncryptionError(Exception):
    """Error durante cifrado o descifrado RSA."""
