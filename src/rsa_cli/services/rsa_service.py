import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from rsa_cli.models.bucket import Bucket
from rsa_cli.services.keystore_service import KeyStoreService
from rsa_cli.utils.exceptions import EncryptionError


class RsaEncryptionService:
    def __init__(self, bucket: Bucket, keystore_service: KeyStoreService | None = None) -> None:
        self.bucket = bucket
        self.keystore_service = keystore_service or KeyStoreService()
        self.private_key = None
        self.public_key = None
        self._init_keys()

    def _init_keys(self) -> None:
        try:
            self.private_key = self.keystore_service.load_private_key(self.bucket)
            self.public_key = self.keystore_service.load_public_key(self.bucket)
        except Exception as exc:
            raise EncryptionError("Error al cargar las llaves del certificado") from exc

    @staticmethod
    def _oaep_padding() -> padding.OAEP:
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

    def encrypt(self, message: str) -> str:
        if self.public_key is None:
            raise EncryptionError("La llave pública no está cargada")

        try:
            encrypted = self.public_key.encrypt(
                message.encode("utf-8"),
                self._oaep_padding(),
            )
            return base64.b64encode(encrypted).decode("utf-8")
        except Exception as exc:
            raise EncryptionError("Error cifrando el mensaje") from exc

    def decrypt(self, encrypted_message_base64: str) -> str:
        if self.private_key is None:
            raise EncryptionError("La llave privada no está cargada")

        try:
            encrypted_bytes = base64.b64decode(encrypted_message_base64)
            decrypted = self.private_key.decrypt(
                encrypted_bytes,
                self._oaep_padding(),
            )
            return decrypted.decode("utf-8")
        except Exception as exc:
            raise EncryptionError("Error descifrando el mensaje") from exc
