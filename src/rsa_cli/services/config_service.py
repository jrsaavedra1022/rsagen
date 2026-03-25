from pathlib import Path
import yaml

from rsa_cli.models.bucket import Bucket


class ConfigService:
    def __init__(self, config_path: str | Path) -> None:
        self.config_path = Path(config_path)

    def load_bucket(self, environment: str) -> Bucket:
        if not self.config_path.exists():
            raise FileNotFoundError(f"No existe el archivo de configuración: {self.config_path}")

        with self.config_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}

        buckets = data.get("buckets", {})
        bucket_data = buckets.get(environment)

        if not bucket_data:
            raise ValueError(f"No existe configuración para el ambiente '{environment}'")

        return Bucket(
            cert_name=bucket_data["cert_name"],
            key_store_password=bucket_data["key_store_password"],
            public_key_password=bucket_data["public_key_password"],
            private_key_password=bucket_data["private_key_password"],
            public_key_alias=bucket_data["public_key_alias"],
            private_key_alias=bucket_data["private_key_alias"],
        )
