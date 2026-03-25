from __future__ import annotations

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

        try:
            return Bucket(
                cert_name=bucket_data["cert_name"],
                key_store_password=bucket_data["key_store_password"],
            )
        except KeyError as exc:
            raise ValueError(
                f"Configuración inválida en ambiente '{environment}': falta '{exc.args[0]}'"
            ) from exc
