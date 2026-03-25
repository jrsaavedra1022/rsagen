from dataclasses import dataclass


@dataclass(slots=True)
class Bucket:
    cert_name: str
    key_store_password: str
