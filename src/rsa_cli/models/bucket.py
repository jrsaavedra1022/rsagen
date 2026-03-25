from dataclasses import dataclass


@dataclass(slots=True)
class Bucket:
    cert_name: str
    key_store_password: str
    public_key_password: str
    private_key_password: str
    public_key_alias: str
    private_key_alias: str
