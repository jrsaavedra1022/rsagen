# rsa-cli

CLI en Python para cifrar y descifrar mensajes con RSA utilizando keystores PKCS#12 (`.p12`).

## Requisitos

- Python 3.11+
- `pip`

## Crear ambiente local

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

### Windows (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .
```

## Configuración

Archivo `config/buckets.yaml`:

```yaml
buckets:
  dev:
    cert_name: "file_dev.p12"
    key_store_password: "..."

  cer:
    cert_name: "file_cer.p12"
    key_store_password: "..."
```

Los certificados `.p12` se buscan por defecto en `appuser/certs/`.

## Uso del CLI

```bash
rsacli inspect --env dev
rsacli encrypt --env dev --message "1234567acde"
rsacli decrypt --env cer --ciphertext "<base64>"
```

Opciones comunes:

- `--config` para indicar otro archivo YAML.
- `--certs-path` para indicar otra carpeta de certificados.
