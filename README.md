# rsa-cli

CLI en Python para cifrar y descifrar mensajes con RSA utilizando keystores JKS.

## Estructura

- `config/buckets.yaml`: configuración de ambientes y aliases.
- `appuser/certs/`: ubicación de certificados JKS.
- `src/rsa_cli/`: código fuente del CLI.

## Uso rápido

```bash
pip install -e .
rsacli inspect --env dev
rsacli encrypt --env dev --message "hola"
rsacli decrypt --env dev --ciphertext "<base64>"
```
