"""Create and configure the test aiohttp application."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet

from gafaelfawr.keypair import RSAKeyPair

if TYPE_CHECKING:
    from typing import List, Optional

    from gafaelfawr.config import OIDCClient

__all__ = ["build_config", "build_settings", "store_secret"]


def build_settings(tmp_path: Path, template_name: str, **kwargs: Path) -> Path:
    """Construct a configuration file from a format template.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        The root of the temporary area.
    template_name : `str`
        Name of the configuration template to use.
    **kwargs : `str`
        The values to substitute into the template.

    Returns
    -------
    settings_path : `pathlib.Path`
        The path to the newly-constructed configuration file.
    """
    template_file = template_name + ".yaml.in"
    template_path = Path(__file__).parent.parent / "settings" / template_file
    template = template_path.read_text()
    settings = template.format(**kwargs)
    settings_path = tmp_path / "gafaelfawr.yaml"
    settings_path.write_text(settings)
    return settings_path


def store_secret(tmp_path: Path, name: str, secret: bytes) -> Path:
    """Store a secret in a temporary path.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        The root of the temporary area.
    name : `str`
        The name of the secret to construct nice file names.
    secret : `bytes`
        The value of the secret.
    """
    secret_path = tmp_path / name
    secret_path.write_bytes(secret)
    return secret_path


def build_config(
    tmp_path: Path,
    environment: str,
    oidc_clients: Optional[List[OIDCClient]] = None,
    **settings: str,
) -> Path:
    """Generate a test Gafaelfawr configuration.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        The root of the temporary area.
    environment : `str`
        Settings template to use.

    Returns
    -------
    config_path : `pathlib.Path`
        The path of the configuration file.
    """
    session_secret = Fernet.generate_key()
    session_secret_file = store_secret(tmp_path, "session", session_secret)
    issuer_key = RSAKeyPair.generate().private_key_as_pem()
    issuer_key_file = store_secret(tmp_path, "issuer", issuer_key)
    influxdb_secret_file = store_secret(tmp_path, "influxdb", b"influx-secret")
    github_secret_file = store_secret(tmp_path, "github", b"github-secret")
    oidc_secret_file = store_secret(tmp_path, "oidc", b"oidc-secret")

    settings_path = build_settings(
        tmp_path,
        environment,
        session_secret_file=session_secret_file,
        issuer_key_file=issuer_key_file,
        github_secret_file=github_secret_file,
        oidc_secret_file=oidc_secret_file,
        influxdb_secret_file=influxdb_secret_file,
    )

    if oidc_clients:
        oidc_path = tmp_path / "oidc.json"
        clients_data = [
            {"id": c.client_id, "secret": c.client_secret}
            for c in oidc_clients
        ]
        oidc_path.write_text(json.dumps(clients_data))
        settings["oidc_server_secrets_file"] = str(oidc_path)

    if settings:
        with settings_path.open("a") as f:
            for key, value in settings.items():
                f.write(f"{key}: {value}\n")

    return settings_path
