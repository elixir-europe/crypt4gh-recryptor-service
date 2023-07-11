from pathlib import Path
from typing import cast

from crypt4gh_recryptor_service.cert import (generate_uvicorn_ssl_cert_options,
                                             setup_localhost_ssl_cert)
from crypt4gh_recryptor_service.config import (get_settings,
                                               LOCALHOST,
                                               ServerMode,
                                               setup_files,
                                               UserSettings)
from crypt4gh_recryptor_service.crypt import crypt4gh_generate_keypair
from crypt4gh_recryptor_service.util import run_in_subprocess
import typer

app = typer.Typer()


def _setup_and_run(server_mode: ServerMode):
    setup_files(server_mode)
    settings = get_settings(server_mode)

    if settings.host == LOCALHOST:
        setup_localhost_ssl_cert(settings)

    uvicorn_ssl_options = generate_uvicorn_ssl_cert_options(settings)

    if server_mode == ServerMode.USER:
        settings = cast(UserSettings, settings)
        keypair_paths = [settings.user_private_key_path, settings.user_public_key_path]
        if all(not key_path.exists() for key_path in keypair_paths):
            print('User key pair files do not exist. Generating new keypair...')

            private_key, public_key = keypair_paths
            crypt4gh_generate_keypair(
                Path(private_key),
                Path(public_key),
                settings.private_key_passphrase,
                settings.private_key_comment,
                verbose=settings.dev_mode)
        for key_path in keypair_paths:
            if not key_path.exists():
                raise ValueError(f'User key file "{key_path}" is missing!')

    run_in_subprocess(
        f'uvicorn --host {settings.host} --port {settings.port} '
        f'{uvicorn_ssl_options}{"--reload " if settings.dev_mode else ""}'
        f'--app-dir {Path(__file__).parent} {server_mode.value}:app',
        verbose=settings.dev_mode)


@app.command()
def user():
    """Runs crypt4gh-recryptor-service in user mode"""
    _setup_and_run(ServerMode.USER)


@app.command()
def compute():
    """Runs crypt4gh-recryptor-service in compute mode"""
    _setup_and_run(ServerMode.COMPUTE)


if __name__ == '__main__':
    app()
