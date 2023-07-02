import subprocess
from pathlib import Path

import typer

from crypt4gh_recryptor_service.config import get_settings, setup_files, ServerMode, LOCALHOST

app = typer.Typer()

def run_in_subprocess(cmd: str):
    print('-' * 26)
    print(f'Running `{cmd}`:')
    print('-' * 26)
    print()
    subprocess.run(cmd, shell=True, check=True)


def _setup_and_run(server_mode: ServerMode):
    setup_files(server_mode)
    settings = get_settings(server_mode)

    if settings.host == LOCALHOST:
        run_in_subprocess('mkcert -install')

        if not (settings.localhost_certfile_path.exists() and settings.localhost_keyfile_path.exists()):
            run_in_subprocess(f'mkcert -cert-file {settings.localhost_certfile_path} '
                              f'-key-file {settings.localhost_keyfile_path} '
                              f'{LOCALHOST}')

        settings.localhost_certfile_path.chmod(mode=0o600)
        settings.localhost_keyfile_path.chmod(mode=0o600)

        uvicorn_ssl_options = \
            f'--ssl-certfile {settings.localhost_certfile_path} --ssl-keyfile {settings.localhost_keyfile_path} '
    else:
        uvicorn_ssl_options = ''

    run_in_subprocess(f"uvicorn --host {settings.host} --port {settings.port} "
                      f"{uvicorn_ssl_options}{'--reload ' if settings.dev_mode else ''}"
                      f"--app-dir {Path(__file__).parent} {server_mode.value}:app")

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