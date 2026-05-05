from pathlib import Path

from crypt4gh_recryptor_service.util import run_in_subprocess


def generate_uvicorn_ssl_cert_options(settings):
    if settings.use_https:
        return f'--ssl-certfile {settings.certfile_path} ' \
               f'--ssl-keyfile {settings.keyfile_path} '
    else:
        return ''


def setup_ssl_cert(settings):
    run_in_subprocess('mkcert -install', verbose=True)
    certfile_path = settings.certfile_path
    keyfile_path = settings.keyfile_path

    if not (certfile_path.exists() and keyfile_path.exists()):
        run_in_subprocess(
            f'mkcert -cert-file {certfile_path} '
            f'-key-file {keyfile_path} '
            f'{settings.host}',
            verbose=True)

    certfile_path.chmod(mode=0o600)
    keyfile_path.chmod(mode=0o600)
    return certfile_path, keyfile_path


def get_ssl_root_cert_path() -> Path:
    results = run_in_subprocess('mkcert -CAROOT', verbose=True, capture_output=True)
    path = Path(results.stdout.strip(), 'rootCA.pem')
    return path
