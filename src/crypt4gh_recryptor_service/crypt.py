from pathlib import Path
from subprocess import CalledProcessError

from crypt4gh_recryptor_service.storage import HashedStrFile, HeaderFile
from crypt4gh_recryptor_service.util import run_in_subprocess
from fastapi import HTTPException


async def crypt4gh_recrypt_header(in_header_file: HeaderFile,
                                  compute_key_file: HashedStrFile,
                                  user_private_key_path: Path,
                                  verbose: bool):
    headers_dir = in_header_file.path.parent
    out_header_file = HeaderFile(headers_dir)

    try:
        run_in_subprocess(
            f'crypt4gh-recryptor recrypt '
            f'--encryption-key {compute_key_file.path} '
            f'-i {in_header_file.path} '
            f'-o {out_header_file.path} '
            f'--decryption-key {user_private_key_path}',
            verbose=verbose)
    except CalledProcessError as e:
        if e.returncode == 1:
            raise HTTPException(
                status_code=406,
                detail='The key header was not able to decode the header. '
                'Please make sure that the encrypted header is '
                "decryptable by the user's private key") from e
        else:
            raise e

    out_header_file.read_from_storage()
    return out_header_file


def crypt4gh_generate_keypair(private_key_path: Path,
                              public_key_path: Path,
                              passphrase: str,
                              comment: str,
                              verbose: bool = False):
    run_in_subprocess(
        f'crypt4gh-recryptor generate-keypair'
        f' --private {private_key_path}'
        f' --public {public_key_path}' + (f' --passphrase "{passphrase}"' if passphrase else '') +
        (f' --comment "{comment}"' if comment else ''),
        verbose=verbose)
