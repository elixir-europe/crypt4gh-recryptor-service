from pathlib import Path
import re

from crypt4gh_recryptor_service.storage import HeaderFile
from crypt4gh_recryptor_service.util import async_run_in_subprocess
from fastapi import HTTPException


async def crypt4gh_recrypt_header(in_header_file: HeaderFile,
                                  decryption_key_path: Path,
                                  encryption_key_path: Path,
                                  verbose: bool):
    headers_dir = in_header_file.path.parent
    out_header_file = HeaderFile(headers_dir)

    try:
        await async_run_in_subprocess(
            f'crypt4gh-recryptor recrypt '
            f'--encryption-key {encryption_key_path} '
            f'-i {in_header_file.path} '
            f'-o {out_header_file.path} '
            f'--decryption-key {decryption_key_path}',
            verbose=verbose)
    except RuntimeError as e:
        if re.search(r'exited with\s+1\]', str(e)) is None:
            raise
        raise HTTPException(status_code=422, detail='Malformed or undecryptable crypt4gh_header') from e

    out_header_file.read_from_storage()
    return out_header_file


async def crypt4gh_generate_keypair(private_key_path: Path,
                                    public_key_path: Path,
                                    passphrase: str,
                                    comment: str,
                                    verbose: bool = False):
    await async_run_in_subprocess(
        f'crypt4gh-recryptor generate-keypair'
        f' --private {private_key_path}'
        f' --public {public_key_path}' + (f' --passphrase "{passphrase}"' if passphrase else '') +
        (f' --comment "{comment}"' if comment else ''),
        verbose=verbose)
