from pathlib import Path
import subprocess


def run_in_subprocess(cmd: str, verbose: bool = False, capture_output: bool = False):
    if verbose:
        print('-' * 26)
        print(f'Running `{cmd}`:')
        print('-' * 26)
        print()
    return subprocess.run(
        cmd,
        shell=True,
        check=True,
        capture_output=True if capture_output else False,
        text=True if capture_output else False)


def ensure_dirs(dir_path: Path):
    if not dir_path.exists():
        dir_path.mkdir(mode=0o700, parents=True)


def generate_keypair(private_key, public_key, passphrase, comment, verbose: bool = False):
    run_in_subprocess(
        f'crypt4gh-recryptor generate-keypair'
        f' --private {private_key}'
        f' --public {public_key}' + (f' --passphrase "{passphrase}"' if passphrase else '') +
        (f' --comment "{comment}"' if comment else ''),
        verbose=verbose)
