import asyncio
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


async def async_run_in_subprocess(cmd: str, verbose: bool = False, capture_output: bool = False):
    if verbose:
        print('-' * 26)
        print(f'Running `{cmd}`:')
        print('-' * 26)
        print()

    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE if capture_output else None, stderr=None)

    stdout, stderr = await proc.communicate()

    if proc.returncode:
        raise RuntimeError(f'[{cmd!r} exited with {proc.returncode}]')

    if capture_output:
        return stdout.decode()


def ensure_dirs(dir_path: Path):
    if not dir_path.exists():
        dir_path.mkdir(mode=0o700, parents=True)
