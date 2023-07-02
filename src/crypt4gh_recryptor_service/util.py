import subprocess


def run_in_subprocess(cmd: str):
    print('-' * 26)
    print(f'Running `{cmd}`:')
    print('-' * 26)
    print()
    subprocess.run(cmd, shell=True, check=True)
