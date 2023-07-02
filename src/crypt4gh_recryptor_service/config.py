import abc
from enum import Enum
from functools import lru_cache
import os
from pathlib import Path
from typing import Union

from dotenv import dotenv_values
from pydantic import BaseSettings
from pydantic.env_settings import SettingsSourceCallable
import yaml

VERSION = '0.1.0'

ENV_PREFIX = 'C4GH_RECRYPTOR_'
ENV_FILE = '.env'
LOCALHOST = 'localhost'

DEFAULT_WORKING_DIR_USER = 'c4gh_recryptor_user'
DEFAULT_WORKING_DIR_COMPUTE = 'c4gh_recryptor_compute'
DEFAULT_YML_CONFIG_FILENAME = 'c4gh_config.yml'
DEFAULT_HOST = LOCALHOST
DEFAULT_PORT_USER = 61357
DEFAULT_PORT_COMPUTE = 61358
DEFAULT_SSL_CERTFILE = 'localhost.pem'
DEFAULT_SSL_KEYFILE = 'localhost-key.pem'

USER_KEYS_DIR = 'user_keys'
COMPUTE_KEYS_DIR = 'compute_keys'
CERT_DIR = 'certs'


class ServerMode(str, Enum):
    USER = 'user'
    COMPUTE = 'compute'


def _get_working_dir(server_mode: ServerMode) -> Path:
    default_working_dir_attr = f'DEFAULT_WORKING_DIR_{server_mode.value.upper()}'
    if env_working_dir := dotenv_values().get(default_working_dir_attr):
        return Path(env_working_dir)
    else:
        return Path.cwd().joinpath(Path(globals()[default_working_dir_attr]))


def _get_yml_config_file_path(working_dir: Path) -> Path:
    return Path(working_dir, DEFAULT_YML_CONFIG_FILENAME)


class BaseConfig:
    env_file = ENV_FILE
    env_prefix = ENV_PREFIX
    use_enum_values = True

    @classmethod
    def customise_sources(
        cls,
        init_settings: SettingsSourceCallable,
        env_settings: SettingsSourceCallable,
        file_secret_settings: SettingsSourceCallable,
    ) -> tuple[SettingsSourceCallable, ...]:
        # Add load from yml file, change priority and remove file secret option
        return env_settings, yml_config_setting


class Settings(BaseSettings):
    host: str = DEFAULT_HOST
    port: int
    server_mode: ServerMode
    ssl_certfile = DEFAULT_SSL_CERTFILE
    ssl_keyfile = DEFAULT_SSL_KEYFILE
    dev_mode: bool = False

    @property
    @abc.abstractmethod
    def working_dir(self) -> Path:
        pass

    @property
    def yml_config_file_path(self) -> Path:
        return _get_yml_config_file_path(self.working_dir)

    @property
    def compute_keys_dir(self) -> Path:
        return Path(self.working_dir, COMPUTE_KEYS_DIR)

    @property
    def cert_dir(self) -> Path:
        return Path(self.working_dir, CERT_DIR)

    @property
    def localhost_certfile_path(self) -> Path:
        return Path(self.cert_dir, self.ssl_certfile)

    @property
    def localhost_keyfile_path(self) -> Path:
        return Path(self.cert_dir, self.ssl_keyfile)


class UserSettings(Settings):
    server_mode: ServerMode = ServerMode.USER
    port: int = DEFAULT_PORT_USER

    @property
    def working_dir(self) -> Path:
        return _get_working_dir(ServerMode.USER)

    @property
    def user_keys_dir(self) -> Path:
        return Path(self.working_dir, USER_KEYS_DIR)

    class Config(BaseConfig):
        pass


class ComputeSettings(Settings):
    server_mode: ServerMode = ServerMode.COMPUTE
    port: int = DEFAULT_PORT_COMPUTE

    @property
    def working_dir(self) -> Path:
        return _get_working_dir(ServerMode.COMPUTE)

    class Config(BaseConfig):
        pass


@lru_cache
def get_user_settings() -> UserSettings:
    return UserSettings()


@lru_cache
def get_compute_settings() -> ComputeSettings:
    return ComputeSettings()


def get_settings(server_mode: ServerMode) -> Union[UserSettings, ComputeSettings]:
    if server_mode == ServerMode.USER:
        return get_user_settings()
    else:
        return get_compute_settings()


def yml_config_setting(settings: Settings) -> dict[str]:
    with open(settings.yml_config_file_path) as f:
        ret = yaml.safe_load(f)
        if ret:
            return ret
        return {}


def _ensure_dirs(dir_path: Path):
    if not dir_path.exists():
        dir_path.mkdir(mode=0o700, parents=True)


def setup_files(server_mode: ServerMode):
    working_dir = _get_working_dir(server_mode)
    yml_config_file_path = _get_yml_config_file_path(working_dir)

    _ensure_dirs(working_dir)
    if server_mode == ServerMode.USER:
        _ensure_dirs(Path(working_dir, USER_KEYS_DIR))
    _ensure_dirs(Path(working_dir, COMPUTE_KEYS_DIR))
    _ensure_dirs(Path(working_dir, CERT_DIR))

    if not os.path.exists(yml_config_file_path):
        with open(yml_config_file_path, 'w') as f:
            f.write('')
        yml_config_file_path.chmod(mode=0o600)

    settings = get_settings(server_mode).dict()
    with open(yml_config_file_path, 'w') as f:
        yaml.safe_dump(settings, f)
