import abc
import os
from enum import Enum
from functools import lru_cache, partial
from pathlib import Path

import yaml
from dotenv import dotenv_values
from pydantic import BaseSettings
from pydantic.env_settings import SettingsSourceCallable


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
    return working_dir.joinpath(Path(DEFAULT_YML_CONFIG_FILENAME))


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

    @property
    @abc.abstractmethod
    def working_dir(self) -> Path:
        pass

    @property
    def yml_config_file_path(self) -> Path:
        return _get_yml_config_file_path(self.working_dir)


class UserSettings(Settings):
    server_mode: ServerMode = ServerMode.USER
    port: int = DEFAULT_PORT_USER

    @property
    def working_dir(self) -> Path:
        return _get_working_dir(ServerMode.USER)

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


@lru_cache()
def get_settings(server_mode: ServerMode):
    if server_mode == ServerMode.USER:
        return UserSettings()
    else:
        return ComputeSettings()


def yml_config_setting(settings: Settings) -> dict[str]:
    with open(settings.yml_config_file_path) as f:
        ret = yaml.safe_load(f)
        if ret:
            return ret
        return {}


def setup_files(server_mode: ServerMode):
    working_dir = _get_working_dir(server_mode)
    yml_config_file_path = _get_yml_config_file_path(working_dir)

    if not os.path.exists(yml_config_file_path):
        if not os.path.exists(working_dir):
            os.makedirs(working_dir)
        with open(yml_config_file_path, 'w') as f:
            f.write("")

    settings = get_settings(server_mode).dict()
    with open(yml_config_file_path, 'w') as f:
        yaml.safe_dump(settings, f)
