from abc import abstractmethod
from base64 import b64decode, b64encode
from hashlib import sha256
from pathlib import Path
import tempfile
from typing import Generic, Optional, TypeVar

T = TypeVar('T', bytes, str)


class HashedFile(Generic[T]):
    def __init__(self, dir: Path, contents: Optional[T] = None):
        self._dir: Path = dir
        self._contents: Optional[bytes] = self._to_bytes(contents) if contents else None
        self._filename: str = self.sha256 if self._contents else tempfile.mktemp(dir=self._dir)

    @classmethod
    def _to_bytes(cls, contents: T) -> bytes:
        assert isinstance(contents, bytes)
        return contents

    @property
    @abstractmethod
    def contents(self) -> T:
        ...

    @property
    def sha256(self):
        return sha256(self._contents).hexdigest()

    @property
    def path(self) -> Path:
        return self._dir.joinpath(self._filename)

    def write_to_storage(self):
        assert self._contents is not None
        with open(self.path, 'wb') as hashed_file:
            hashed_file.write(self._contents)
        self.path.chmod(mode=0o600)

    def read_from_storage(self):
        with open(self.path, 'rb') as hashed_file:
            self._contents = hashed_file.read()
            if self._filename != self.sha256:
                self.path.rename(self._dir.joinpath(self.sha256))


class HashedBytesFile(HashedFile[bytes]):
    @property
    def contents(self) -> bytes:
        assert self._contents is not None
        return self._contents


class HashedStrFile(HashedFile[str]):
    @classmethod
    def _to_bytes(cls, contents: str) -> bytes:
        return contents.encode('utf8')

    @property
    def contents(self) -> str:
        assert self._contents is not None
        return self._contents.decode('utf8')


class HeaderFile(HashedFile[str]):
    @classmethod
    def _to_bytes(cls, contents: str) -> bytes:
        return b64decode(contents)

    @property
    def contents(self) -> str:
        assert self._contents is not None
        return b64encode(self._contents).decode('ascii')
