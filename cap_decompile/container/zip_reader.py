"""Bounded ZIP reads with an unambiguous, validated member index."""
from collections.abc import Callable, Iterable
from contextlib import contextmanager
from dataclasses import dataclass, fields
import os
from pathlib import Path
import zipfile
import zlib


@dataclass(frozen=True)
class ZipLimits:
    """Analysis policy, not limits imposed by the Java Card specification."""
    max_archive_bytes: int = 16 * 1024 * 1024
    max_members: int = 1024
    max_member_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 16 * 1024 * 1024

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value < 1:
                raise ValueError(f'{field.name} must be a positive integer')


class ZipReader:
    def __init__(self, path: Path, *, limits: ZipLimits | None = None):
        self.path = Path(path)
        if limits is not None and not isinstance(limits, ZipLimits):
            raise TypeError('limits must be ZipLimits or None')
        self.limits = ZipLimits() if limits is None else limits

    @staticmethod
    def _validate_name(info: zipfile.ZipInfo) -> None:
        name = info.filename
        # ZipInfo may truncate at NUL or normalize platform separators. Such
        # aliases must not become indistinguishable entries in our dictionary.
        if info.orig_filename != name or '\\' in name or '\x00' in name:
            raise ValueError(f'Non-canonical ZIP member name: {info.orig_filename!r}')
        parts = (name[:-1] if info.is_dir() else name).split('/')
        if any(part in ('', '.', '..') for part in parts) or ':' in parts[0]:
            raise ValueError(f'Non-canonical ZIP member name: {name!r}')

    def _index(self, archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
        infos = archive.infolist()
        if len(infos) > self.limits.max_members:
            raise ValueError(f'ZIP member count exceeds max_members={self.limits.max_members}')
        index, total = {}, 0
        for info in infos:
            self._validate_name(info)
            name = info.filename
            if name in index:
                raise ValueError(f'Duplicate ZIP member: {name!r}')
            if info.flag_bits & 1:
                raise ValueError(f'Encrypted ZIP member is unsupported: {name!r}')
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ValueError(f'Unsupported ZIP compression {info.compress_type} for {name!r}')
            if info.file_size > self.limits.max_member_bytes:
                raise ValueError(f'ZIP member {name!r} exceeds max_member_bytes={self.limits.max_member_bytes}')
            total += info.file_size
            if total > self.limits.max_total_bytes:
                raise ValueError(f'ZIP total size exceeds max_total_bytes={self.limits.max_total_bytes}')
            index[name] = info
        return index

    @contextmanager
    def _open_index(self):
        try:
            # Check the opened file, not a path stat followed by another open.
            with self.path.open('rb') as raw:
                if os.fstat(raw.fileno()).st_size > self.limits.max_archive_bytes:
                    raise ValueError(f'ZIP file exceeds max_archive_bytes={self.limits.max_archive_bytes}')
                with zipfile.ZipFile(raw, 'r') as archive:
                    yield archive, self._index(archive)
        except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, RuntimeError, zlib.error) as exc:
            raise ValueError(f'Invalid or unreadable ZIP archive: {exc}') from exc

    def _read_member(self, archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
        limit = min(info.file_size, self.limits.max_member_bytes)
        data = bytearray()
        with archive.open(info, 'r') as stream:
            while True:
                # The extra byte detects a stream exceeding its declared size.
                chunk = stream.read(min(64 * 1024, limit - len(data) + 1))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise ValueError(f'ZIP member exceeds declared/allowed size: {info.filename!r}')
        if len(data) != info.file_size:
            raise ValueError(f'ZIP member size mismatch: {info.filename!r}')
        return bytes(data)

    def list_files(self) -> list[str]:
        with self._open_index() as (_, index):
            return list(index)

    def read_selected(self, selector: Callable[[tuple[str, ...]], Iterable[str]]) -> dict[str, bytes]:
        """Select by validated full names before opening any member payload.

        The index and payloads belong to one open archive. Limits apply to all
        entries, including those omitted by selector. No filesystem extraction.
        """
        with self._open_index() as (archive, index):
            names = tuple(selector(tuple(index)))
            if len(set(names)) != len(names):
                raise ValueError('ZIP selection contains duplicate member names')
            infos = [index[name] for name in names]  # Validate the entire selection first.
            return {info.filename: self._read_member(archive, info) for info in infos}

    def read_file(self, name: str) -> bytes:
        return self.read_selected(lambda _: (name,))[name]

    def read_all(self) -> dict[str, bytes]:
        """Compatibility API; reads all members under the same bounds policy."""
        return self.read_selected(lambda names: names)
