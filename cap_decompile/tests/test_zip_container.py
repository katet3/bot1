"""D-10: reject ambiguous archives before payload reads; bound selected I/O."""
import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from cap_decompile.container.cap_container import CAPContainer
from cap_decompile.container.zip_reader import ZipLimits, ZipReader
from cap_decompile.tests.library_fixture import library_components
from main import load_cap


PROJECT = Path(__file__).resolve().parents[2]


def entries_for(parts, directory='pkg/javacard'):
    return [(directory + '/' + name, data) for name, data in parts.items()]


def write_zip(path, entries, compression=zipfile.ZIP_STORED):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)  # Deliberately duplicated test entries.
        with zipfile.ZipFile(path, 'w', compression=compression) as archive:
            for name, data in entries:
                archive.writestr(name, data)


def corrupt_member(path, name):
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo(name)
    data = bytearray(path.read_bytes())
    name_len, extra_len = struct.unpack_from('<HH', data, info.header_offset + 26)
    start = info.header_offset + 30 + name_len + extra_len
    data[start] ^= 0x01
    path.write_bytes(data)


class ZipReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'input.zip'

    def test_list_and_read_apis_preserve_exact_bytes_and_empty_files(self):
        entries = [('pkg/', b''), ('pkg/a', b'abc'), ('pkg/empty', b'')]
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(compression=compression):
                write_zip(self.path, entries, compression)
                reader = ZipReader(self.path)
                with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
                    self.assertEqual(reader.list_files(), [name for name, _ in entries])
                self.assertEqual(reader.read_file('pkg/a'), b'abc')
                self.assertEqual(reader.read_all(), dict(entries))

    def test_selection_reads_only_requested_members_using_one_archive(self):
        write_zip(self.path, [('wanted', b'yes'), ('unused', b'no'), ('also_wanted', b'yes too')])
        seen = []
        original = zipfile.ZipFile.open
        def track(archive, info, *args, **kwargs):
            self.assertIsInstance(info, zipfile.ZipInfo)
            seen.append((id(archive), info.filename))
            return original(archive, info, *args, **kwargs)
        with patch.object(zipfile.ZipFile, 'open', track):
            result = ZipReader(self.path).read_selected(lambda names: (names[0], names[2]))
        self.assertEqual(result, {'wanted': b'yes', 'also_wanted': b'yes too'})
        self.assertEqual([name for _, name in seen], ['wanted', 'also_wanted'])
        self.assertEqual(len({identity for identity, _ in seen}), 1)

    def test_missing_or_duplicate_selection_is_rejected_before_payload(self):
        write_zip(self.path, [('a', b'yes')])
        with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
            with self.assertRaises(KeyError):
                ZipReader(self.path).read_file('absent')
            with self.assertRaises(KeyError):
                ZipReader(self.path).read_selected(lambda _: ('a', 'absent'))
            with self.assertRaisesRegex(ValueError, 'duplicate member names'):
                ZipReader(self.path).read_selected(lambda _: ('a', 'a'))

    def test_duplicate_full_names_are_rejected_by_every_public_read_api(self):
        write_zip(self.path, [('a', b'first'), ('a', b'second')])
        reader = ZipReader(self.path)
        for call in (reader.list_files, reader.read_all, lambda: reader.read_file('a')):
            with self.subTest(call=call):
                with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
                    with self.assertRaisesRegex(ValueError, 'Duplicate ZIP member'):
                        call()

    def test_noncanonical_names_are_not_normalized_into_aliases(self):
        names = ('/pkg/a', 'pkg//a', './pkg/a', 'pkg/../a', 'pkg/./a',
                 'C:/pkg/a', 'pkg\\a', 'pkg/a\x00suffix', '/')
        for name in names:
            with self.subTest(name=name):
                # Patch both filename records after writing, so a Windows writer
                # cannot sanitize the malformed test input before we read it.
                placeholder = 'x' * len(name.encode('utf-8'))
                write_zip(self.path, [(placeholder, b'payload')])
                raw = self.path.read_bytes()
                self.assertEqual(raw.count(placeholder.encode()), 2)
                self.path.write_bytes(raw.replace(placeholder.encode(), name.encode()))
                with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
                    with self.assertRaisesRegex(ValueError, 'Non-canonical ZIP member'):
                        ZipReader(self.path).read_all()

    def test_physical_size_limit_is_checked_before_constructing_zipfile(self):
        write_zip(self.path, [('a', b'abc')])
        size = self.path.stat().st_size
        self.assertEqual(ZipReader(self.path, limits=ZipLimits(max_archive_bytes=size)).read_file('a'), b'abc')
        with patch.object(zipfile, 'ZipFile', side_effect=AssertionError('catalog read')):
            with self.assertRaisesRegex(ValueError, 'max_archive_bytes'):
                ZipReader(self.path, limits=ZipLimits(max_archive_bytes=size - 1)).list_files()

    def test_member_count_limit_includes_directory_entries(self):
        write_zip(self.path, [('pkg/', b''), ('pkg/a', b'1'), ('pkg/b', b'2')])
        self.assertEqual(len(ZipReader(self.path, limits=ZipLimits(max_members=3)).list_files()), 3)
        with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
            with self.assertRaisesRegex(ValueError, 'max_members'):
                ZipReader(self.path, limits=ZipLimits(max_members=2)).read_file('pkg/a')

    def test_member_limit_applies_to_unselected_compressed_entries(self):
        write_zip(self.path, [('a', b'ok'), ('unused', b'0' * 4096)], zipfile.ZIP_DEFLATED)
        self.assertEqual(ZipReader(self.path, limits=ZipLimits(max_member_bytes=4096)).read_file('a'), b'ok')
        with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
            with self.assertRaisesRegex(ValueError, 'max_member_bytes'):
                ZipReader(self.path, limits=ZipLimits(max_member_bytes=4095)).read_file('a')

    def test_total_limit_counts_the_whole_archive_before_selection(self):
        write_zip(self.path, [('a', b'123'), ('b', b'456')])
        self.assertEqual(len(ZipReader(self.path, limits=ZipLimits(max_total_bytes=6)).read_all()), 2)
        with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
            with self.assertRaisesRegex(ValueError, 'max_total_bytes'):
                ZipReader(self.path, limits=ZipLimits(max_total_bytes=5)).read_file('a')

    def test_limit_parameters_cannot_disable_checks_implicitly(self):
        for field in ('max_archive_bytes', 'max_members', 'max_member_bytes', 'max_total_bytes'):
            for value in (0, -1, False, True, 1.5, None, '10'):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(ValueError, field):
                        ZipLimits(**{field: value})
        with self.assertRaises(TypeError):
            ZipReader(self.path, limits={})

    def test_encrypted_member_is_rejected_before_payload(self):
        write_zip(self.path, [('a', b'abc')])
        raw = bytearray(self.path.read_bytes())
        central = raw.index(b'PK\x01\x02')
        raw[6] |= 1  # Local header flags.
        raw[central + 8] |= 1  # Central directory flags.
        self.path.write_bytes(raw)
        with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
            with self.assertRaisesRegex(ValueError, 'Encrypted ZIP member'):
                ZipReader(self.path).read_all()

    def test_unsupported_compression_is_rejected_before_payload(self):
        write_zip(self.path, [('a', b'abc')])
        raw = bytearray(self.path.read_bytes())
        central = raw.index(b'PK\x01\x02')
        struct.pack_into('<H', raw, 8, zipfile.ZIP_BZIP2)
        struct.pack_into('<H', raw, central + 10, zipfile.ZIP_BZIP2)
        self.path.write_bytes(raw)
        with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
            with self.assertRaisesRegex(ValueError, 'Unsupported ZIP compression'):
                ZipReader(self.path).read_all()

    def test_actual_stream_length_is_checked_with_bounded_reads(self):
        write_zip(self.path, [('a', b'12345')])
        for data, message in ((b'123456', 'exceeds declared/allowed'), (b'12', 'size mismatch')):
            with self.subTest(data=data):
                class CheckedStream(io.BytesIO):
                    def read(stream, size=-1):
                        self.assertGreater(size, 0)
                        self.assertLessEqual(size, 64 * 1024)
                        return super().read(size)
                with patch.object(zipfile.ZipFile, 'open', return_value=CheckedStream(data)):
                    with self.assertRaisesRegex(ValueError, message):
                        ZipReader(self.path).read_file('a')

    def test_bad_zip_and_corrupted_member_crc_have_value_error_diagnostics(self):
        self.path.write_bytes(b'not a ZIP archive')
        with self.assertRaisesRegex(ValueError, 'Invalid or unreadable ZIP'):
            ZipReader(self.path).read_all()
        write_zip(self.path, [('a', b'abc')])
        corrupt_member(self.path, 'a')
        with self.assertRaisesRegex(ValueError, 'CRC'):
            ZipReader(self.path).read_all()


class CAPContainerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'input.cap'
        self.parts = library_components()

    def test_one_package_reads_only_direct_cap_components(self):
        entries = entries_for(self.parts) + [('META-INF/MANIFEST.MF', b'manifest'),
                                            ('notes/Header.cap', b'not a component')]
        write_zip(self.path, entries, zipfile.ZIP_DEFLATED)
        original, seen = zipfile.ZipFile.open, []
        def track(archive, info, *args, **kwargs):
            seen.append(info.filename)
            return original(archive, info, *args, **kwargs)
        container = CAPContainer(self.path)
        with patch.object(zipfile.ZipFile, 'open', track):
            container.load()
        self.assertEqual(container.component_directory, 'pkg/javacard')
        self.assertEqual(container.components, self.parts)
        self.assertEqual(set(seen), {name for name, _ in entries_for(self.parts)})

    def test_two_complete_packages_are_rejected_in_either_order(self):
        entries = entries_for(self.parts, 'a/javacard') + entries_for(self.parts, 'b/javacard')
        for members in (entries, list(reversed(entries))):
            write_zip(self.path, members)
            container = CAPContainer(self.path)
            with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
                with self.assertRaisesRegex(ValueError, 'Multiple CAP component directories.*a/javacard, b/javacard'):
                    container.load()
            self.assertEqual(container.components, {})
            self.assertIsNone(container.component_directory)

    def test_two_partial_packages_cannot_supply_each_others_components(self):
        items = list(self.parts.items())
        entries = entries_for(dict(items[:5]), 'a/javacard') + entries_for(dict(items[5:]), 'b/javacard')
        write_zip(self.path, entries)
        with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
            with self.assertRaisesRegex(ValueError, 'Multiple CAP component directories'):
                CAPContainer(self.path).load()

    def test_repeated_header_in_the_same_directory_is_rejected(self):
        write_zip(self.path, entries_for(self.parts) + [('pkg/javacard/Header.cap', b'replacement')])
        with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
            with self.assertRaisesRegex(ValueError, 'Duplicate ZIP member.*Header.cap'):
                CAPContainer(self.path).load()

    def test_nested_components_cannot_alias_direct_children(self):
        write_zip(self.path, entries_for(self.parts) + [('pkg/javacard/nested/Header.cap', b'replacement')])
        with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
            with self.assertRaisesRegex(ValueError, 'directly inside javacard'):
                CAPContainer(self.path).load()

    def test_missing_components_are_detected_before_payload_read(self):
        for entries in ([], [('META-INF/MANIFEST.MF', b'manifest')],
                        [('pkg/javacard/Header.cap', self.parts['Header.cap'])]):
            with self.subTest(entries=entries):
                write_zip(self.path, entries)
                with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
                    with self.assertRaisesRegex(ValueError, 'Missing CAP components:.*Class.cap'):
                        CAPContainer(self.path).load()

    def test_successful_reload_replaces_optional_components_and_directory(self):
        source = CAPContainer(PROJECT / 'examples/name1/name1.cap')
        source.load()
        write_zip(self.path, entries_for(source.components, 'old/javacard'))
        container = CAPContainer(self.path)
        container.load()
        self.assertIsNotNone(container.get_optional_component('Applet.cap'))
        write_zip(self.path, entries_for(self.parts, 'new/javacard'))
        container.load()
        self.assertEqual(container.components, self.parts)
        self.assertEqual(container.component_directory, 'new/javacard')
        self.assertIsNone(container.get_optional_component('Applet.cap'))

    def test_failed_reload_preserves_last_successful_snapshot(self):
        for failure in ('missing', 'crc'):
            with self.subTest(failure=failure):
                write_zip(self.path, entries_for(self.parts))
                container = CAPContainer(self.path)
                container.load()
                previous = container.components
                replacement = dict(self.parts)
                if failure == 'missing':
                    replacement.pop('Header.cap')
                write_zip(self.path, entries_for(replacement, 'new/javacard'))
                if failure == 'crc':
                    corrupt_member(self.path, 'new/javacard/Directory.cap')
                with self.assertRaises(ValueError):
                    container.load()
                self.assertIs(container.components, previous)
                self.assertEqual(container.components, self.parts)
                self.assertEqual(container.component_directory, 'pkg/javacard')

    def test_unused_member_crc_is_not_read_but_its_size_counts_towards_limits(self):
        write_zip(self.path, entries_for(self.parts) + [('unused.bin', b'abc')])
        corrupt_member(self.path, 'unused.bin')
        container = CAPContainer(self.path)
        container.load()  # No accidental decompression of unrelated files.
        total = sum(len(data) for data in self.parts.values()) + 3
        with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
            with self.assertRaisesRegex(ValueError, 'max_total_bytes'):
                CAPContainer(self.path, limits=ZipLimits(max_total_bytes=total - 1)).load()

    def test_root_javacard_directory_and_real_applet_packages_remain_readable(self):
        write_zip(self.path, entries_for(self.parts, 'javacard'))
        cap = load_cap(self.path)
        self.assertIsNone(cap.applet)
        self.assertEqual(len(cap.to_model()), 2)
        for fixture, count in (('examples/name1/name1.cap', 7), ('examples/symdemo/symdemo.cap', 11),
                               ('example_applet/scr/com/example/transactiontest/transaction_test.cap', 4)):
            with self.subTest(fixture=fixture):
                self.assertEqual(len(load_cap(PROJECT / fixture).to_model()), count)

    def test_cli_reports_duplicate_zip_member_without_traceback(self):
        write_zip(self.path, entries_for(self.parts) + [('pkg/javacard/Header.cap', b'replacement')])
        result = subprocess.run(
            [sys.executable, str(PROJECT / 'main.py'), '--cap', str(self.path),
             '--output-root', str(Path(self.tmp.name) / 'outputs'),
             '--no-pysoot', '--no-png', '--quiet'],
            cwd=PROJECT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('Duplicate ZIP member', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse((Path(self.tmp.name) / 'outputs').exists())


if __name__ == '__main__':
    unittest.main()
