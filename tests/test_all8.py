# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The thin OALL8 through its al8i4 array, one schema both sides read (#2773).

The client writes the execute through _ALL8, and the Mirror's parse_exec reads
it back through the same schema, so a field either side gets wrong shows here.
"""

import contextvars
import unittest

from seerdb.common.exceptions import Truncated
from seerdb.common.tns import (
    _ALL8_FROM_THIN,
    _DECODE_FIELD_VERSION,
    _all8_blocks,
    encode_dictionary_exec,
    parse_exec,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_9_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_23_4,
)

SQL = 'SELECT a FROM t'


def _execute(version: int, server_field_version: int | None = None, **query) -> bytes:
    fields = {
        'type': 'select',
        'auto': 0,
        'fetch': 100,
        'server_version': 0x17000000,
        'cursor': 0,
        'query': SQL,
        'bind': [],
        'batch': [],
        'def': [],
        'batcherrors': False,
        'arraydmlrowcounts': False,
        'return_binds': None,
        **query,
    }
    message = {'seq': 3, 'field_version': version, 'query': fields}
    if server_field_version is not None:
        message['server_field_version'] = server_field_version
    return contextvars.copy_context().run(encode_dictionary_exec, message)


def _at(version: int, read, *args):
    # Run a reader at the session's field version, which the token number reads.
    def run():
        _DECODE_FIELD_VERSION.set(version)
        return read(*args)

    return contextvars.copy_context().run(run)


def _parse(version: int, payload: bytes):
    return _at(version, parse_exec, payload)


class TestARegisteredQuery(unittest.TestCase):
    # A query a subscription registers carries the registration id's low word
    # and al8regid_msb (#2460). The Mirror passed over them as five fixed
    # bytes, which only a zero registration takes, and read the SQL from the
    # wrong place.
    def test_the_mirror_reads_its_sql(self):
        for registration in (7, 0x123456789):
            with self.subTest(registration=registration):
                payload = _execute(FIELD_VERSION_23_4, registration_id=registration)
                self.assertEqual(_parse(FIELD_VERSION_23_4, payload).sql, SQL)

    def test_the_registration_reads_back_in_its_two_words(self):
        payload = _execute(FIELD_VERSION_23_4, registration_id=0x123456789)
        given = _all8_blocks(FIELD_VERSION_23_4, server_92=False, server_10=False)
        (head, _rest) = _at(FIELD_VERSION_23_4, _ALL8_FROM_THIN, payload, given)
        self.assertEqual(
            (head['registration_id_msb'], head['registration_id']), (1, 0x23456789)
        )


class TestTheBlocksByVersion(unittest.TestCase):
    def test_9_2_reads_the_sql_straight_after_the_define_count(self):
        # 9.2 answers 10g's block ORA-03120 (#2768): no registration, no al8blv.
        at_92 = _execute(
            FIELD_VERSION_11_2, FIELD_VERSION_9_2, server_version=0x09200000
        )
        at_11 = _execute(FIELD_VERSION_11_2, server_version=0x0B200000)
        self.assertEqual(len(at_11) - len(at_92), 8)

    def test_a_10_x_server_reads_no_al8blv(self):
        at_10 = _execute(FIELD_VERSION_11_2, server_version=0x0A200000)
        at_11 = _execute(FIELD_VERSION_11_2, server_version=0x0B200000)
        self.assertEqual(len(at_11) - len(at_10), 5)

    def test_12_1_adds_the_row_count_block_and_frames_the_sql(self):
        at_11 = _execute(FIELD_VERSION_11_2)
        at_12 = _execute(FIELD_VERSION_12_1)
        # Three bytes of al8pidmlrc, and the SQL's length byte.
        self.assertEqual(len(at_12) - len(at_11), 4)
        self.assertEqual(_parse(FIELD_VERSION_12_1, at_12).sql, SQL)
        self.assertEqual(_parse(FIELD_VERSION_11_2, at_11).sql, SQL)


class TestACutExecute(unittest.TestCase):
    def test_is_truncated_so_the_session_reads_on(self):
        for version in (FIELD_VERSION_11_2, FIELD_VERSION_12_1, FIELD_VERSION_23_4):
            payload = _execute(version)
            for cut in range(3, len(payload)):
                with self.subTest(version=version, cut=cut):
                    with self.assertRaises(Truncated):
                        _parse(version, payload[:cut])


if __name__ == '__main__':
    unittest.main()
