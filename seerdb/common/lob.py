# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Represents an Oracle LOB (CLOB / NCLOB / BLOB / BFILE) value returned by a
# SELECT. The raw locator the server emits in RXD is exactly what it expects
# back in a TTI_LOBOPS round-trip (verified by diffing against sqlplus's
# LOBOPS request locator), so we keep it verbatim and hand it back as the
# source pointer when reading.
#
# The locator's fixed metadata overhead is 102 bytes on Oracle 11g; for
# LOBs whose content fits inside the locator's inline budget the content
# is woven into the same block and we could pluck it out without a round-
# trip. We don't bother — going through TTI_LOBOPS works for inline and
# out-of-line content uniformly and is simpler.
#
# BFILE locators have a different layout (43+ bytes carrying the directory
# name and filename in plain ASCII) and require an explicit FILEOPEN before
# READ. We read them natively over TTI_LOBOPS — FILE_OPEN -> READ ->
# FILE_CLOSE (#46, OracleConnect.bfile_read_native) — using the open-flagged
# locator the server returns from FILE_OPEN.

from seerdb.common.tns_consts import (
    TNS_TYPE_BFILE,
    TNS_TYPE_BLOB,
    TNS_TYPE_CLOB,
    TNS_TYPE_JSON,
    TNS_TYPE_VECTOR,
)

# Column types whose value is delivered as a LOB locator but decoded from the
# fetched binary image into a Python object (not returned as a LOB).
_DECODED_IMAGE_TYPES = (TNS_TYPE_JSON, TNS_TYPE_VECTOR)

# Types that stay a LOB object even when the connection asks for values
# (`fetch_lobs=False`). A BFILE names a file on the SERVER's filesystem and has
# no inline value: reading it opens that file, which is a question for
# fileexists() / read(), not for the fetch. Materialising one made selecting a
# BFILE whose directory does not exist fail with ORA-22285 at the fetch, where
# python-oracledb hands back the locator (#1101).
_EXTERNAL_LOB_TYPES = (TNS_TYPE_BFILE,)

# Where a BFILE locator's two names begin, counted from the start of `raw` --
# so it spans raw's own ub2 inner length and the 14 fixed bytes behind it.
# Everything before it is the server's header and is never rebuilt; see
# LOB.setfilename.
_BFILE_NAMES_OFFSET = 16

_LOCATOR_OVERHEAD = 102

# The mode a LOB OPEN carries in its amount field. Measured against a live 23ai:
# 1 (read-only) and 2 (read-write) are accepted, 0 and 11 are refused with
# ORA-64219 "invalid LOB locator encountered" (#964, PROTOCOL.md 14.6).
_LOB_OPEN_READ_ONLY = 1
_LOB_OPEN_READ_WRITE = 2


def _check_write_value(is_character: bool, value: object, offset: object) -> None:
    # A CLOB takes str and a BLOB bytes; the reference driver raises TypeError
    # for the wrong one rather than coercing, and its suite pins that.
    if is_character and not isinstance(value, str):
        raise TypeError('a CLOB is written from str, not bytes')
    if not is_character and not isinstance(value, (bytes, bytearray)):
        raise TypeError('a BLOB is written from bytes, not str')
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise TypeError('offset must be an int')


def _check_read_range(offset: int, amount: int | None) -> None:
    # oracledb's codes, so a caller sees the same failure it would there.
    from seerdb.common.exceptions import InterfaceError

    if not isinstance(offset, int) or isinstance(offset, bool):
        raise TypeError('offset must be an int')
    if offset < 1:
        raise InterfaceError('DPY-2030: LOB offset must be greater than zero')
    if amount is not None:
        if not isinstance(amount, int) or isinstance(amount, bool):
            raise TypeError('amount must be an int')
        if amount < 1:
            raise InterfaceError('DPY-2047: LOB amount must be greater than zero')


class LOB:
    __slots__ = (
        'data_type',
        'raw',
        '_connection',
        '_prefetched',
        '_is_open',
        '_temp',
        '_csfrm',
        'charset',
    )

    def __init__(
        self,
        data_type: int,
        raw: bytes,
        connection=None,
        prefetched=None,
        *,
        temp: bool = False,
        csfrm: int = 1,
        charset: int | None = None,
    ):
        # `data_type` is the column's TNS data type code (112 CLOB, 113 BLOB,
        # 114 BFILE; NCLOB shares 112 + a national charset form). `raw` is
        # the locator block from RXD — same bytes go back to the server for
        # TTI_LOBOPS. `connection` is the OracleConnect used to round-trip
        # in `read()`; `Cursor.execute` injects it after fetching rows.
        #
        # `prefetched` is the value's image when the server already sent it in
        # the row (a JSON or VECTOR column in the prefetched framing, §22.1b):
        # there is nothing to fetch, and asking would be answered with whatever
        # the locator resolves to -- nothing, in the Mirror's case (#959).
        self.data_type = data_type
        self.raw = bytes(raw)
        self._connection = connection
        # A 9i CLOB's content travels in its column's database charset, not the
        # UTF-16 the 10g+ path uses, so a 9i LOB keeps it for its reads and
        # writes (#2259). None elsewhere.
        self.charset = charset
        self._prefetched = None if prefetched is None else bytes(prefetched)
        # Whether open() was called through this object and not yet closed. The
        # server owns the real state -- a second open answers ORA-22293 and a
        # second close ORA-22289 -- so this only reports what we did.
        self._is_open = False
        # A temp LOB this client made (connection.createlob, #1066) rather than
        # one a query returned. Only a temp LOB can be bound back as it stands:
        # it binds as the temp-LOB locator bind, captured byte for byte against
        # python-oracledb. Its `raw` is the locator INCLUDING the ub2 the
        # CREATE_TEMP reply framed it in -- the form every LOBOPS call on it
        # expects (lobops-locator rule, PROTOCOL.md 14.4d).
        self._temp = temp
        # The charset form: 2 for an NCLOB, 1 for a CLOB, meaningless for a
        # BLOB. An NCLOB is a CLOB (type 112) that differs only here.
        self._csfrm = csfrm

    @property
    def is_binary(self) -> bool:
        return self.data_type in (TNS_TYPE_BLOB, TNS_TYPE_BFILE)

    @property
    def is_character(self) -> bool:
        return self.data_type == TNS_TYPE_CLOB

    @property
    def is_file(self) -> bool:
        return self.data_type == TNS_TYPE_BFILE

    @property
    def directory_name(self) -> str | None:
        # BFILE only: the DIRECTORY object name from the locator. Returns
        # None for non-BFILE LOBs and for malformed BFILE locators.
        parts = self._parse_bfile_locator()
        return parts[0] if parts else None

    @property
    def filename(self) -> str | None:
        # BFILE only: the filename portion of the locator.
        parts = self._parse_bfile_locator()
        return parts[1] if parts else None

    def _parse_bfile_locator(self) -> tuple[str, str] | None:
        # BFILE locator wire format (43+ bytes):
        #   ub2 BE  inner_length      offset 0..1
        #   16 bytes  flags / metadata
        #   ub1     dir_name_length   offset 17
        #   N bytes dir_name (ASCII)
        #   ub1 0x00
        #   ub1     filename_length
        #   M bytes filename (ASCII)
        # Anchored by parsing the two length-prefixed ASCII strings.
        if not self.is_file or len(self.raw) < 19:
            return None
        try:
            DirLen = self.raw[17]
            DirStart = 18
            DirEnd = DirStart + DirLen
            if DirEnd + 1 >= len(self.raw):
                return None
            Directory = self.raw[DirStart:DirEnd].decode('ascii')
            # next byte is a 0x00 separator, then the filename length
            FileLen = self.raw[DirEnd + 1]
            FileStart = DirEnd + 2
            FileEnd = FileStart + FileLen
            if FileEnd > len(self.raw):
                return None
            Filename = self.raw[FileStart:FileEnd].decode('ascii')
            return (Directory, Filename)
        except (UnicodeDecodeError, IndexError):
            return None

    @property
    def content_size(self) -> int:
        # Size of the inline content section for *regular* CLOB / BLOB
        # locators. Always 0 for BFILE and temporary-LOB locators (those
        # are shorter than the regular 102-byte overhead and don't carry
        # inline content — their content lives server-side and only
        # comes back via the TTI_LOBOPS round-trip).
        if len(self.raw) <= _LOCATOR_OVERHEAD:
            return 0
        return len(self.raw) - _LOCATOR_OVERHEAD

    def read(self, offset: int = 1, amount: int | None = None) -> object:
        # Sync read. Returns str/bytes for a CLOB/BLOB but the decoded value
        # (e.g. dict/list) for a JSON/VECTOR image LOB, hence `object` for now
        # (to be narrowed later). See `aread` below for the async equivalent.
        #
        # `offset` is 1-based and `amount` counts CHARACTERS for a CLOB / NCLOB
        # and bytes for a BLOB / BFILE, as every LOB call does (#964).
        if self.data_type in _DECODED_IMAGE_TYPES:
            return self._decode_image(self._fetch_content())
        _check_read_range(offset, amount)
        if len(self.raw) == _LOCATOR_OVERHEAD:
            return '' if self.is_character else b''
        if self._connection is None:
            from seerdb.common.exceptions import InterfaceError

            raise InterfaceError('LOB has no connection to read from')
        if self.is_file:
            return self._connection.bfile_read_native(self.raw)
        return self._connection.lob_read(
            self.raw, self.data_type, offset=offset, amount=amount, **self._charset()
        )

    def size(self) -> int:
        """The LOB's length — characters for a CLOB / NCLOB, bytes for a BLOB."""
        from seerdb.common.tns_consts import TNS_LOB_OP_GET_LENGTH

        return self._operation(TNS_LOB_OP_GET_LENGTH) or 0

    def getchunksize(self) -> int:
        """The server's chunk size for this LOB, for sizing reads and writes."""
        from seerdb.common.tns_consts import TNS_LOB_OP_GET_CHUNK_SIZE

        return self._operation(TNS_LOB_OP_GET_CHUNK_SIZE) or 0

    def write(self, value: str | bytes, offset: int = 1) -> None:
        """Write ``value`` at ``offset`` (1-based), extending the LOB if needed.

        Oracle requires the LOB's ROW to be locked first — a value fetched
        without `SELECT ... FOR UPDATE` in an open transaction answers
        ORA-22920 rather than writing (#964)."""
        _check_write_value(self.is_character, value, offset)
        self._refresh(
            self._require_mutable().lob_write(
                self.raw,
                value,
                is_blob=not self.is_character,
                offset=offset,
                **self._charset(),
            )
        )

    def trim(self, new_size: int = 0) -> None:
        """Shorten the LOB to ``new_size``. Needs the row locked, like write()."""
        if not isinstance(new_size, int) or isinstance(new_size, bool):
            raise TypeError('new_size must be an int')
        from seerdb.common.tns_consts import TNS_LOB_OP_TRIM

        self._require_mutable()
        self._operation(TNS_LOB_OP_TRIM, new_size)

    def open(self) -> None:
        """Open the LOB for read-write. A second open answers ORA-22293."""
        from seerdb.common.tns_consts import TNS_LOB_OP_OPEN

        self._operation(TNS_LOB_OP_OPEN, _LOB_OPEN_READ_WRITE)
        self._is_open = True

    def close(self) -> None:
        """Close the LOB. Closing one that is not open answers ORA-22289."""
        from seerdb.common.tns_consts import TNS_LOB_OP_CLOSE

        self._operation(TNS_LOB_OP_CLOSE)
        self._is_open = False

    def isopen(self) -> bool:
        """Whether this LOB was opened through this object and not yet closed."""
        return self._is_open

    def _require_file(self, what: str):
        # The three BFILE calls below are meaningless on a CLOB / BLOB, and the
        # reference client refuses them there rather than answering something
        # (DPY-3026). A BFILE is the only external LOB: its bytes live in a
        # server-side DIRECTORY, so it is the only one with a file name at all.
        if not self.is_file:
            from seerdb.common.exceptions import NotSupportedError

            raise NotSupportedError(f'{what} is only supported on a BFILE')

    def getfilename(self) -> tuple[str, str]:
        """The ``(directory, filename)`` pair this BFILE names (#1109).

        Both come out of the locator itself -- the server is not asked -- which
        is why this answers for a file that does not exist, and for a DIRECTORY
        that was never created.
        """
        self._require_file('getfilename()')
        parts = self._parse_bfile_locator()
        if parts is None:
            from seerdb.common.exceptions import InterfaceError

            raise InterfaceError('this BFILE locator carries no file name')
        return parts

    def setfilename(self, directory: str, filename: str) -> None:
        """Point this BFILE at ``directory``/``filename`` (#1109).

        Local: nothing is sent. Whether either name exists is only settled when
        the file is asked about -- ``fileexists()`` or a read.

        Only the NAMES are replaced. The 16 bytes in front of them are the
        server's own locator header and are kept verbatim: a locator built from
        scratch is answered ``ORA-22275: invalid LOB locator specified``, because
        what makes a locator valid is that the server minted it. Each name rides
        behind a ub2 length (the same bytes ``_parse_bfile_locator`` reads as a
        zero separator plus a ub1, which is all a name under 256 bytes needs).
        """
        self._require_file('setfilename()')
        Dir = directory.encode('ascii')
        File = filename.encode('ascii')
        if len(Dir) > 0xFFFF or len(File) > 0xFFFF:
            from seerdb.common.exceptions import DataError

            raise DataError('a BFILE directory or file name is too long')
        # `raw` opens with the ub2 length of everything after it, so the header
        # to keep is that prefix plus the 16 fixed bytes, and the prefix is
        # recomputed for the new names.
        Body = (
            self.raw[2:_BFILE_NAMES_OFFSET]
            + len(Dir).to_bytes(2, 'big')
            + Dir
            + len(File).to_bytes(2, 'big')
            + File
        )
        self.raw = len(Body).to_bytes(2, 'big') + Body

    def fileexists(self) -> bool:
        """Whether the file this BFILE names is there (#1109).

        One ``TTI_LOBOPS`` round-trip (``FILE_EXISTS``). A *directory* that does
        not exist is not a False -- the server raises ORA-22285 for it, and that
        reaches the caller, because "there is no such alias" and "the file is
        missing" are different answers.
        """
        self._require_file('fileexists()')
        from seerdb.common.tns_consts import TNS_LOB_OP_FILE_EXISTS

        return bool(self._operation(TNS_LOB_OP_FILE_EXISTS))

    def _require_connection(self):
        if self._connection is None:
            from seerdb.common.exceptions import InterfaceError

            raise InterfaceError('LOB has no connection to operate on')
        return self._connection

    def _require_mutable(self):
        # Writing a PERSISTENT LOB locator is 11g and up. Measured on every
        # tier: the ub2-prefixed locator form a temp LOB uses is answered
        # ORA-22275 everywhere, and the bare form that 11g / 21c / 23ai accept
        # makes 10g DROP THE CONNECTION outright -- taking the row lock with it,
        # so the next statement then fails ORA-00054. Refusing up front is the
        # only honest option until 10g's form is found (#964).
        from seerdb.common.exceptions import NotSupportedError
        from seerdb.common.tns_consts import FIELD_VERSION_11_2

        conn = self._require_connection()
        native = getattr(conn, 'dialect_serves_lobs', None)
        if native is not None and native():
            return conn  # 9i writes through its own LOBOPS form (#2259)
        if getattr(conn, 'field_version', FIELD_VERSION_11_2) < FIELD_VERSION_11_2:
            raise NotSupportedError(
                'modifying a LOB needs Oracle 11g or later; on 10g the server '
                'closes the connection on a persistent-LOB write'
            )
        return conn

    def _charset(self) -> dict:
        # A 9i LOB's column charset for the connection's read and write, which
        # carry its text in it (#2259); nothing for any other LOB. A national
        # LOB's text is AL16UTF16 whatever the column says, and an NCLOB
        # attribute of an object has no column at all to say it (#2258).
        if self._csfrm == 2 and self.is_character:
            from seerdb.common.tns_consts import AL16UTF16_CHARSET

            return {'charset': AL16UTF16_CHARSET}
        return {} if self.charset is None else {'charset': self.charset}

    def _operation(self, operation: int, amount: int = 0) -> int | None:
        (value, locator) = self._require_connection().lob_operation(
            self.raw, operation, amount
        )
        self._refresh(locator)
        return value

    def _refresh(self, locator: bytes | None) -> None:
        # Every LOB call answers with the locator as the server now sees it, and
        # a mutating one really does change it. Keeping the original meant the
        # next read was served the PRE-write value, so a write looked like it
        # had silently done nothing (#964).
        #
        # The two forms differ by a header: a locator taken from a ROW carries a
        # 2-byte length prefix that the one in a reply does not (measured on
        # 23ai: reply == row[2:]). Adopting the reply's bytes as-is therefore
        # produced a locator the next call refused with ORA-22275, so the prefix
        # is put back when the original had one.
        from seerdb.common.tns import is_prefixed_locator, prefixed_locator

        if not locator:
            return
        self.raw = (
            prefixed_locator(locator)
            if is_prefixed_locator(self.raw)
            else bytes(locator)
        )

    def _fetch_content(self) -> bytes:
        # Fetch the raw locator content over TTI_LOBOPS (the OSON image for a
        # JSON column). Shared by the sync read() path.
        if self._prefetched is not None:
            return self._prefetched
        if self._connection is None:
            from seerdb.common.exceptions import InterfaceError

            raise InterfaceError('LOB has no connection to read from')
        return self._connection.lob_read(self.raw, self.data_type)

    def _decode_image(self, content: bytes) -> object:
        # A native JSON (#30) or VECTOR (#55) column comes back as a binary
        # image over the LOB locator path; decode it to a Python value.
        # lob_read returns bytes for these non-CLOB types.
        if self.data_type == TNS_TYPE_JSON:
            from seerdb.common.oson import decode_oson

            return decode_oson(content)
        from seerdb.common.vector import decode_vector

        return decode_vector(content)

    async def aread(self, offset: int = 1, amount: int | None = None) -> object:
        """Async equivalent of `read()`. Use this when the LOB came
        out of an `AsyncCursor`; the `_connection` attached to it is
        an `AsyncOracleConnect` whose `lob_read` / `bfile_read` are
        coroutines."""
        if self.data_type not in _DECODED_IMAGE_TYPES:
            _check_read_range(offset, amount)
        if self.data_type in _DECODED_IMAGE_TYPES:
            if self._prefetched is not None:
                return self._decode_image(self._prefetched)
            if self._connection is None:
                from seerdb.common.exceptions import InterfaceError

                raise InterfaceError('LOB has no connection to read from')
            content = await self._connection.lob_read(self.raw, self.data_type)
            return self._decode_image(content)
        if len(self.raw) == _LOCATOR_OVERHEAD:
            return '' if self.is_character else b''
        if self._connection is None:
            from seerdb.common.exceptions import InterfaceError

            raise InterfaceError('LOB has no connection to read from')
        if self.is_file:
            return await self._connection.bfile_read_native(self.raw)
        return await self._connection.lob_read(
            self.raw, self.data_type, offset=offset, amount=amount, **self._charset()
        )

    async def asize(self) -> int:
        """Async equivalent of :meth:`size`."""
        from seerdb.common.tns_consts import TNS_LOB_OP_GET_LENGTH

        return await self._aoperation(TNS_LOB_OP_GET_LENGTH) or 0

    async def agetchunksize(self) -> int:
        """Async equivalent of :meth:`getchunksize`."""
        from seerdb.common.tns_consts import TNS_LOB_OP_GET_CHUNK_SIZE

        return await self._aoperation(TNS_LOB_OP_GET_CHUNK_SIZE) or 0

    async def awrite(self, value: str | bytes, offset: int = 1) -> None:
        """Async equivalent of :meth:`write`."""
        _check_write_value(self.is_character, value, offset)
        self._refresh(
            await self._require_mutable().lob_write(
                self.raw,
                value,
                is_blob=not self.is_character,
                offset=offset,
                **self._charset(),
            )
        )

    async def atrim(self, new_size: int = 0) -> None:
        """Async equivalent of :meth:`trim`."""
        if not isinstance(new_size, int) or isinstance(new_size, bool):
            raise TypeError('new_size must be an int')
        from seerdb.common.tns_consts import TNS_LOB_OP_TRIM

        self._require_mutable()
        await self._aoperation(TNS_LOB_OP_TRIM, new_size)

    async def aopen(self) -> None:
        """Async equivalent of :meth:`open`."""
        from seerdb.common.tns_consts import TNS_LOB_OP_OPEN

        await self._aoperation(TNS_LOB_OP_OPEN, _LOB_OPEN_READ_WRITE)
        self._is_open = True

    async def aclose(self) -> None:
        """Async equivalent of :meth:`close`."""
        from seerdb.common.tns_consts import TNS_LOB_OP_CLOSE

        await self._aoperation(TNS_LOB_OP_CLOSE)
        self._is_open = False

    async def afileexists(self) -> bool:
        """Async equivalent of :meth:`fileexists`."""
        self._require_file('fileexists()')
        from seerdb.common.tns_consts import TNS_LOB_OP_FILE_EXISTS

        return bool(await self._aoperation(TNS_LOB_OP_FILE_EXISTS))

    async def _aoperation(self, operation: int, amount: int = 0) -> int | None:
        (value, locator) = await self._require_connection().lob_operation(
            self.raw, operation, amount
        )
        self._refresh(locator)
        return value

    def __repr__(self) -> str:
        Kind = (
            'BLOB'
            if self.is_binary
            else ('CLOB' if self.is_character else f'LOB(type={self.data_type})')
        )
        return f'<{Kind} {len(self.raw)}B>'

    def __len__(self) -> int:
        return len(self.raw)

    def __eq__(self, other) -> bool:
        if not isinstance(other, LOB):
            return NotImplemented
        return self.data_type == other.data_type and self.raw == other.raw

    def __hash__(self) -> int:
        return hash((self.data_type, self.raw))
