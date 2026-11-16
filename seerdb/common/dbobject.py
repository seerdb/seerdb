# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# SQL OBJECT (ADT) value support (#115).
#
# Decoding a SQL object column is two-phase (mirrors python-oracledb's
# base.pyx _process_column_data -> read_dbobject):
#   1. DESCRIBE gives the column's type identity (owner + name, captured in the
#      DCB by seerdb.common.tns). The ordered attribute layout is fetched separately
#      from the data dictionary (ALL_TYPE_ATTRS) and cached per connection.
#   2. ROW: the wire value carries a small framing wrapper plus a packed
#      "image"; the image is the attributes serialised length-prefixed in
#      declaration order behind a short header.
#
# This module owns the image walk (decode_object_image) and the surfaced
# Python value (DbObject). The wire-framing wrapper is read in seerdb.common.tns
# (which hands us an ObjectImage placeholder); the layout fetch lives on the
# connection. Read-only here -- binding an object is #116, and VARRAY / nested
# table / REF are #117 / #118 / #119.

# Defer annotation evaluation (PEP 563): DbRef defines a `bytes` property that
# shadows the builtin inside the class body, so an eagerly-evaluated annotation
# like `-> bytes | None` on a later method would fail on Python < 3.14 with
# "unsupported operand type(s) for |: 'property' and 'NoneType'".
from __future__ import annotations

import bisect
import builtins
import re
from collections.abc import Callable

from seerdb.common.exceptions import NotSupportedError, ProgrammingError
from seerdb.common.tns_consts import (
    AL16UTF16_CHARSET,
    AL32UTF8_CHARSET,
    TNS_LONG_LENGTH_INDICATOR,
    TNS_MAX_SHORT_LENGTH,
    TNS_NULL_LENGTH_INDICATOR,
    TNS_TYPE_ADT,
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_BLOB,
    TNS_TYPE_BOOLEAN,
    TNS_TYPE_CHAR,
    TNS_TYPE_CLOB,
    TNS_TYPE_DATE,
    TNS_TYPE_INT,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_INTERVALYM,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
)

# Object image header flags (python-oracledb constants.pxi "image flags").
_OBJ_IS_DEGENERATE = 0x10  # object stored in a LOB -- not supported here
_OBJ_NO_PREFIX_SEG = 0x04  # no prefix segment precedes the attributes
# The byte that precedes a nested object / collection attribute when it is NULL:
# an "atomic null" (python-oracledb TNS_OBJ_ATOMIC_NULL). A collection also
# accepts the ordinary 0xFF null there. Distinct from a scalar attribute's own
# 0xFF null, so the flat length walk mistook it for a length of 253 and desynced.
_OBJ_ATOMIC_NULL = 0xFD

# Collection kinds (python-oracledb "database object collection types").
COLLECTION_PLSQL_INDEX_TABLE = 1
COLLECTION_NESTED_TABLE = 2
COLLECTION_VARRAY = 3

# The HAS_INDEXES bit in a collection image's flag byte: set for a PL/SQL
# associative array, whose elements are each prefixed with an int32 key (#888).
_COLL_HAS_INDEXES = 0x10


# XMLType image flags (#124, python-oracledb constants.pxi).
_XML_TYPE_LOB = 0x0001  # content is a CLOB locator
_XML_TYPE_STRING = 0x0004  # content is an inline string
_XML_TYPE_FLAG_SKIP_NEXT_4 = 0x100000
# Observed only on Oracle 11g XMLType *columns* (CLOB storage): the image holds
# a complex binary structure, not a plain CLOB locator, and the LOBOPS read of
# it returns the wrong bytes. 12c+ (binary XML) and 10g never set this bit, so
# it cleanly marks the one reference-less case (oracledb can't reach 11g) we
# don't support. Inline XML (XMLELEMENT etc.) uses the STRING flag and is fine.
_XML_TYPE_LEGACY_STORAGE = 0x01000000

# Map an ALL_TYPE_ATTRS.attr_type_name to the TNS data type code that
# seerdb.common.types.decode_value understands. The image stores each scalar with the
# same on-wire encoding the column form uses, so the existing scalar decoders
# apply unchanged. Timestamp variants all decode through decode_date (which
# keys on byte length), so collapsing them onto TNS_TYPE_TIMESTAMP is safe.
# A name we don't map (e.g. a nested object type -- #117/#118) yields None, and
# decode_value then returns the attribute's raw bytes rather than desyncing.
_TYPE_NAME_TO_TNS = {
    'VARCHAR2': TNS_TYPE_VARCHAR,
    'NVARCHAR2': TNS_TYPE_VARCHAR,
    'CHAR': TNS_TYPE_CHAR,
    'NCHAR': TNS_TYPE_CHAR,
    'NUMBER': TNS_TYPE_NUMBER,
    'FLOAT': TNS_TYPE_NUMBER,
    # ALL_TYPE_ATTRS reports the NUMBER subtypes by their SQL spelling; they all
    # store as NUMBER in the object image.
    'INTEGER': TNS_TYPE_NUMBER,
    'SMALLINT': TNS_TYPE_NUMBER,
    'REAL': TNS_TYPE_NUMBER,
    'DOUBLE PRECISION': TNS_TYPE_NUMBER,
    'RAW': TNS_TYPE_RAW,
    # A LOB attribute of an object: the image carries a locator (its content is
    # read separately over TTI_LOBOPS), so typing it lets the object walkers tell
    # a LOB attribute from an inline scalar. NCLOB shares CLOB's wire type + a
    # national charset form, exactly as NVARCHAR2 shares VARCHAR2's (#888).
    'CLOB': TNS_TYPE_CLOB,
    'NCLOB': TNS_TYPE_CLOB,
    'BLOB': TNS_TYPE_BLOB,
    'DATE': TNS_TYPE_DATE,
    'TIMESTAMP': TNS_TYPE_TIMESTAMP,
    # ALL_TYPE_ATTRS abbreviates the zone as "TZ", not "TIME ZONE" (as a column
    # describe spells it); map both spellings.
    'TIMESTAMP WITH TZ': TNS_TYPE_TIMESTAMPTZ,
    'TIMESTAMP WITH LOCAL TZ': TNS_TYPE_TIMESTAMPLTZ,
    'TIMESTAMP WITH TIME ZONE': TNS_TYPE_TIMESTAMPTZ,
    'TIMESTAMP WITH LOCAL TIME ZONE': TNS_TYPE_TIMESTAMPLTZ,
    'BINARY_FLOAT': TNS_TYPE_BFLOAT,
    'BINARY_DOUBLE': TNS_TYPE_BDOUBLE,
    'INTERVAL DAY TO SECOND': TNS_TYPE_INTERVALDS,
    'INTERVAL YEAR TO MONTH': TNS_TYPE_INTERVALYM,
    # A BOOLEAN attribute (23ai) or a PL/SQL record's BOOLEAN / PLS_INTEGER /
    # BINARY_INTEGER field (#1607): in an object image each is a ub4, not a
    # NUMBER -- see _IMAGE_INT32_TYPES.
    'BOOLEAN': TNS_TYPE_BOOLEAN,
    'PL/SQL BOOLEAN': TNS_TYPE_BOOLEAN,
    'PL/SQL PLS INTEGER': TNS_TYPE_INT,
    'PL/SQL BINARY INTEGER': TNS_TYPE_INT,
}

# The members an object image carries as a big-endian 32-bit integer, length 4,
# where they are no NUMBER (python-oracledb `_pack_value`): a BOOLEAN, 0 or 1,
# and a PL/SQL integer, signed (#1607).
_IMAGE_INT32_TYPES = frozenset({TNS_TYPE_BOOLEAN, TNS_TYPE_INT})


def decode_image_int32(DataType: int | None, Raw: bytes) -> object:
    """A BOOLEAN or PL/SQL integer member of an object image (#1607)."""
    Value = int.from_bytes(Raw, 'big', signed=True)
    return Value == 1 if DataType == TNS_TYPE_BOOLEAN else Value


def encode_image_int32(Value: int) -> bytes:
    """The length-prefixed form of a BOOLEAN or PL/SQL integer member (#1607)."""
    return b'\x04' + int(Value).to_bytes(4, 'big', signed=True)


def national_charset(character_set_name: str | None) -> int | None:
    """The character set an attribute or element takes in an object image, from
    its CHARACTER_SET_NAME in ALL_TYPE_ATTRS / ALL_COLL_TYPES: AL16UTF16 for
    ``NCHAR_CS``, else None (the session's).

    An NVARCHAR2 / NCHAR value lives in the image in the national character set,
    as it does in a column; read and written as the session's AL32UTF8 it came
    back garbled and went in corrupt (#1433). The character set name says so on
    every version: 10g names such an attribute VARCHAR2 / CHAR, not NVARCHAR2.
    """
    return AL16UTF16_CHARSET if character_set_name == 'NCHAR_CS' else None


def type_name_to_tns(name: str | None) -> int | None:
    """TNS data type code for an ALL_TYPE_ATTRS attribute type name (or None).

    TIMESTAMP / INTERVAL names carry a precision, wherever the name puts it:
    ``TIMESTAMP(6)``, ``TIMESTAMP(6) WITH TIME ZONE`` (as a table column names
    it, #1476), ``INTERVAL DAY(2) TO SECOND(6)``; strip each before the lookup.
    """
    if not name:
        return None
    Key = ' '.join(re.sub(r'\(\s*\d+\s*\)', ' ', name).split())
    return _TYPE_NAME_TO_TNS.get(Key)


class ObjectImage:
    """Placeholder for an object column value carried in a row.

    The row decoder produces this from the wire framing without needing the
    attribute layout (so the row stream stays in sync); the cursor turns it
    into a DbObject once the layout has been fetched.
    """

    __slots__ = (
        'type_oid',
        'type_schema',
        'type_name',
        'charset',
        'image',
        'lob_contents',
    )

    def __init__(self, type_oid, type_schema, type_name, charset, image):
        self.type_oid = type_oid
        self.type_schema = type_schema
        self.type_name = type_name
        self.charset = charset
        self.image = image
        # For an inbound object bind, the content the Mirror served under each LOB
        # locator the image may carry, so the backend can turn a LOB attribute
        # back into an upstream LOB (#888). {locator: (value, is_clob)}; the
        # session fills it, the decoder leaves it empty.
        self.lob_contents: dict[bytes, tuple[object, bool]] = {}

    def served_lob(self, locator: bytes) -> tuple[object, bool] | None:
        """The (content, is_clob) the Mirror served under a LOB attribute's
        locator in this image, or None for one it never served."""
        return served_lob_content(self.lob_contents, locator)


def served_lob_content(
    contents: dict[bytes, tuple[object, bool]], locator: bytes
) -> tuple[object, bool] | None:
    """The (content, is_clob) held for ``locator`` in a map of the LOBs the
    Mirror served (#888), or None.

    The map keys a fetched LOB by the locator it went out as, and a temporary
    LOB by the bare locator CREATE_TEMP minted. A client echoes a temporary
    LOB's locator with the ub2 length it was handed out with (#1260), so the
    locator is tried as it came, then with a leading ub2 that states the rest's
    length removed."""
    entry = contents.get(locator)
    if entry is not None:
        return entry
    if len(locator) >= 2 and int.from_bytes(locator[:2], 'big') == len(locator) - 2:
        return contents.get(locator[2:])
    return None


class DbRef:
    """A REF — an opaque reference to a row object (#119).

    A REF is a pointer to an object instance, not the object itself; to read the
    object, dereference it in SQL (``SELECT DEREF(ref_col) ...``), which yields a
    DbObject (#115). The raw locator bytes are exposed for inspection / equality
    and to bind the REF back (#139); ``type_name`` / ``type_oid`` identify the
    referenced object type when the describe carried them — the bind OAC needs
    the 16-byte OID.
    """

    __slots__ = ('_locator', '_type_name', '_type_schema', '_type_oid')

    def __init__(
        self,
        locator: bytes,
        type_name: str | None = None,
        type_schema: str | None = None,
        type_oid: bytes | None = None,
    ):
        self._locator = bytes(locator)
        self._type_name = type_name
        self._type_schema = type_schema
        self._type_oid = bytes(type_oid) if type_oid else None

    @property
    def bytes(self) -> bytes:
        """The raw REF locator bytes."""
        return self._locator

    @property
    def hex(self) -> str:
        """The locator as a hex string."""
        return self._locator.hex()

    @property
    def type_name(self) -> str | None:
        """The referenced object type name, if known."""
        return self._type_name

    @property
    def type_schema(self) -> str | None:
        """The referenced object type's schema/owner, if known."""
        return self._type_schema

    @property
    def type_oid(self) -> builtins.bytes | None:
        """The referenced object type's 16-byte OID, if the describe carried it
        (needed to bind the REF back, #139)."""
        return self._type_oid

    def __eq__(self, other):
        if not isinstance(other, DbRef):
            return NotImplemented
        return self._locator == other._locator

    def __hash__(self):
        return hash(self._locator)

    def __repr__(self):
        Label = f' {self._type_name}' if self._type_name else ''
        return f'<seerdb.DbRef{Label} {self._locator.hex()}>'


class DbObjectType:
    """A SQL object type handle, returned by ``connection.gettype(name)``.

    Holds what the wire bind needs: the type's owner / name, its 16-byte OID,
    its version, and the ordered attribute layout (each entry
    ``{'name', 'type_name', 'data_type', 'charset'}``). ``newobject()`` builds
    a fresh, settable DbObject of this type ready to bind (#116).

    A DbObjectType can also stand in as a ``cursor.var()`` type, so it exposes the
    minimal DbType surface a Var reads (``tns_type`` / ``default_size`` /
    ``csfrm``). That is how an object / collection OUT bind and a typed-NULL
    object bind carry their type (#888).
    """

    # DbType-like surface so `cursor.var(objtype)` works: an object is TNS type
    # 109, needs no fixed buffer size, and carries no character-set form.
    tns_type = TNS_TYPE_ADT
    default_size = 0
    csfrm = 0

    def __init__(
        self,
        schema,
        name,
        oid,
        version,
        attrs,
        is_collection=False,
        collection_type=None,
        element=None,
        max_elements=0,
        package_name=None,
    ):
        self.schema = schema
        self.name = name
        # The package a PL/SQL package-level type is declared in, None for an
        # ordinary schema-level type (#1030). It is part of the type's identity
        # -- two packages may each declare a UDT_RECORD -- so it rides in
        # full_name, as python-oracledb reports it.
        self.package_name = package_name
        self.oid = oid  # 16-byte type OID (bytes)
        self.version = version
        self.attrs = attrs  # ordered layout (list of dict)
        # Collection types (#117/#118): a single element type instead of named
        # attributes. collection_type is VARRAY (3) / NESTED_TABLE (2).
        self.is_collection = is_collection
        self.collection_type = collection_type
        self.element = element  # one layout dict, or None
        self.max_elements = max_elements
        # The charset an image of the type holds its text in: the database's,
        # which the connection that describes the type sets. The server reads
        # and writes an image's text in it, not the session's: a WE8ISO8859P1
        # database stored an image's UTF-8 'café' as 'cafÃ©'. None: AL32UTF8.
        self.db_charset: int | None = None

    @property
    def full_name(self) -> str:
        Parts = [P for P in (self.schema, self.package_name, self.name) if P]
        return '.'.join(Parts)

    @property
    def attr_names(self) -> list:
        return [A['name'] for A in self.attrs]

    @property
    def attributes(self) -> 'list[DbObjectAttr]':
        """The attributes, in declaration order, as python-oracledb lists them
        (#1490); empty for a collection."""
        return [_object_attr(A) for A in self.attrs]

    @property
    def element_type(self):
        """A collection's element type: a ``DB_TYPE_*``, or the
        :class:`DbObjectType` of an object or collection element; None for a
        type that is no collection (#1490)."""
        if not self.is_collection or not self.element:
            return None
        return _attr_type(self.element)

    @property
    def iscollection(self) -> bool:
        """Whether this is a collection type, as python-oracledb names it."""
        return bool(self.is_collection)

    def __call__(self, value=None) -> 'DbObject':
        """A new object of this type: ``newobject()``, as python-oracledb lets a
        type be called (#1490)."""
        return self.newobject(value)

    def newobject(self, values=None, keys: list[int] | None = None) -> 'DbObject':
        """A new DbObject of this type, ready to bind (#116/#117).

        For an object type every attribute starts NULL; seed from ``values`` (a
        dict, or a sequence in declaration order). For a collection type
        ``values`` is the element sequence (default empty). Set object
        attributes by name (``obj.STREET = '...'``) or collection elements by
        index / ``append`` before binding.

        ``keys`` carries an associative array's element keys, for rebuilding one
        that came off the wire; a locally built array leaves it None and is
        keyed 1..N (#1053).
        """
        if self.is_collection:
            return DbObject(
                self.full_name, elements=list(values or []), dbtype=self, keys=keys
            )
        Obj = DbObject(
            self.full_name, [(A['name'], None) for A in self.attrs], dbtype=self
        )
        if isinstance(values, dict):
            # Oracle identifiers are upper-cased unless quoted, so accept seed
            # keys in any case (direct obj.ATTR access stays exact).
            ByUpper = {A['name'].upper(): A['name'] for A in self.attrs}
            for Key, Val in values.items():
                Obj[ByUpper.get(Key.upper(), Key)] = Val
        elif values is not None:
            for Name, Val in zip(self.attr_names, values):
                Obj[Name] = Val
        return Obj

    def __repr__(self):
        Kind = 'collection ' if self.is_collection else ''
        return f'<seerdb.DbObjectType {Kind}{self.full_name}>'


class DbObject:
    """A SQL OBJECT (ADT) value.

    Attributes are read and set by name (``obj.STREET``) or item
    (``obj['STREET']``), in the order Oracle declared them. A fetched object is
    typically read; one built via ``DbObjectType.newobject()`` carries its type
    (``_dbtype``) so it can be bound (#116). oracledb-compatible enough for the
    common ``cursor.fetchone()`` / bind use.
    """

    def __init__(
        self,
        type_name: str | None,
        attrs: list[tuple[str, object]] | None = None,
        elements: list | None = None,
        dbtype: 'DbObjectType | None' = None,
        keys: list[int] | None = None,
    ):
        # _ prefixes keep the namespace clear of attribute names; __setattr__
        # routes any non-underscore name into _attrs. A collection object holds
        # an ordered element list instead of named attributes (#117/#118).
        IsCollection = elements is not None or (
            dbtype is not None and dbtype.is_collection
        )
        object.__setattr__(self, '_type_name', type_name)
        object.__setattr__(self, '_dbtype', dbtype)
        object.__setattr__(self, '_is_collection', IsCollection)
        object.__setattr__(
            self, '_elements', list(elements or []) if IsCollection else None
        )
        # An associative array's element keys, parallel to _elements and in the
        # same (sorted-key) order; None for a VARRAY / nested table, which has
        # no keys at all. Kept beside the list rather than replacing it so
        # aslist() / len() / [i] / append() keep meaning what they mean (#1053).
        #
        # An index-by table built locally gets keys 0..N-1 rather than None, so
        # it goes out under real keys like any other. Zero-based because that is
        # where PL/SQL written for these arrays starts -- `for i in 0..count-1`
        # is the ordinary idiom, and a 1-based array makes `a(0)` raise
        # NO_DATA_FOUND (#1055).
        Keyed = IsCollection and (
            keys is not None
            or (
                dbtype is not None
                and dbtype.collection_type == COLLECTION_PLSQL_INDEX_TABLE
            )
        )
        if not Keyed:
            object.__setattr__(self, '_keys', None)
        elif keys is not None:
            object.__setattr__(self, '_keys', list(keys))
        else:
            object.__setattr__(self, '_keys', list(range(len(self._elements or []))))
        object.__setattr__(self, '_attrs', {} if IsCollection else dict(attrs or []))
        object.__setattr__(
            self, '_order', [] if IsCollection else [Name for Name, _ in (attrs or [])]
        )

    @property
    def type_name(self) -> str | None:
        return self._type_name

    @property
    def is_collection(self) -> bool:
        return self._is_collection

    def __getattr__(self, name: str):
        try:
            return object.__getattribute__(self, '_attrs')[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name: str, value):
        if name.startswith('_'):
            object.__setattr__(self, name, value)
            return
        Attrs = object.__getattribute__(self, '_attrs')
        if name not in Attrs:
            raise AttributeError(
                f'{self._type_name or "object"} has no attribute {name!r}'
            )
        Attrs[name] = value

    def __getitem__(self, key):
        if self._is_collection:
            return self._elements[key]
        return self._attrs[key]

    def __setitem__(self, key, value):
        if self._is_collection:
            self._elements[key] = value
            return
        if key not in self._attrs:
            raise KeyError(key)
        self._attrs[key] = value

    def __len__(self):
        return len(self._elements) if self._is_collection else len(self._order)

    def __iter__(self):
        return iter(self._elements if self._is_collection else self._order)

    def append(self, value) -> None:
        """Append an element (collection types only)."""
        if not self._is_collection:
            raise TypeError('append is only valid on a collection object')
        self._elements.append(value)
        self._key_appended()

    def extend(self, values) -> None:
        """Append several elements (collection types only)."""
        if not self._is_collection:
            raise TypeError('extend is only valid on a collection object')
        Before = len(self._elements)
        self._elements.extend(values)
        for _ in range(len(self._elements) - Before):
            self._key_appended()

    def _key_appended(self) -> None:
        # Keep _keys parallel to _elements when a keyed collection grows; without
        # this the two lists drift apart and the encoder pairs a value with some
        # other element's key. The new key follows the highest, and the FIRST one
        # is 0 -- PL/SQL written for these arrays indexes from zero, so a 1-based
        # array makes `a(0)` raise NO_DATA_FOUND (#1055).
        if self._keys is None:
            return
        self._keys.append(max(self._keys) + 1 if self._keys else 0)

    def aslist(self) -> list:
        """The collection elements, or an object's attribute values in order."""
        if self._is_collection:
            return list(self._elements)
        return [self._attrs[Name] for Name in self._order]

    def asdict(self) -> dict:
        """An index -> value mapping for a collection, name -> value otherwise.

        For an associative array the keys are the PL/SQL ones, so this is the
        view that survives a ``delete()`` -- ``aslist()`` renumbers nothing but
        also says nothing about which key a value sits at (#1035).
        """
        if self._is_collection:
            return {Key: Value for (Key, Value) in zip(self._indices(), self._elements)}
        return dict(self._attrs)

    # --- collection index access (#1035) ------------------------------------
    #
    # An "index" here is what PL/SQL calls it: an associative array's own key,
    # which may be sparse and negative, and for a VARRAY / nested table the
    # 0-based position. The two live in one API because that is how
    # python-oracledb surfaces them, and code that walks a collection with
    # first()/next() then works on either kind.

    def _ensure_collection(self, What: str) -> None:
        if not self._is_collection:
            raise TypeError(f'{What} is only valid on a collection object')

    def _indices(self) -> list[int]:
        # The valid indices in order: an associative array's keys, or 0..N-1.
        if self._keys is not None:
            return self._keys
        return list(range(len(self._elements)))

    def _position_of(self, Index: int) -> int | None:
        # Where `Index` sits in _elements, or None if there is no such element.
        if self._keys is None:
            return Index if 0 <= Index < len(self._elements) else None
        try:
            return self._keys.index(Index)
        except ValueError:
            return None

    def first(self) -> int | None:
        """The lowest index in the collection, or None if it is empty."""
        self._ensure_collection('first')
        Indices = self._indices()
        return Indices[0] if Indices else None

    def last(self) -> int | None:
        """The highest index in the collection, or None if it is empty."""
        self._ensure_collection('last')
        Indices = self._indices()
        return Indices[-1] if Indices else None

    def next(self, index: int) -> int | None:
        """The index following ``index``, or None if there is none."""
        self._ensure_collection('next')
        return next((I for I in self._indices() if I > index), None)

    def prev(self, index: int) -> int | None:
        """The index preceding ``index``, or None if there is none."""
        self._ensure_collection('prev')
        return next((I for I in reversed(self._indices()) if I < index), None)

    def exists(self, index: int) -> bool:
        """Whether an element exists at ``index``."""
        self._ensure_collection('exists')
        return self._position_of(index) is not None

    def getelement(self, index: int):
        """The element at ``index``; raises if there is none."""
        self._ensure_collection('getelement')
        Position = self._position_of(index)
        if Position is None:
            raise ProgrammingError(f'DPY-2038: element at index {index} does not exist')
        return self._elements[Position]

    def setelement(self, index: int, value) -> None:
        """Set the element at ``index``.

        On an associative array an unused key CREATES an element, keeping the
        keys sorted -- that is what `a(k) := v` does in PL/SQL. A VARRAY /
        nested table has no such thing, so an out-of-range index is an error.
        """
        self._ensure_collection('setelement')
        Position = self._position_of(index)
        if Position is not None:
            self._elements[Position] = value
            return
        if self._keys is None:
            Max = max(len(self._elements) - 1, 0)
            raise ProgrammingError(
                f'DPY-2039: given index {index} must be in the range of 0 to {Max}'
            )
        At = bisect.bisect_left(self._keys, index)
        self._keys.insert(At, index)
        self._elements.insert(At, value)

    def delete(self, index: int) -> None:
        """Remove the element at ``index``.

        On an associative array this leaves a HOLE: the surviving elements keep
        their own keys rather than shifting down. On a VARRAY / nested table,
        whose index *is* the position, the later elements do shift.
        """
        self._ensure_collection('delete')
        Position = self._position_of(index)
        if Position is None:
            raise ProgrammingError(f'DPY-2038: element at index {index} does not exist')
        del self._elements[Position]
        if self._keys is not None:
            del self._keys[Position]

    def size(self) -> int:
        """The number of elements in the collection."""
        self._ensure_collection('size')
        return len(self._elements)

    def __eq__(self, other):
        if not isinstance(other, DbObject):
            return NotImplemented
        if self._is_collection or other._is_collection:
            return (
                self._type_name == other._type_name
                and self._is_collection == other._is_collection
                and self._elements == other._elements
            )
        return self._type_name == other._type_name and self._attrs == other._attrs

    def __repr__(self):
        Name = self._type_name or 'OBJECT'
        if self._is_collection:
            return f'<seerdb.DbObject {Name}{self._elements!r}>'
        Body = ', '.join(f'{N}={self._attrs[N]!r}' for N in self._order)
        return f'<seerdb.DbObject {Name}({Body})>'


def _read_length(Image: bytes, Pos: int) -> tuple[int | None, int]:
    # One attribute / segment length: a single byte, unless it is the long
    # indicator (then a 4-byte big-endian length follows) or the NULL marker.
    Length = Image[Pos]
    Pos += 1
    if Length == TNS_NULL_LENGTH_INDICATOR:  # NULL attribute, no bytes follow
        return (None, Pos)
    if Length == TNS_LONG_LENGTH_INDICATOR:  # next 4 bytes are a big-endian length
        Length = int.from_bytes(Image[Pos : Pos + 4], 'big')
        Pos += 4
    return (Length, Pos)


def _read_image_header(Image: bytes, Pos: int = 0) -> int:
    # Mirrors python-oracledb DbObjectPickleBuffer.read_header: flags + version,
    # the (skipped) image length, then -- unless the NO_PREFIX_SEG flag is set
    # -- a prefix segment that is read and skipped. Returns the offset of the
    # first attribute. ``Pos`` lets a nested object / collection image be read
    # inline, in the middle of its parent's image.
    Flags = Image[Pos]
    Pos += 2  # flags + version
    (_, Pos) = _read_length(Image, Pos)  # image length (unused here)
    if Flags & _OBJ_IS_DEGENERATE:
        raise NotSupportedError('decoding an object stored in a LOB is not supported')
    if not (Flags & _OBJ_NO_PREFIX_SEG):
        (PrefixLen, Pos) = _read_length(Image, Pos)
        Pos += PrefixLen or 0
    return Pos


def decode_object_image(
    Image: bytes, Layout: list[dict], Charset: int = AL32UTF8_CHARSET
) -> list[tuple[str, object]]:
    """Walk an object image into a list of (attr_name, value) pairs.

    ``Layout`` is the ordered attribute list from the data dictionary; each entry
    is ``{'name', 'data_type', 'charset'}``, plus ``'object_type'`` (a nested
    ``DbObjectType``) for an attribute that is itself an object or a collection.
    A nested attribute is decoded recursively into a ``DbObject``; a nested value
    that is atomically NULL is ``None`` (#117/#118).
    """
    Attrs, _ = _decode_object_attrs(Image, 0, Layout, Charset, header=True)
    return Attrs


def _decode_object_attrs(
    Image: bytes, Pos: int, Layout: list[dict], Charset: int, *, header: bool
) -> tuple[list[tuple[str, object]], int]:
    # The image header (flags / version / length / prefix seg) precedes only a
    # self-contained image. A nested object *attribute* embeds its attributes
    # inline with no header of its own, so ``header`` is False there.
    if header:
        Pos = _read_image_header(Image, Pos)
    Attrs: list[tuple[str, object]] = []
    for Attr in Layout:
        (Value, Pos) = _decode_member(Image, Pos, Attr, Charset, in_collection=False)
        Attrs.append((Attr['name'], Value))
    return Attrs, Pos


def _decode_member(
    Image: bytes, Pos: int, Attr: dict, Charset: int, *, in_collection: bool
) -> tuple[object, int]:
    # One attribute (or collection element). How a nested value is framed depends
    # on where it sits (python-oracledb `_pack_value`):
    #   * an object ATTRIBUTE of an object -> its attributes inline, no header;
    #   * a collection attribute, or ANY nested value inside a collection ->
    #     a length-prefixed full image (with its own header);
    #   * a scalar -> a length-prefixed value.
    # A NULL nested object is the atomic-null 0xFD; a NULL collection is 0xFF.
    Nested = Attr.get('object_type')
    if Nested is not None and is_xml_type(Nested):
        # An XMLType attribute rides as a length-prefixed XMLType image, not the
        # inline attributes a normal nested object uses; a NULL is the 0xFF marker
        # (#124). A large (CLOB-backed) document is left to decode_xmltype.
        (Length, Pos) = _read_length(Image, Pos)
        if Length is None:
            return (None, Pos)
        (_is_lob, Value) = decode_xmltype(bytes(Image[Pos : Pos + Length]), Charset)
        return (Value, Pos + Length)
    if Nested is not None and Nested.is_collection:
        if Image[Pos] in (TNS_NULL_LENGTH_INDICATOR, _OBJ_ATOMIC_NULL):
            return (None, Pos + 1)
        (Length, Pos) = _read_length(Image, Pos)
        Sub = bytes(Image[Pos : Pos + (Length or 0)])
        Pos += Length or 0
        (Elements, Keys) = decode_collection_keyed(Sub, Nested.element or {}, Charset)
        return (
            DbObject(Nested.full_name, elements=Elements, dbtype=Nested, keys=Keys),
            Pos,
        )
    if Nested is not None:
        if Image[Pos] == _OBJ_ATOMIC_NULL:
            return (None, Pos + 1)
        if in_collection:
            # A length-prefixed full object image (its own header included).
            (Length, Pos) = _read_length(Image, Pos)
            Sub = bytes(Image[Pos : Pos + (Length or 0)])
            Pos += Length or 0
            SubAttrs = decode_object_image(Sub, Nested.attrs, Charset)
            return (DbObject(Nested.full_name, SubAttrs, dbtype=Nested), Pos)
        # An object attribute of an object: its attributes inline, no header.
        SubAttrs, Pos = _decode_object_attrs(
            Image, Pos, Nested.attrs, Charset, header=False
        )
        return (DbObject(Nested.full_name, SubAttrs, dbtype=Nested), Pos)
    # A scalar (or a LOB, whose locator bytes come back raw for now).
    from seerdb.common.types import decode_value

    (Length, Pos) = _read_length(Image, Pos)
    if Length is None or Length == 0:
        return (None, Pos)
    Raw = bytes(Image[Pos : Pos + Length])
    Pos += Length
    if Attr.get('data_type') in _IMAGE_INT32_TYPES:
        return (decode_image_int32(Attr.get('data_type'), Raw), Pos)
    Col = {
        'data_type': Attr.get('data_type'),
        'charset': Attr.get('charset') or Charset,
    }
    return (decode_value(Col, Raw), Pos)


class DbObjectAttr:
    """An attribute of an object type as python-oracledb describes one (#1490):
    its name; its type, a ``DB_TYPE_*`` or the :class:`DbObjectType` of a nested
    object or collection; its precision and scale, set for a number or a
    timestamp; and its maximum size in bytes, set for a character or RAW one."""

    __slots__ = ('name', 'type', 'precision', 'scale', 'max_size')

    def __init__(self, name, type, precision=None, scale=None, max_size=None):
        self.name = name
        self.type = type
        self.precision = precision
        self.scale = scale
        self.max_size = max_size

    def __repr__(self) -> str:
        return f'<seerdb.DbObjectAttr {self.name}>'


# A type name as the data dictionary spells it, its parenthesised sizes
# dropped -- TIMESTAMP(6) WITH TIME ZONE is TIMESTAMP WITH TIME ZONE -- to the
# DB_TYPE_* python-oracledb reports for it (#1490).
_SIZES = re.compile(r'\s*\(\s*\d+\s*(?:,\s*-?\d+\s*)?(?:BYTE|CHAR)?\s*\)')


def _base_type_name(name) -> str:
    return _SIZES.sub('', str(name or '')).strip().upper()


def _db_type_by_name() -> dict:
    from seerdb.common import datatypes as T

    return {
        'NUMBER': T.DB_TYPE_NUMBER,
        'FLOAT': T.DB_TYPE_NUMBER,
        'INTEGER': T.DB_TYPE_NUMBER,
        'SMALLINT': T.DB_TYPE_NUMBER,
        'REAL': T.DB_TYPE_NUMBER,
        'DOUBLE PRECISION': T.DB_TYPE_NUMBER,
        'DECIMAL': T.DB_TYPE_NUMBER,
        'VARCHAR2': T.DB_TYPE_VARCHAR,
        'VARCHAR': T.DB_TYPE_VARCHAR,
        'NVARCHAR2': T.DB_TYPE_NVARCHAR,
        'CHAR': T.DB_TYPE_CHAR,
        'NCHAR': T.DB_TYPE_NCHAR,
        'RAW': T.DB_TYPE_RAW,
        'LONG': T.DB_TYPE_LONG,
        'LONG RAW': T.DB_TYPE_LONG_RAW,
        'DATE': T.DB_TYPE_DATE,
        'TIMESTAMP': T.DB_TYPE_TIMESTAMP,
        'TIMESTAMP WITH TZ': T.DB_TYPE_TIMESTAMP_TZ,
        'TIMESTAMP WITH TIME ZONE': T.DB_TYPE_TIMESTAMP_TZ,
        'TIMESTAMP WITH LOCAL TZ': T.DB_TYPE_TIMESTAMP_LTZ,
        'TIMESTAMP WITH LOCAL TIME ZONE': T.DB_TYPE_TIMESTAMP_LTZ,
        'INTERVAL DAY TO SECOND': T.DB_TYPE_INTERVAL_DS,
        'INTERVAL YEAR TO MONTH': T.DB_TYPE_INTERVAL_YM,
        'BINARY_FLOAT': T.DB_TYPE_BINARY_FLOAT,
        'BINARY_DOUBLE': T.DB_TYPE_BINARY_DOUBLE,
        'BINARY_INTEGER': T.DB_TYPE_BINARY_INTEGER,
        'PLS_INTEGER': T.DB_TYPE_BINARY_INTEGER,
        'BOOLEAN': T.DB_TYPE_BOOLEAN,
        'PL/SQL BOOLEAN': T.DB_TYPE_BOOLEAN,
        'CLOB': T.DB_TYPE_CLOB,
        'NCLOB': T.DB_TYPE_NCLOB,
        'BLOB': T.DB_TYPE_BLOB,
        'BFILE': T.DB_TYPE_BFILE,
        'ROWID': T.DB_TYPE_ROWID,
        'UROWID': T.DB_TYPE_UROWID,
        'JSON': T.DB_TYPE_JSON,
        'VECTOR': T.DB_TYPE_VECTOR,
        'XMLTYPE': T.DB_TYPE_XMLTYPE,
    }


def _attr_type(layout: dict):
    # An attribute's or element's type as python-oracledb reports it (#1490):
    # the nested DbObjectType of an object or collection, else the DB_TYPE_*
    # its type name stands for (None for one this does not know).
    nested = layout.get('object_type')
    if nested is not None and _base_type_name(layout.get('type_name')) != 'XMLTYPE':
        return nested
    return _db_type_by_name().get(_base_type_name(layout.get('type_name')))


def attr_max_size(type_name, length, char_used=None) -> int | None:
    """An attribute's maximum size in bytes, from the length ALL_TYPE_ATTRS
    lists (#1490): a character type's in its declared semantics -- a CHAR one
    four bytes a character, the database character set's widest -- a national
    one's at two bytes a character, a RAW's as is; None for any other."""
    if length is None:
        return None
    base = _base_type_name(type_name)
    if base in ('VARCHAR2', 'VARCHAR', 'CHAR'):
        return int(length) * (4 if char_used == 'C' else 1)
    if base in ('NVARCHAR2', 'NCHAR'):
        return 2 * int(length)
    if base == 'RAW':
        return int(length)
    return None


def _precision_scale(type_name, precision, scale) -> tuple:
    # A number's or timestamp's (precision, scale) as python-oracledb reports it
    # -- which it reads from the type's TDS -- from what the data dictionary
    # lists (#1490), measured on 23ai: a NUMBER with neither is (0, -127), one
    # with a scale alone (38, s); a FLOAT of any b is (126, -127), a REAL
    # (63, -127); INTEGER and SMALLINT are (38, 0); a timestamp is (0, its
    # fractional precision).
    base = _base_type_name(type_name)
    if base in ('NUMBER', 'DECIMAL'):
        if precision is None:
            return (0, -127) if scale is None else (38, int(scale))
        return (int(precision), int(scale or 0))
    if base == 'REAL':
        return (63, -127)
    if base in ('FLOAT', 'DOUBLE PRECISION'):
        return (126, -127)
    if base in ('INTEGER', 'SMALLINT'):
        return (38, 0)
    if base.startswith('TIMESTAMP'):
        return (0, 6 if scale is None else int(scale))
    return (None, None)


def _object_attr(layout: dict) -> DbObjectAttr:
    typ = _attr_type(layout)
    (precision, scale) = (
        (None, None)
        if isinstance(typ, DbObjectType)
        else _precision_scale(
            layout.get('type_name'), layout.get('precision'), layout.get('scale')
        )
    )
    return DbObjectAttr(
        layout.get('name'), typ, precision, scale, layout.get('max_size')
    )


def lob_attribute_csfrm(Attr: dict) -> int:
    """The charset form of a LOB attribute: an NCLOB shares CLOB's wire type, so
    only its type name tells the national form apart (#1260)."""
    return 2 if (Attr.get('type_name') or '').upper() == 'NCLOB' else 1


def map_object_lobs(Value: object, Fn: Callable[[dict, object], object]) -> object:
    """A copy of an object or collection with ``Fn(attr, value)`` applied to each
    non-NULL CLOB / BLOB attribute or element, nested objects and collections
    included, in the order the image carries them (#1260).

    Decoded, such a leaf is the locator the image carried; bound, it is whatever
    the caller set. Walking in image order lets a caller first collect the leaves
    with one ``Fn`` and then substitute results with another, which the async
    client needs: it cannot await inside ``Fn``."""
    if not isinstance(Value, DbObject):
        return Value
    Typ = Value._dbtype
    if Typ is None:
        return Value
    if Typ.is_collection:
        Element = Typ.element or {}
        return DbObject(
            Value._type_name,
            elements=[_map_lob_member(E, Element, Fn) for E in Value._elements or []],
            dbtype=Typ,
            keys=Value._keys,
        )
    Attrs = [
        (Name, _map_lob_member(Value._attrs.get(Name), Attr, Fn))
        for Name, Attr in ((A['name'], A) for A in Typ.attrs)
    ]
    Known = {Name for Name, _ in Attrs}
    # An attribute the layout does not name (set by hand) rides along untouched.
    Attrs += [(N, V) for N, V in Value._attrs.items() if N not in Known]
    return DbObject(Value._type_name, Attrs, dbtype=Typ)


def _map_lob_member(Value: object, Attr: dict, Fn: Callable) -> object:
    if Value is None:
        return None
    if Attr.get('object_type') is not None:
        return map_object_lobs(Value, Fn)
    if Attr.get('data_type') in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
        return Fn(Attr, Value)
    return Value


def decode_xmltype(Image: bytes, Charset: int = AL32UTF8_CHARSET) -> tuple:
    """Decode an XMLType image (#124), returning ``(is_lob, value)``.

    Mirrors python-oracledb ``read_xmltype``: the shared image header, a 1-byte
    XML version, a ``ub4`` flag word (with an optional 4-byte skip), then the
    content. For an inline document (the ``STRING`` flag) ``value`` is the
    decoded ``str`` and ``is_lob`` is False; for a large document (the ``LOB``
    flag) ``value`` is the CLOB locator bytes and ``is_lob`` is True (the caller
    reads it through the LOB path).
    """
    Pos = _read_image_header(Image)
    Pos += 1  # XML version (skip)
    Flag = int.from_bytes(Image[Pos : Pos + 4], 'big')
    Pos += 4
    if Flag & _XML_TYPE_FLAG_SKIP_NEXT_4:
        Pos += 4
    Content = bytes(Image[Pos:])
    if Flag & _XML_TYPE_STRING:
        # Inline XML content arrives as UTF-8 in our AL32UTF8 session; the
        # `Charset` id is retained for signature parity (#236 — the old
        # CharsetDict lookup keyed a name->id map by an int, so it always fell
        # through to 'utf-8' anyway).
        return (False, Content.decode('utf-8', 'replace'))
    if Flag & _XML_TYPE_LOB:
        if Flag & _XML_TYPE_LEGACY_STORAGE:
            raise NotSupportedError(
                'reading a CLOB-stored XMLType column (Oracle 11g) is not '
                'supported; cast it in SQL, e.g. '
                'SELECT XMLTYPE.getclobval(col) or XMLSERIALIZE(...)'
            )
        return (True, Content)  # CLOB locator
    raise NotSupportedError(f'unexpected XMLType flag 0x{Flag:x}')


# The image flags an inline XMLType carries: IS_VERSION_81 | NO_PREFIX_SEG plus
# the XMLType marker bit, exactly as a live 23ai emits (#124).
_XML_IMAGE_FLAGS = 0x85


def encode_xmltype(
    Value: object, Charset: int = AL32UTF8_CHARSET, Flags: int = _XML_TYPE_STRING
) -> bytes:
    """Encode an inline XMLType document into its image — the inverse of
    :func:`decode_xmltype` for the ``STRING`` form.

    The image is the shared header (flags + version + length), a 1-byte XML
    version, a ub4 flag word (``STRING``), then the UTF-8 content. A live 23ai
    additionally sets a ``0x10`` bit in the flag word, which python-oracledb
    ignores (it checks only STRING / LOB / SKIP_NEXT_4), so the bare STRING flag
    round-trips through either reader (#124).

    A large document is inline too. Captured from 23ai serving a 32 KB one to
    python-oracledb, the server sends the same STRING image with the length in
    its long form, ``fe`` + a 4-byte length, and the content rides as ordinary
    chunked column bytes; no LOB is involved (#1073).
    """
    content = str(Value).encode('utf-8')
    tail = bytes([1]) + Flags.to_bytes(4, 'big') + content
    # flags + version + image length + tail; the length spans the whole image,
    # its own field included, as the server writes it.
    if len(tail) + 3 <= TNS_MAX_SHORT_LENGTH:
        return bytes([_XML_IMAGE_FLAGS, 1, len(tail) + 3]) + tail
    return (
        bytes([_XML_IMAGE_FLAGS, 1, TNS_LONG_LENGTH_INDICATOR])
        + (len(tail) + 7).to_bytes(4, 'big')
        + tail
    )


def is_xml_type(typ: object) -> bool:
    """Whether ``typ`` (a DbObjectType) is SYS.XMLTYPE, which rides as a
    specially-framed XMLType image rather than a normal object (#124)."""
    return (
        getattr(typ, 'schema', None) == 'SYS'
        and getattr(typ, 'name', None) == 'XMLTYPE'
    )


def decode_collection_keyed(
    Image: bytes, Element: dict, Charset: int = AL32UTF8_CHARSET
) -> tuple[list, list[int] | None]:
    """Walk a collection image into ``(elements, keys)``.

    The header (incl. the prefix segment a collection carries) is consumed by
    the shared ``_read_image_header``; then a 1-byte collection-flags marker, a
    length-prefixed element count, and that many length-prefixed element values
    decoded with the single element type. A NULL element is ``None``.

    A PL/SQL associative array sets the HAS_INDEXES flag in that marker byte and
    prefixes each element with its key; ``keys`` is that list, and ``None`` for a
    VARRAY / nested table, which has no keys at all. Elements ride in sorted-key
    order, so the element list is in key order either way (#888/#1053).

    The key is a **signed** big-endian int32: a PL/SQL index-by table may be
    keyed by any BINARY_INTEGER, and the negative half is not hypothetical --
    ``fff00000`` is -1048576 on a live 23ai. Reading it unsigned agrees for every
    key a dense 1..N array has, which is why it went unnoticed.
    """
    Pos = _read_image_header(Image, 0)
    index_table = bool(Image[Pos] & _COLL_HAS_INDEXES)
    Pos += 1  # collection flags
    (Count, Pos) = _read_length(Image, Pos)
    Out: list = []
    Keys: list[int] | None = [] if index_table else None
    for _ in range(Count or 0):
        if Keys is not None:
            Keys.append(int.from_bytes(Image[Pos : Pos + 4], 'big', signed=True))
            Pos += 4
        (Value, Pos) = _decode_member(Image, Pos, Element, Charset, in_collection=True)
        Out.append(Value)
    return (Out, Keys)


def decode_collection_image(
    Image: bytes, Element: dict, Charset: int = AL32UTF8_CHARSET
) -> list:
    """The elements of a collection image, without their keys.

    For callers that only want values; an associative array's keys come from
    :func:`decode_collection_keyed`, which this wraps.
    """
    return decode_collection_keyed(Image, Element, Charset)[0]
