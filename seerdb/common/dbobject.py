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

import builtins

from seerdb.common.exceptions import NotSupportedError
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    TNS_LONG_LENGTH_INDICATOR,
    TNS_NULL_LENGTH_INDICATOR,
    TNS_TYPE_ADT,
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_BLOB,
    TNS_TYPE_CHAR,
    TNS_TYPE_CLOB,
    TNS_TYPE_DATE,
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
}


def type_name_to_tns(name: str | None) -> int | None:
    """TNS data type code for an ALL_TYPE_ATTRS attribute type name (or None).

    TIMESTAMP / INTERVAL names carry a precision suffix (e.g. ``TIMESTAMP(6)``);
    strip it before the lookup.
    """
    if not name:
        return None
    Key = name.split('(')[0].strip()
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
    ):
        self.schema = schema
        self.name = name
        self.oid = oid  # 16-byte type OID (bytes)
        self.version = version
        self.attrs = attrs  # ordered layout (list of dict)
        # Collection types (#117/#118): a single element type instead of named
        # attributes. collection_type is VARRAY (3) / NESTED_TABLE (2).
        self.is_collection = is_collection
        self.collection_type = collection_type
        self.element = element  # one layout dict, or None
        self.max_elements = max_elements

    @property
    def full_name(self) -> str:
        return f'{self.schema}.{self.name}' if self.schema else self.name

    @property
    def attr_names(self) -> list:
        return [A['name'] for A in self.attrs]

    def newobject(self, values=None) -> 'DbObject':
        """A new DbObject of this type, ready to bind (#116/#117).

        For an object type every attribute starts NULL; seed from ``values`` (a
        dict, or a sequence in declaration order). For a collection type
        ``values`` is the element sequence (default empty). Set object
        attributes by name (``obj.STREET = '...'``) or collection elements by
        index / ``append`` before binding.
        """
        if self.is_collection:
            return DbObject(self.full_name, elements=list(values or []), dbtype=self)
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

    def extend(self, values) -> None:
        """Append several elements (collection types only)."""
        if not self._is_collection:
            raise TypeError('extend is only valid on a collection object')
        self._elements.extend(values)

    def aslist(self) -> list:
        """The collection elements, or an object's attribute values in order."""
        if self._is_collection:
            return list(self._elements)
        return [self._attrs[Name] for Name in self._order]

    def asdict(self) -> dict:
        """A name -> value mapping of the attributes (object types only)."""
        if self._is_collection:
            raise TypeError('asdict is not valid on a collection object')
        return dict(self._attrs)

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
    if Nested is not None and Nested.is_collection:
        if Image[Pos] in (TNS_NULL_LENGTH_INDICATOR, _OBJ_ATOMIC_NULL):
            return (None, Pos + 1)
        (Length, Pos) = _read_length(Image, Pos)
        Sub = bytes(Image[Pos : Pos + (Length or 0)])
        Pos += Length or 0
        Elements = decode_collection_image(Sub, Nested.element or {}, Charset)
        return (DbObject(Nested.full_name, elements=Elements, dbtype=Nested), Pos)
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
    Col = {
        'data_type': Attr.get('data_type'),
        'charset': Attr.get('charset') or Charset,
    }
    return (decode_value(Col, Raw), Pos)


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


def decode_collection_image(
    Image: bytes, Element: dict, Charset: int = AL32UTF8_CHARSET
) -> list:
    """Walk a collection (VARRAY / nested table) image into a list of elements.

    The header (incl. the prefix segment a collection carries) is consumed by
    the shared ``_read_image_header``; then a 1-byte collection-flags marker, a
    length-prefixed element count, and that many length-prefixed element values
    decoded with the single element type. A NULL element is ``None``. (PL/SQL
    associative arrays prefix each element with an int32 key -- that is #122.)
    """
    Pos = _read_image_header(Image, 0)
    Pos += 1  # collection flags (skip)
    (Count, Pos) = _read_length(Image, Pos)
    Out: list = []
    for _ in range(Count or 0):
        (Value, Pos) = _decode_member(Image, Pos, Element, Charset, in_collection=True)
        Out.append(Value)
    return Out
