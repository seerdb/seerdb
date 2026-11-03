# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""What a Mirror session may carry, decided once at login (#2395).

This is the Mirror's table. The server session sets it at login, and the
encoders read it; it lives here, not in seerdb/server, only because those
encoders do. The client never uses it: it reads whatever the server sends,
and decides its own refusals from what the server advertised.

A client's protocol predates some of what a database can hold: sqlplus 11.2
has no type code for a BOOLEAN. Each such feature gets one verdict per session:

- **native:** carried as the newest protocol carries it;
- **mapped:** carried in a form the client's protocol has, the one real Oracle
  sends that client;
- **refused:** answered with the error a real server returns.

The field version still decides how bytes are laid out (the describe's slots,
the OAC tails); this table decides only what goes into them. The encoders and
the session ask it rather than comparing field versions themselves.

The table also holds the choices a sqlplus's own capability block makes at
login: which LOB cell, TIMESTAMP WITH TIME ZONE cell and release it reads.
"""

from __future__ import annotations

import contextvars
import enum
from dataclasses import dataclass

from seerdb.common.tns_consts import (
    FIELD_VERSION_12_1,
    FIELD_VERSION_18_1,
    FIELD_VERSION_20_1,
    FIELD_VERSION_23_1,
)


class Carry(enum.Enum):
    """How a session carries one feature."""

    NATIVE = 'native'
    MAPPED = 'mapped'
    REFUSED = 'refused'


@dataclass(frozen=True)
class Features:
    """One session's verdicts. The defaults are what a session that never
    logged in gets: the newest forms, as the codec's own defaults are."""

    # The 23ai types and calls that older clients have no form for. Each is
    # NATIVE at every band until its own change maps or refuses it (#2416-#2419).
    # A BOOLEAN reaches a client below 23.1 as a NUMBER 1 / 0, described with
    # length 22, precision 0 and scale 0: what 23ai sends the thin client at
    # every field version below 17, and sqlplus 11.2 (#2416).
    boolean: Carry = Carry.NATIVE
    # A JSON column reaches a client below 20.1 as a BLOB holding the
    # document's text, which 23ai sends the thin client below field version 14
    # and sqlplus 11.2 (#2417).
    json: Carry = Carry.NATIVE
    # A VECTOR reaches a client below 12.1 as a CLOB holding its text, which
    # 23ai sends the thin client at field version 6 and sqlplus 11.2 (#2418).
    vector: Carry = Carry.NATIVE
    # An implicit result (DBMS_SQL.RETURN_RESULT) is refused to a client below
    # 12.1: 23ai raises ORA-29481 at the call, to the thin client at field
    # version 6 and to sqlplus 11.2. The backend raises it, where the block
    # runs, so a handler can catch it (#2419).
    implicit_results: Carry = Carry.NATIVE
    # A sqlplus that offered CCAP_LOB_12C (sqlplus 23.26) reads a LOB cell with
    # the LOB's length and chunk size before the locator; one that did not
    # (11.2) cannot parse the cell with them. A live 11g answers each in its
    # own form (#1287).
    oci_lob_12c: bool = False
    # Whether a sqlplus reads a TIMESTAMP WITH TIME ZONE cell as the wall clock
    # with the 0x40 flag (#2018). A live 11g, which the Mirror's pre-12c OCI
    # replies imitate, sends that form to sqlplus 23.26 and the UTC form to
    # 11.2. Told apart by the field version the client's own block names, 12.1
    # or later; the capability bit the server keys on is not pinned down.
    oci_tstz_local: bool = True
    # Whether a sqlplus's version call is answered with the full release and
    # banner_full (#2024). Measured against 18c, 21c and 23ai: sqlplus 23.26 is
    # sent the full release (SHOW RELEASE 2326020000) and the two-line
    # banner_full, 11.2 the base release (2300000000) and the one-line banner.
    # banner_full is 18c's, so the line is drawn at a client of 18.1 or later;
    # no client between 11.2 and 23.26 has been tried.
    oci_full_release: bool = True
    # The field version the client itself speaks, which the verdicts above
    # follow: the session's for a thin client, the one its capability block
    # names for sqlplus. None when not known. A passthrough logs in upstream
    # at it, so its upstream answers the client as it would directly (#2430).
    client_field_version: int | None = None


def session_features(
    field_version: int,
    *,
    oci: bool = False,
    client_field_version: int | None = None,
    lob_12c: bool = False,
) -> Features:
    """The table for a session at ``field_version``. ``oci`` is the sqlplus
    dialect; for it, ``client_field_version`` is the version its capability
    block names (None when the block can't be read, which keeps the newer
    forms) and ``lob_12c`` whether it offered CCAP_LOB_12C.

    The 23ai features follow the client's own version: the session's for a
    thin client, and for sqlplus the one its block names, since the Mirror
    speaks 12.1's dialect to every sqlplus from 12.1 on while 23ai sends
    sqlplus 23.26 a native BOOLEAN."""
    client = client_field_version if oci else field_version

    def from_version(native_from: int) -> Carry:
        newer = client is None or client >= native_from
        return Carry.NATIVE if newer else Carry.MAPPED

    boolean = from_version(FIELD_VERSION_23_1)
    json = from_version(FIELD_VERSION_20_1)
    vector = from_version(FIELD_VERSION_12_1)
    implicit_results = Carry.REFUSED if vector is Carry.MAPPED else Carry.NATIVE
    if not oci:
        return Features(
            boolean=boolean,
            json=json,
            vector=vector,
            implicit_results=implicit_results,
            client_field_version=client,
        )
    return Features(
        boolean=boolean,
        json=json,
        vector=vector,
        implicit_results=implicit_results,
        client_field_version=client,
        oci_lob_12c=lob_12c,
        oci_tstz_local=client_field_version is None
        or client_field_version >= FIELD_VERSION_12_1,
        oci_full_release=client_field_version is None
        or client_field_version >= FIELD_VERSION_18_1,
    )


# The table of the session the current context serves. Set at login.
_SESSION_FEATURES: contextvars.ContextVar[Features] = contextvars.ContextVar(
    'session_features', default=Features()
)
