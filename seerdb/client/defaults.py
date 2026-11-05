# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""``seerdb.defaults``: the values a connection or cursor starts from (#2458).

python-oracledb's ``oracledb.defaults``, under the same names. Each is read when
the thing it is the default for is made -- a connection at connect, a cursor
when it is opened, ``fetch_decimals`` at each execute -- so changing one affects
what is made afterwards, not what already exists. A value passed explicitly
(``connect(fetch_lobs=False)``, ``cursor.arraysize = 10``) still wins.

The identity defaults (``program``, ``machine``, ``osuser``, ``terminal``,
``driver_name``) start as ``None``, meaning what seerdb reports when nothing is
set: this process's own name, host and user, and seerdb's banner.
python-oracledb fills them in at import instead; what reaches the server is the
same either way.
"""

from __future__ import annotations


class Defaults:
    """The module-wide defaults; one instance, ``seerdb.defaults``."""

    __slots__ = (
        'arraysize',
        'config_dir',
        'driver_name',
        'fetch_decimals',
        'fetch_lobs',
        'machine',
        'osuser',
        'prefetchrows',
        'program',
        'stmtcachesize',
        'terminal',
    )

    def __init__(self) -> None:
        # Rows fetchmany() returns, and a scrollable cursor refills, per batch.
        self.arraysize: int = 100
        # Where tnsnames.ora and a wallet are looked for when connect() names
        # no config_dir (TNS_ADMIN is consulted after it).
        self.config_dir: str | None = None
        self.driver_name: str | None = None
        # Whether a NUMBER column is fetched as decimal.Decimal, whole values
        # included. Off, a NUMBER is an int when whole and a Decimal otherwise,
        # as seerdb has always fetched it (python-oracledb returns a float).
        self.fetch_decimals: bool = False
        # Whether a CLOB / BLOB column is fetched as a LOB object (True) or as
        # its str / bytes content.
        self.fetch_lobs: bool = True
        self.machine: str | None = None
        self.osuser: str | None = None
        # Rows the server returns with a scrollable cursor's open.
        self.prefetchrows: int = 2
        self.program: str | None = None
        # Server cursors a connection keeps in its statement cache. 32, seerdb's
        # own default (python-oracledb's is 20).
        self.stmtcachesize: int = 32
        self.terminal: str | None = None

    def __repr__(self) -> str:
        Fields = ', '.join(f'{N}={getattr(self, N)!r}' for N in self.__slots__)
        return f'Defaults({Fields})'


defaults = Defaults()
