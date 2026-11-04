# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Helpers for building SQL text dynamically (#2456).

The same three functions python-oracledb 4.0 offers, with the same results:
quoting a string as a literal, quoting a name, and checking that a name is a
simple SQL name. Binds stay the way to pass values; these are for the parts of
a statement a bind cannot stand in for, such as a table's name.
"""

from __future__ import annotations

from seerdb.common.exceptions import ProgrammingError


def enquote_literal(value: str) -> str:
    """``value`` as a SQL string literal: in single quotes, each one inside
    doubled."""
    return "'" + value.replace("'", "''") + "'"


def enquote_name(value: str, capitalize: bool = True) -> str:
    """``value`` as a quoted SQL name, upper-cased unless ``capitalize`` is
    false. A quoted name can't hold a double quote, so one inside is refused."""
    if '"' in value:
        raise ProgrammingError('name has embedded quotes')
    return '"' + (value.upper() if capitalize else value) + '"'


def is_simple_sql_name(value: str) -> bool:
    """Whether ``value``, surrounding whitespace aside, is a simple SQL name.

    Unquoted, it starts with a letter and goes on in letters, digits, ``_``,
    ``$`` and ``#``. Quoted, it holds at least one character and no double
    quote."""
    Name = value.strip()
    if len(Name) >= 2 and Name[0] == '"' and Name[-1] == '"':
        Inner = Name[1:-1]
        return bool(Inner) and '"' not in Inner
    if not Name or not Name[0].isalpha():
        return False
    return all(Char.isalnum() or Char in '_$#' for Char in Name[1:])
