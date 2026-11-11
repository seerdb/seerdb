# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Reading the bind placeholders out of a statement's text.

Both ends of the connection need this, and they need to agree. The client scans
a statement to work out which value goes where, and how many to send. The Mirror
scans the same statement to work out how many values to expect, because a
`RETURNING ... INTO` bind is filled by the server and so carries no value in the
row data -- read one for it and everything after it is misread
(docs/PROTOCOL.md 22). One implementation, so the two cannot drift.

Nothing here touches the wire. It is text analysis, kept beside the codec rather
than inside it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import NamedTuple

# The spans an Oracle statement's text is made of (#1679), tried in this order
# at each position. A comment runs to the end of its line or its `*/`; a string
# literal's quote is escaped by doubling it, and may carry an N prefix; a
# quoted identifier is escaped the same way. An unterminated comment, string or
# identifier runs to the end of the text, as the server reads it. Alternative
# quoting -- q'[...]' -- is found by its opening here and closed by
# `sql_tokens`, since its closing delimiter depends on its opening one.
#
# A bind is `:name`, `:"name"` or `:123`, never the second colon of a `::`; a
# quoted one may have space after its colon. Its name is matched as before
# this tokenizer: letters, digits and `_`.
#
# The comment body is `(?:[^*]|\*(?!/))*`, not a lazy `.*?`: CodeQL flags the
# lazy form as a ReDoS (#1560).
_SQL_TOKEN = re.compile(
    r"""
    (?P<comment>--[^\n]*|/\*(?:[^*]|\*(?!/))*(?:\*/|\Z))
  | (?P<qstring>[nN]?[qQ]'(?P<delimiter>\S))
  | (?P<string>[nN]?'(?:[^']|'')*(?:'|\Z))
  | (?P<bind>(?<!:):(?:\s*"[^"\n]+"|[A-Za-z_]\w*|\d+))
  | (?P<identifier>"(?:[^"]|"")*(?:"|\Z))
  | (?P<word>[A-Za-z_][\w$#]*)
  | (?P<space>\s+)
  | (?P<other>.)
    """,
    re.VERBOSE | re.DOTALL,
)
# The delimiters of alternative quoting that close with a different character.
_Q_CLOSING = {'[': ']', '(': ')', '{': '}', '<': '>'}


class SqlToken(NamedTuple):
    """One span of a statement's text: ``kind`` is ``comment``, ``string``,
    ``identifier``, ``bind``, ``word``, ``space`` or ``other``, and
    ``text[start:end]`` is its text."""

    kind: str
    start: int
    end: int


def sql_tokens(SQL: str) -> Iterator[SqlToken]:
    """The spans of an Oracle statement's text, in order, covering all of it.

    One reading of what is a literal, a quoted identifier, a comment or a bind,
    for every scanner that has to step past them (#1679). Hand-written scanners
    disagreed: some skipped comments, some did not, and none knew Oracle's
    alternative quoting, so a `:name` inside `q'[...]'` or a comment counted as
    a bind and an apostrophe in a comment opened a string.
    """
    Pos = 0
    while Pos < len(SQL):
        M = _SQL_TOKEN.match(SQL, Pos)
        assert M is not None  # `other` matches any one character
        Kind = M.lastgroup
        if Kind == 'delimiter':
            Kind = 'qstring'
        if Kind == 'qstring':
            Opening = M.group('delimiter')
            Close = SQL.find(_Q_CLOSING.get(Opening, Opening) + "'", M.end())
            End = len(SQL) if Close < 0 else Close + 2
            yield SqlToken('string', Pos, End)
            Pos = End
            continue
        assert Kind is not None
        yield SqlToken(Kind, Pos, M.end())
        Pos = M.end()


# A `:name` placeholder, in either spelling. An unquoted name follows normal SQL
# identifier rules and is case-insensitive; pure-digit forms (`:1`, `:2`) are
# handled separately as positional indices.
#
# A quoted name (`:"name"`) is how a name the unquoted form cannot express gets
# through — a reserved word, or one starting with a digit — and unlike the
# unquoted form it is case-SENSITIVE, so `:"a"` and `:"A"` are two different
# placeholders (#686). Group 1 is the quoted name, group 2 the unquoted one.
_NAMED_BIND_RE = re.compile(r':(?:"([^"\n]+)"|([A-Za-z_]\w*))')
# The same, plus the numeric `:1` form. Used to count the placeholders after a
# RETURNING clause's INTO, where only how many there are matters.
_ANY_BIND_RE = re.compile(r':\s*(?:"[^"\n]+"|\w+)')


def _blank(Text: str) -> str:
    """Spaces of the same length, with newlines kept so line structure survives."""
    return ''.join(' ' if C != '\n' else C for C in Text)


def strip_non_bind_text(SQL: str) -> str:
    """SQL with everything a placeholder cannot appear inside blanked out.

    String literals and comments go, and so do quoted identifiers — but *not* a
    quoted bind name, which is a colon away from looking exactly like one.

    Blanked, not deleted: the result is the same length as the input, so an
    offset found here indexes the original text as well. `strip_returning_into`
    depends on that, and a statement carrying a comment would otherwise cut in
    the wrong place.
    """
    return ''.join(
        _blank(SQL[T.start : T.end])
        if T.kind in ('string', 'identifier', 'comment')
        else SQL[T.start : T.end]
        for T in sql_tokens(SQL)
    )


def canonical_bind_key(Key: str) -> str:
    """The lookup form of a caller-supplied bind name.

    A key written with quotes means the quoted placeholder of that exact name;
    anything else is an unquoted placeholder, which is case-insensitive and so
    folds. Matches python-oracledb, where `:"P"` is reachable as both `'"P"'`
    and `'p'` while `:"p"` is reachable only as `'"p"'`.
    """
    if len(Key) > 2 and Key.startswith('"') and Key.endswith('"'):
        return Key[1:-1]
    return Key.upper()


def bind_placeholders(SQL: str, dedupe: bool = False) -> list[tuple[str, bool]]:
    # Every `:name` placeholder in left-to-right SQL order as (name, quoted),
    # with string literals, comments and quoted identifiers stripped so we don't
    # match inside them.
    #
    # The name is in its lookup form: an unquoted one folds to upper (it is
    # case-insensitive), a quoted one keeps its exact text (it is not). The flag
    # says which spelling it was, which is what tells `:"a"` apart from `:A` —
    # the two fold to the same string but are different placeholders (#686).
    #
    # If `dedupe` is True (PL/SQL path), keep only the first occurrence of each.
    # Otherwise (plain SQL path) return every occurrence — Oracle expects one
    # bind value per textual occurrence in DML.
    Seen: list[tuple[str, bool]] = []
    Found: set[tuple[str, bool]] = set()
    for T in sql_tokens(SQL):
        if T.kind != 'bind' or not _NAMED_BIND_RE.fullmatch(SQL, T.start, T.end):
            continue  # a numbered one, or a quoted one spaced off its colon
        Name = SQL[T.start + 1 : T.end]
        Quoted = Name.startswith('"')
        Entry = (Name[1:-1], True) if Quoted else (Name.upper(), False)
        if dedupe:
            if Entry not in Found:
                Found.add(Entry)
                Seen.append(Entry)
        else:
            Seen.append(Entry)
    return Seen


# Any placeholder: a quoted or unquoted name, or a number -- but not the second
# colon of a `::` cast.
_PLACEHOLDER_RE = re.compile(r'(?<!:):(?:"([^"\n]+)"|([A-Za-z_]\w*)|(\d+))')


def placeholder_count(SQL: str) -> int:
    """How many distinct placeholders a statement has, named AND numbered.

    What a caller with no values sizes its list of NULLs by -- a parse, which
    carries none. `bind_placeholders` reports only named ones, so `values (:1)`
    counted none and went to the database with its `:1` unbound (#1394).
    """
    Seen: set[str] = set()
    for T in sql_tokens(SQL):
        M = _PLACEHOLDER_RE.fullmatch(SQL, T.start, T.end) if T.kind == 'bind' else None
        if M is not None:
            Seen.add(
                M.group(1)
                if M.group(1) is not None
                else (M.group(2) or M.group(3)).upper()
            )
    return len(Seen)


def extract_bind_names(SQL: str, dedupe: bool = False) -> list[str]:
    # The placeholder names alone, in SQL order. See `bind_placeholders` for
    # what "name" means for each spelling.
    return [Name for Name, _Quoted in bind_placeholders(SQL, dedupe)]


_RETURNING_RE = re.compile(r'\bRETURNING\b', re.I)
_INTO_RE = re.compile(r'\bINTO\b', re.I)


def returning_bind_positions(SQL: str, num_binds: int) -> frozenset:
    # 0-based positions of the OUT binds in a DML
    # `... RETURNING col[, ...] INTO :b[, ...]` (#120). Empty if the statement
    # isn't a RETURNING-INTO. The INTO binds are the trailing K of the bind
    # list (the leading binds are the VALUES/SET/WHERE inputs); K is the count
    # of placeholders after the RETURNING's INTO, so this is robust to both
    # named and numeric placeholder styles.
    if num_binds <= 0:
        return frozenset()
    if is_plsql(SQL):
        # A `RETURNING ... INTO` *inside* a PL/SQL block is the block's own
        # business, not the wire's: the INTO target is an ordinary PL/SQL OUT
        # bind, and the block is executed like any other. Classified as a DML
        # RETURNING, the bind is one the client writes NO value for -- so the
        # server sat waiting for bind bytes that never came and neither side
        # ever spoke again, until the client's read timeout fired 15s later
        # (#826). The same misreading on the Mirror's side of this function
        # routed the block into the DML-RETURNING path.
        return frozenset()
    Cleaned = strip_non_bind_text(SQL)
    Ret = _RETURNING_RE.search(Cleaned)
    if Ret is None:
        return frozenset()
    Into = _INTO_RE.search(Cleaned, Ret.end())
    if Into is None:
        return frozenset()
    K = len(_ANY_BIND_RE.findall(Cleaned[Into.end() :]))
    if K <= 0 or K > num_binds:
        return frozenset()
    return frozenset(range(num_binds - K, num_binds))


def strip_returning_into(SQL: str) -> str:
    """The same statement with the `INTO :a, :b` of its RETURNING clause removed.

    Oracle spells the clause `RETURNING col[, ...] INTO :bind[, ...]`, naming
    where each returned column goes. Every other database that has the feature
    spells it `RETURNING col[, ...]` and hands the columns back as rows. A Mirror
    backend built on one of those runs the statement without the INTO part and
    reads the rows (#689).

    Returns the statement unchanged when it has no RETURNING-INTO. The INTO list
    ends the statement, so everything from that keyword on is dropped; a trailing
    `;` or whitespace is not part of it and is kept.
    """
    Cleaned = strip_non_bind_text(SQL)
    Ret = _RETURNING_RE.search(Cleaned)
    if Ret is None:
        return SQL
    Into = _INTO_RE.search(Cleaned, Ret.end())
    if Into is None:
        return SQL
    # strip_non_bind_text blanks rather than deletes, so the offset found in the
    # cleaned text indexes the original directly.
    Tail = SQL[Into.end() :]
    Trailing = Tail[len(Tail.rstrip().rstrip(';')) :]
    return SQL[: Into.start()].rstrip() + Trailing


def wrap_returning_in_block(SQL: str) -> tuple[str, str]:
    """Wrap a ``DML ... RETURNING ... INTO`` in an anonymous PL/SQL block (#801).

    Pre-10g servers refuse the 10g+ RETURNING request form -- 9i answers
    ``ORA-00439`` for this client type -- but they run the identical statement
    inside a PL/SQL block, where the INTO targets are ordinary OUT binds, a form
    those tiers have always supported. So the clause needs no new wire protocol:
    it needs the statement in a block.

    The block also assigns ``SQL%ROWCOUNT`` to one appended bind, because a
    block's own row count reports the *block* executing (measured: always 1)
    rather than the rows the DML touched. Without it a wrapped statement would
    report a plausible but wrong ``cursor.rowcount``.

    Returns the wrapped SQL and the name of the appended rowcount placeholder;
    the caller appends a matching OUT bind, and must strip both back out before
    handing results to the user.
    """
    Statement = SQL.strip()
    # A trailing `;` would close the statement early inside the block.
    Statement = Statement.rstrip().rstrip(';').rstrip()
    # The appended placeholder must not collide with one the statement already
    # uses; bind names are matched case-insensitively.
    Taken = {Name.lower() for Name in extract_bind_names(SQL)}
    Name = 'seerdb_rowcount'
    while Name in Taken:
        Name += '_'
    return f'BEGIN {Statement}; :{Name} := SQL%ROWCOUNT; END;', Name


_ALTER_SCHEMA_RE = re.compile(
    r'\s*ALTER\s+SESSION\s+SET\s+CURRENT_SCHEMA\s*=\s*("?)([^\s";]+)\1', re.I
)


def altered_current_schema(SQL: str) -> str | None:
    """The schema an ``ALTER SESSION SET CURRENT_SCHEMA = X`` selects, else None.

    A server reports the new value back to the client, which is the only way
    ``connection.current_schema`` ever learns it (#973), so a Mirror has to
    recognise the statement rather than treat it as an ordinary DDL.
    """
    match = _ALTER_SCHEMA_RE.match(SQL)
    return match.group(2) if match else None


_ALTER_EDITION_RE = re.compile(
    r'\s*ALTER\s+SESSION\s+SET\s+EDITION\s*=\s*("?)([^\s";]+)\1', re.I
)


def altered_edition(SQL: str) -> str | None:
    """The edition an ``ALTER SESSION SET EDITION = X`` selects, else None.

    Reported back to the client the same way a schema change is (§20.6), under
    its own key -- `connection.edition` learns it from that reply alone (#973).
    """
    match = _ALTER_EDITION_RE.match(SQL)
    return match.group(2) if match else None


def statement_head(SQL: str) -> str:
    """The statement, upper-cased, from its first word: leading whitespace and
    SQL comments dropped.

    What kind of statement it is -- a query, a PL/SQL block, DML -- is read off
    its first word, and a comment ahead of that word does not change it. Read
    off the raw text instead, `/* why */ SELECT ...` was taken for DML and its
    rows were never fetched ("no result set").
    """
    for T in sql_tokens(SQL):
        if T.kind not in ('space', 'comment'):
            return SQL[T.start :].upper()
    return ''


def is_plsql(SQL: str) -> bool:
    # PL/SQL blocks start with BEGIN or DECLARE after stripping leading
    # whitespace and SQL comments. Anonymous blocks, packaged calls
    # wrapped in BEGIN...END;, and DECLARE...BEGIN forms all match.
    Head = statement_head(SQL)[:8]
    return Head.startswith('BEGIN') or Head.startswith('DECLARE')


_REUSABLE_DML_RE = re.compile(r'\s*(INSERT|UPDATE|DELETE|MERGE)\b', re.I)


def is_reusable_dml(SQL: str) -> bool:
    """Whether a server cursor for this statement may be reused for a re-execute.

    True only for real DML. Such a statement is parsed once and then executed
    again per set of bind values, so keeping the server's handle saves a parse
    and changes nothing about the outcome.

    DDL is excluded, and that is the whole point of this function (#703). A
    `CREATE` or `DROP` does its work when the server **parses** it, so a cached
    re-execute has nothing left to do -- the server reports success and the
    statement never happens. Silently: the caller is told the table was created
    and it was not.

    Everything unrecognised is excluded too. Being wrong in this direction costs
    a re-parse; being wrong in the other loses the statement.
    """
    return _REUSABLE_DML_RE.match(strip_non_bind_text(SQL)) is not None


# Words a PL/SQL statement starts after, besides `;` (#1783).
_PLSQL_STATEMENT_STARTS = frozenset(
    {'BEGIN', 'DECLARE', 'THEN', 'ELSE', 'ELSIF', 'LOOP', 'EXCEPTION'}
)
# What opens an embedded SQL statement, whose binds are read but for an INTO's.
_SQL_STATEMENT_HEADS = frozenset(
    {'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'SELECT', 'WITH'}
)
# What opens a condition or a loop's bounds, which only read (#2453).
_PLSQL_CONDITION_HEADS = frozenset(
    {'IF', 'ELSIF', 'WHILE', 'FOR', 'CASE', 'WHEN', 'EXIT'}
)


def plsql_bind_directions(SQL: str, num_binds: int) -> list[str] | None:
    """Per bind position of a PL/SQL block, the direction a server would report
    for it -- 'IN', 'OUT' or 'IN OUT' (#1783). None when it cannot say.

    23ai reports a bind IN when every use reads it, OUT when every use writes
    it, and IN OUT when it is both read and written, in any order (#2453). This
    sorts each use the same way where the text alone settles it:

    - **read:** inside an embedded SQL statement anywhere but its INTO list; on
      the right of `:=` outside any parentheses; in a condition or a loop's
      bounds (`IF`, `ELSIF`, `WHILE`, `FOR`, `CASE`, `WHEN`, `EXIT`) outside
      any parentheses.
    - **written:** an embedded SQL statement's INTO target (`RETURNING ... INTO
      :b`, `SELECT ... INTO :b`), and the whole target of an assignment
      (`:b := ...`).
    - **might be either:** anything else, a call argument above all. Its mode
      is the called routine's, which the text doesn't say, so it counts as both.

    The doubt always falls on IN OUT: telling a client IN for a written bind
    loses its value (#1363), and OUT for a read one loses its input, while IN
    OUT costs nothing. A position's binds are its name's occurrences (a block
    binds each name once); a numbered bind, or a count other than the client's,
    gives up.
    """
    Names = bind_placeholders(SQL, dedupe=True)
    if len(Names) != num_binds or placeholder_count(SQL) != num_binds:
        return None
    Position = {Entry: I for I, Entry in enumerate(Names)}
    Reads = [False] * num_binds
    Writes = [False] * num_binds
    Head: str | None = None  # the current statement's first word
    AtStart = True
    IntoSeen = False  # inside an embedded SQL statement's INTO list
    AfterAssign = False  # past the `:=` of the current statement
    Depth = 0  # parentheses open since the statement or its assignment began
    Target: int | None = None  # a bind opening a statement, until its `:=`
    Prev = ''
    for T in sql_tokens(SQL):
        Text = SQL[T.start : T.end]
        if T.kind in ('space', 'comment'):
            continue
        if Target is not None:
            # A statement opened by a bind: only a bare `:=` straight after it
            # makes it the whole assignment target; `:b(1) :=` or `:b.f :=`
            # writes part of it, and a call `:b(...)` is no write.
            if Text == ':' and Prev != ':':
                Prev = Text
                continue
            if not (Text == '=' and Prev == ':'):
                Reads[Target] = True
            Writes[Target] = True
            Target = None
        Word = Text.upper() if T.kind == 'word' else ''
        if Text == ';' or Word in _PLSQL_STATEMENT_STARTS:
            Head, AtStart, IntoSeen, AfterAssign, Depth = None, True, False, False, 0
            if Word == 'ELSIF':
                Head, AtStart = Word, False  # its condition follows straight on
            Prev = Text
            continue
        Opens = AtStart
        if AtStart:
            Head, AtStart = (Word or Text), False
        if Word == 'INTO' and Prev.upper() not in ('INSERT', 'MERGE'):
            # A RETURNING's or a SELECT's INTO; `INSERT INTO` names a table.
            IntoSeen = True
        elif Word == 'FROM':
            IntoSeen = False  # a SELECT's INTO list ends at its FROM
        elif Prev == ':' and Text == '=':
            AfterAssign, Depth = True, 0
        elif Text == '(':
            Depth += 1
        elif Text == ')':
            Depth -= 1
        if T.kind == 'bind' and _NAMED_BIND_RE.fullmatch(SQL, T.start, T.end):
            Name = SQL[T.start + 1 : T.end]
            Entry = (
                (Name[1:-1], True) if Name.startswith('"') else (Name.upper(), False)
            )
            At = Position[Entry]
            if Head in _SQL_STATEMENT_HEADS:
                if IntoSeen:
                    Writes[At] = True
                else:
                    Reads[At] = True
            elif Opens:
                Target = At
            elif Depth == 0 and (AfterAssign or Head in _PLSQL_CONDITION_HEADS):
                Reads[At] = True
            else:
                Reads[At] = Writes[At] = True
        Prev = Text
    if Target is not None:
        Reads[Target] = Writes[Target] = True
    return [
        'IN OUT' if Reads[I] and Writes[I] else 'OUT' if Writes[I] else 'IN'
        for I in range(num_binds)
    ]
