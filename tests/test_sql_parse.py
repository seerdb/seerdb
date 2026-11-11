# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the client-side SQL-text parsers (#439).

``is_plsql`` classifies a statement as a PL/SQL block (so execute picks the
anonymous-block path and the temp-LOB promotion), and ``extract_bind_names``
pulls the ``:name`` placeholders a dict bind is matched against. Both must see
through leading comments and quoted text.

A placeholder name is returned in its lookup form: an unquoted one folds to
upper, since it is case-insensitive, while a quoted ``:"name"`` keeps its exact
text, since it is not (#686). The scenarios (comment-led
SELECT/DML/PLSQL classification and named-bind extraction) cover the same
ground as go-ora's statement/parse tests.
"""

import unittest

from seerdb.client.cursor import _resolve_parameters
from seerdb.common.sqltext import (
    SqlToken,
    bind_placeholders,
    canonical_bind_key,
    extract_bind_names,
    is_plsql,
    is_reusable_dml,
    sql_tokens,
    statement_head,
    strip_non_bind_text,
)


class TestStatementHead(unittest.TestCase):
    # What kind of statement it is is read off its first word; a comment ahead
    # of it must not change that. `/* why */ SELECT` was taken for DML.
    def test_leading_comments_and_whitespace_go(self):
        self.assertEqual(
            statement_head('/* why */ select 1 from dual'), 'SELECT 1 FROM DUAL'
        )
        self.assertEqual(statement_head('-- a\n  -- b\n\tselect 1'), 'SELECT 1')
        self.assertEqual(
            statement_head('  insert into t values (1)'), 'INSERT INTO T VALUES (1)'
        )

    def test_a_hint_inside_the_statement_stays(self):
        self.assertEqual(
            statement_head('select /*+ index(t) */ 1 from t'),
            'SELECT /*+ INDEX(T) */ 1 FROM T',
        )


class TestIsPlsql(unittest.TestCase):
    def test_plain_block_forms(self):
        self.assertTrue(is_plsql('BEGIN null; END;'))
        self.assertTrue(is_plsql('DECLARE x number; BEGIN null; END;'))

    def test_case_insensitive_and_leading_whitespace(self):
        self.assertTrue(is_plsql('  begin null; end;'))
        self.assertTrue(is_plsql('\n\t declare x number; begin null; end;'))

    def test_leading_line_comments_before_block(self):
        # `--` line comments preceding BEGIN/DECLARE are stripped first.
        self.assertTrue(is_plsql('-- comment #1\n-- comment #2\nBEGIN null; END;'))

    def test_leading_block_comments_before_block(self):
        # `/* ... */` block comments (including multi-line) are stripped first.
        self.assertTrue(is_plsql('/* comment */ BEGIN null; END;'))
        self.assertTrue(
            is_plsql('/* multi\nline */\nDECLARE x number; BEGIN null; END;')
        )

    def test_mixed_comments_before_declare_block(self):
        sql = (
            '-- comment #1\n  -- comment #2\n/* comment #3 */\n'
            '  /* comment #4 */\nDECLARE\n  foo NUMBER := 42;\n'
            'BEGIN\n  INSERT INTO bar VALUES (foo);\nEND;\n'
        )
        self.assertTrue(is_plsql(sql))

    def test_comment_led_select_is_not_plsql(self):
        sql = '-- comment #1\n/* comment #2 */ select * from dual'
        self.assertFalse(is_plsql(sql))

    def test_comment_led_dml_is_not_plsql(self):
        sql = '/* comment */ update foo set bar = 1 where baz = 1'
        self.assertFalse(is_plsql(sql))

    def test_a_word_starting_with_begin_is_not_a_block(self):
        # `beginning` must not be mistaken for the BEGIN keyword.
        self.assertFalse(is_plsql('select beginning from t'))


class TestExtractBindNames(unittest.TestCase):
    def test_named_placeholders_in_order(self):
        sql = (
            'INSERT INTO TTB_NESTED_UDT(ID, DATA1, SEP1, DATA2, SEP2)\n'
            'VALUES(:ID, :DATA1, :SEP1, :DATA2, :SEP2)'
        )
        self.assertEqual(
            extract_bind_names(sql), ['ID', 'DATA1', 'SEP1', 'DATA2', 'SEP2']
        )

    def test_colons_inside_string_and_quoted_ident_are_ignored(self):
        sql = 'select \':notabind\', "col:notabind", :real from dual'
        self.assertEqual(extract_bind_names(sql), ['REAL'])

    def test_colons_inside_comments_are_ignored(self):
        sql = 'select :a /* :b */ , :c -- :d\nfrom dual'
        self.assertEqual(extract_bind_names(sql), ['A', 'C'])

    def test_dml_path_keeps_every_occurrence(self):
        # Plain SQL: Oracle expects one bind value per textual occurrence.
        self.assertEqual(
            extract_bind_names('select :x, :x, :y from dual'), ['X', 'X', 'Y']
        )

    def test_plsql_path_dedupes_repeats(self):
        # A PL/SQL block reuses one value per named placeholder.
        self.assertEqual(
            extract_bind_names('begin proc(:x, :x, :y); end;', dedupe=True),
            ['X', 'Y'],
        )

    def test_numeric_placeholders_are_not_named_binds(self):
        # `:1` positionals are not `:name` binds (a dict never names them).
        self.assertEqual(extract_bind_names('select :1, :name from dual'), ['NAME'])


class TestQuotedBindPlaceholders(unittest.TestCase):
    """`:"name"` — the spelling that reaches a name the plain form cannot (#686).

    A reserved word, or a name starting with a digit, is rejected outright as an
    unquoted placeholder, and quoting is how it gets through. Unlike the plain
    form it is case-sensitive, so the two spellings live in one namespace but
    fold differently.
    """

    def test_quoted_name_is_found(self):
        self.assertEqual(extract_bind_names('select :"p" from dual'), ['p'])

    def test_quoted_name_keeps_its_case(self):
        self.assertEqual(extract_bind_names('select :"p", :"P" from dual'), ['p', 'P'])

    def test_quoted_and_plain_are_told_apart(self):
        # Both fold to the same string, so the spelling is what distinguishes
        # them. This is the pair that a name alone cannot resolve.
        self.assertEqual(
            bind_placeholders('select :"P", :p from dual'),
            [('P', True), ('P', False)],
        )

    def test_names_the_plain_form_cannot_express(self):
        self.assertEqual(extract_bind_names('select :"desc" from dual'), ['desc'])
        self.assertEqual(extract_bind_names('select :"2x" from dual'), ['2x'])

    def test_a_quoted_identifier_is_still_not_a_bind(self):
        # The closing quote of a bind name must not open an identifier and
        # swallow the rest of the statement, which is what a naive scan does.
        sql = 'insert into "T" ("C") values (:"a") returning "C" into :"b"'
        self.assertEqual(extract_bind_names(sql), ['a', 'b'])

    def test_quoted_name_inside_a_string_literal_is_ignored(self):
        sql = 'select \':"a"\', :"b" from dual'
        self.assertEqual(extract_bind_names(sql), ['b'])


class TestBindKeyMatching(unittest.TestCase):
    """Which caller-supplied keys reach which placeholder.

    Matches python-oracledb: an unquoted key folds to upper, a quoted one is
    taken literally. So `:"P"` is reachable as both `'"P"'` and `'p'`, while
    `:"p"` is reachable only as `'"p"'`.
    """

    def test_key_forms(self):
        self.assertEqual(canonical_bind_key('p'), 'P')
        self.assertEqual(canonical_bind_key('"p"'), 'p')
        self.assertEqual(canonical_bind_key('"P"'), 'P')

    def test_upper_quoted_placeholder_accepts_either_spelling(self):
        sql = 'select :"P" from dual'
        for key in ('"P"', 'P', 'p'):
            self.assertEqual(_resolve_parameters(sql, {key: 1}), [1], key)

    def test_lower_quoted_placeholder_needs_the_quoted_key(self):
        sql = 'select :"p" from dual'
        self.assertEqual(_resolve_parameters(sql, {'"p"': 1}), [1])
        for key in ('p', 'P', '"P"'):
            with self.assertRaises(Exception) as ctx:
                _resolve_parameters(sql, {key: 1})
            self.assertIn(':"p"', str(ctx.exception))

    def test_plain_placeholder_rejects_a_quoted_key(self):
        with self.assertRaises(Exception):
            _resolve_parameters('select :q from dual', {'"q"': 1})

    def test_a_quoted_and_a_plain_bind_in_one_statement(self):
        self.assertEqual(
            _resolve_parameters('select :"a" + :b from dual', {'"a"': 1, 'b': 2}),
            [1, 2],
        )


class TestReusableDml(unittest.TestCase):
    """Which statements may have their server cursor reused (#703).

    Reusing a cursor is a parse saved: the statement is parsed once and executed
    again per set of bind values. That is true of DML and of nothing else. DDL
    does its work when the server *parses* it, so a re-execute has nothing left
    to do -- the server reports success and the statement never happens, without
    raising anything. A `CREATE TABLE` issued twice silently created nothing the
    second time, on every server old enough to use the cache.
    """

    def test_the_four_that_may_be_reused(self):
        for sql in (
            'insert into t values (1)',
            'UPDATE t SET a = 1',
            'delete from t where id = 1',
            'merge into t using s on (t.id = s.id) when matched then update set a = 1',
        ):
            self.assertTrue(is_reusable_dml(sql), sql)

    def test_ddl_may_not_be(self):
        for sql in (
            'create table t (id number)',
            'drop table t',
            'alter table t add c number',
            'truncate table t',
            'create or replace view v as select 1 from dual',
            "comment on table t is 'x'",
            'grant select on t to someone',
            'rename t to u',
        ):
            self.assertFalse(is_reusable_dml(sql), sql)

    def test_leading_comments_and_whitespace_do_not_hide_the_verb(self):
        self.assertTrue(is_reusable_dml('  /* note */ insert into t values (1)'))
        self.assertFalse(is_reusable_dml('  -- note\ncreate table t (id number)'))

    def test_anything_unrecognised_is_excluded(self):
        # Wrong in this direction costs a re-parse; wrong in the other loses the
        # statement, so the default has to be "do not reuse".
        for sql in ('call p()', 'explain plan for select 1 from dual', 'commit', ''):
            self.assertFalse(is_reusable_dml(sql), sql)


if __name__ == '__main__':
    unittest.main()


def test_placeholder_count_counts_named_and_numbered() -> None:
    # A parse sizes its NULL values by this, and a numbered placeholder is one
    # too (#1394); a repeat, a `::` cast, a literal and a comment are not new.
    from seerdb.common.sqltext import placeholder_count

    assert placeholder_count('insert into t (n) values (:1)') == 1
    assert placeholder_count('select :1, :b, :"q", :1, :B from t') == 3
    assert placeholder_count("select x::int, ':9' from t -- :8") == 0


def _kinds(sql: str) -> list[tuple[str, str]]:
    return [(t.kind, sql[t.start : t.end]) for t in sql_tokens(sql)]


class TestSqlTokens(unittest.TestCase):
    """One reading of Oracle statement text for every scanner (#1679)."""

    def test_the_spans_cover_the_whole_text(self):
        sql = 'select :a, \'x\'\'y\', "Q""" -- c\n/* d */ from t where n = :1 and m::int = 2'
        tokens = list(sql_tokens(sql))
        self.assertEqual(''.join(sql[t.start : t.end] for t in tokens), sql)
        self.assertEqual(tokens[0], SqlToken('word', 0, 6))

    def test_kinds(self):
        self.assertEqual(
            _kinds('x := :a||\'b\'||"C" -- d'),
            [
                ('word', 'x'),
                ('space', ' '),
                ('other', ':'),
                ('other', '='),
                ('space', ' '),
                ('bind', ':a'),
                ('other', '|'),
                ('other', '|'),
                ('string', "'b'"),
                ('other', '|'),
                ('other', '|'),
                ('identifier', '"C"'),
                ('space', ' '),
                ('comment', '-- d'),
            ],
        )

    def test_alternative_quoting(self):
        # q'<d>...<d>' with a bracket closing on its pair and any other
        # delimiter on itself, N and Q in either case, an apostrophe inside.
        for literal in (
            "q'[it's :z]'",
            "Q'(a)b:z)'",
            "q'{x}'",
            "q'<x>'",
            "q'!it's :z!'",
            "nq'[x]'",
            "NQ'#x#'",
            "N'it''s'",
        ):
            with self.subTest(literal=literal):
                sql = f'select {literal} from t where x = :b'
                self.assertIn(('string', literal), _kinds(sql))
                self.assertEqual(bind_placeholders(sql), [('B', False)])

    def test_a_comment_holds_no_bind_and_opens_no_string(self):
        for sql in (
            "select :a -- don't :c\n from t where x = :b",
            "select :a /* it's :c */ from t where x = :b",
            "select :a -- it's\n, 'a' -- don't\n from t where x = :b",
        ):
            with self.subTest(sql=sql):
                self.assertEqual(bind_placeholders(sql), [('A', False), ('B', False)])

    def test_a_cast_is_no_bind(self):
        self.assertEqual(
            bind_placeholders('select :a::int, x::text from t'), [('A', False)]
        )

    def test_a_quoted_bind_may_have_space_after_its_colon(self):
        self.assertIn(('bind', ': "a b"'), _kinds('select : "a b" from t'))

    def test_unterminated_runs_to_the_end(self):
        for sql, kind in (
            ("select 'abc", 'string'),
            ('select "abc', 'identifier'),
            ('select /* abc', 'comment'),
            ("select q'[abc", 'string'),
        ):
            with self.subTest(sql=sql):
                self.assertEqual(_kinds(sql)[-1][0], kind)

    def test_blanking_keeps_offsets(self):
        sql = "select q'[:z]', 'a' /* :c */ from t where x = :b -- :d"
        cleaned = strip_non_bind_text(sql)
        self.assertEqual(len(cleaned), len(sql))
        self.assertEqual(cleaned.index(':b'), sql.index(':b'))
        self.assertNotIn(':z', cleaned)
        self.assertNotIn(':c', cleaned)
        self.assertNotIn(':d', cleaned)

    def test_a_long_comment_scans_in_linear_time(self):
        # The comment pattern CodeQL accepts (#1560): '/*' then '*//*'
        # repeated would backtrack forever under a lazy `.*?`.
        import time

        sql = '/*' + '*//*' * 100000
        start = time.perf_counter()
        list(sql_tokens(sql))
        self.assertLess(time.perf_counter() - start, 2.0)


class TestPlsqlBindDirections(unittest.TestCase):
    """The bind directions the Mirror reports for a block a backend cannot ask
    a server about (#1783): IN only where every use reads, OUT only where every
    use is an embedded SQL statement's INTO target, IN OUT for the rest."""

    def directions(self, sql: str, count: int):
        from seerdb.common.sqltext import plsql_bind_directions

        return plsql_bind_directions(sql, count)

    def test_a_returning_into_target_is_out(self):
        # Measured on 23ai for python-oracledb's test_connection_1229 block.
        self.assertEqual(
            self.directions(
                'begin insert into t (a, b) values (:int_val, :str_val) '
                'returning a into :out_bind; end;',
                3,
            ),
            ['IN', 'IN', 'OUT'],
        )

    def test_a_select_into_list_ends_at_from(self):
        self.assertEqual(
            self.directions('begin select c into :o from t where id = :i; end;', 2),
            ['OUT', 'IN'],
        )

    def test_reads_in_dml_are_in(self):
        self.assertEqual(
            self.directions(
                'begin update t set c = :v where id = :i; '
                'merge into t using dual on (t.id = :k) when matched then update '
                'set c = :v; end;',
                3,
            ),
            ['IN', 'IN', 'IN'],
        )

    def test_an_assignment_target_is_out(self):
        # Each answer measured on 23ai Free 23.26.2 (#2453).
        for Sql, Count, Want in (
            ("begin :result := 'got ' || :given; end;", 2, ['OUT', 'IN']),
            ('begin :x := :y + 1; end;', 2, ['OUT', 'IN']),
            ('begin :r := 1; end;', 1, ['OUT']),
            ('begin\n  :r\n  :=\n  2;\nend;', 1, ['OUT']),
            ('begin :r:=2; end;', 1, ['OUT']),
            ('begin :r := 1; :r := 2; end;', 1, ['OUT']),
            ('begin if 1 = 0 then :r := 1; end if; end;', 1, ['OUT']),
            ('begin :r := 1; exception when others then :r := 2; end;', 1, ['OUT']),
            ('declare v number := :a; begin :b := v; end;', 2, ['IN', 'OUT']),
        ):
            with self.subTest(Sql):
                self.assertEqual(self.directions(Sql, Count), Want)

    def test_a_condition_or_a_bound_is_read(self):
        # Measured on 23ai (#2453).
        for Sql, Count, Want in (
            ('begin if :a > 0 then :b := :a; end if; end;', 2, ['IN', 'OUT']),
            (
                'begin :b := case when :a > 0 then 1 else 0 end; end;',
                2,
                ['OUT', 'IN'],
            ),
            ('begin for i in 1 .. :n loop :t := i; end loop; end;', 2, ['IN', 'OUT']),
            (
                'begin :r := :a; if :a is null then :r := 0; end if; end;',
                2,
                ['OUT', 'IN'],
            ),
            (
                'begin if :a = 1 then null; elsif :b = 2 then null; end if; end;',
                2,
                ['IN', 'IN'],
            ),
            ('begin loop exit when :a > 0; end loop; end;', 1, ['IN']),
        ):
            with self.subTest(Sql):
                self.assertEqual(self.directions(Sql, Count), Want)

    def test_read_and_written_is_in_out(self):
        # In either order, measured on 23ai (#2453).
        for Sql, Count, Want in (
            ('begin :x := :x + 1; end;', 1, ['IN OUT']),
            ('begin :r := 1; :s := :r; end;', 2, ['IN OUT', 'OUT']),
            ('begin :r := :g; :g := 2; end;', 2, ['OUT', 'IN OUT']),
            (
                'begin select 1 into :o from dual; :p := :o; end;',
                2,
                ['IN OUT', 'OUT'],
            ),
            ('begin while :n > 0 loop :n := :n - 1; end loop; end;', 1, ['IN OUT']),
            ('begin select c into :o from t where id = :o; end;', 1, ['IN OUT']),
        ):
            with self.subTest(Sql):
                self.assertEqual(self.directions(Sql, Count), Want)

    def test_what_might_be_written_is_in_out(self):
        # A call argument takes the routine's mode, which the text doesn't say:
        # 23ai answers IN for put_line's and OUT for get_line's, and upper's
        # inside an expression IN. Each is IN OUT here, which loses nothing.
        self.assertEqual(self.directions('begin p(:a, :b); end;', 2), ['IN OUT'] * 2)
        self.assertEqual(
            self.directions('begin :r := upper(:a); end;', 2), ['OUT', 'IN OUT']
        )
        self.assertEqual(
            self.directions('begin if f(:a) then null; end if; end;', 1), ['IN OUT']
        )
        # Part of a bind written, or a bind that opens a statement as a call.
        self.assertEqual(self.directions('begin :r(1) := 2; end;', 1), ['IN OUT'])
        self.assertEqual(self.directions('begin :r.f := 2; end;', 1), ['IN OUT'])

    def test_it_gives_up_on_what_it_cannot_map(self):
        self.assertIsNone(self.directions('begin :1 := 2; end;', 1))
        self.assertIsNone(self.directions('begin :a := :b; end;', 3))
