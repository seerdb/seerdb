-- SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
-- SPDX-License-Identifier: MIT
--
-- Sets an Oracle test bed up for the integration tests that otherwise skip on
-- configuration alone (#2455). Run it as SYSDBA, in the container (PDB) the
-- test user lives in, on Oracle 10g or later:
--
--   sqlplus -s / as sysdba @tools/test_bed_setup.sql <test_user> [admin_password]
--
-- In a CDB, switch to the PDB first (ALTER SESSION SET CONTAINER = FREEPDB1).
-- Running it again changes nothing. It grants the test user only what the
-- tests read, and creates:
--   - DIRECTORY SEERDB_BFILE_DIR on /tmp, holding pyoracle_bfile_test.txt
--     (export SEERDB_TEST_BFILE_DIR=SEERDB_BFILE_DIR);
--   - SEERDB_PROXY_TARGET, a user the test user may connect through
--     (export SEERDB_TEST_PROXY_USER=seerdb_proxy_target);
--   - SEERDB_ADMIN, a DBA, only when an admin password is given
--     (export SEERDB_TEST_ADMIN_USER=seerdb_admin, SEERDB_TEST_ADMIN_PASSWORD).
--
-- tools/test_bed_teardown.sql undoes all of it.

set verify off feedback off serveroutput on
whenever sqlerror exit failure
-- The admin password is optional: define &2 as empty when it isn't given.
column 2 new_value 2 noprint
select null "2" from dual where 1 = 0;
define test_user = &1
define admin_password = '&2'

-- What the tests read: session counters, parameters, the database's identity.
grant select on sys.v_$session to &test_user;
grant select on sys.v_$sesstat to &test_user;
grant select on sys.v_$statname to &test_user;
grant select on sys.v_$parameter to &test_user;
grant select on sys.v_$database to &test_user;
grant create view to &test_user;
grant create procedure to &test_user;
grant execute on sys.dbms_lob to &test_user;

-- The BFILE tests read this file through this directory.
create or replace directory seerdb_bfile_dir as '/tmp';
grant read on directory seerdb_bfile_dir to &test_user;
declare
    f utl_file.file_type;
begin
    -- Binary mode: in text mode FCLOSE ends the file with a newline, and
    -- the tests compare its bytes exactly.
    f := utl_file.fopen('SEERDB_BFILE_DIR', 'pyoracle_bfile_test.txt', 'wb');
    utl_file.put_raw(f, utl_raw.cast_to_raw('hello bfile from disk'));
    utl_file.fclose(f);
end;
/

-- A user the test user may connect through. Nobody logs in as it directly,
-- so its password is random and never written down.
declare
    n number;
begin
    select count(*) into n from dba_users where username = 'SEERDB_PROXY_TARGET';
    if n = 0 then
        execute immediate 'create user seerdb_proxy_target identified by "P'
            || dbms_random.string('x', 20) || '"';
    end if;
    execute immediate 'grant create session to seerdb_proxy_target';
    execute immediate 'alter user seerdb_proxy_target grant connect through '
        || dbms_assert.simple_sql_name('&test_user');
end;
/

-- A DBA for the kill-session and pre-SHA-2-verifier tests, when asked for.
declare
    n number;
    pw varchar2(128) := '&admin_password';
begin
    if pw is not null then
        select count(*) into n from dba_users where username = 'SEERDB_ADMIN';
        if n = 0 then
            execute immediate 'create user seerdb_admin identified by "'
                || replace(pw, '"') || '"';
        else
            execute immediate 'alter user seerdb_admin identified by "'
                || replace(pw, '"') || '" account unlock';
        end if;
        execute immediate 'grant dba to seerdb_admin';
    end if;
end;
/

prompt test bed set up for &test_user
exit
