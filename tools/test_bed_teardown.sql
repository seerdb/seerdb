-- SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
-- SPDX-License-Identifier: MIT
--
-- Undoes tools/test_bed_setup.sql (#2455). Run it as SYSDBA, in the same
-- container:
--
--   sqlplus -s / as sysdba @tools/test_bed_teardown.sql <test_user>
--
-- It leaves CREATE VIEW, CREATE PROCEDURE and EXECUTE on
-- DBMS_LOB, which the test user may have held before.

set verify off feedback off
define test_user = &1
whenever sqlerror continue

revoke select on sys.v_$session from &test_user;
revoke select on sys.v_$sesstat from &test_user;
revoke select on sys.v_$statname from &test_user;
revoke select on sys.v_$parameter from &test_user;
revoke select on sys.v_$database from &test_user;
revoke select on sys.dba_pending_transactions from &test_user;
drop directory seerdb_bfile_dir;
drop user seerdb_proxy_target cascade;
drop user seerdb_admin cascade;

prompt test bed setup removed for &test_user
exit
