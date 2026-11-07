# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

from enum import Enum

TNS_CONNECT = 1
TNS_ACCEPT = 2
TNS_ACK = 3
TNS_REFUSE = 4
TNS_REDIRECT = 5
TNS_DATA = 6
TNS_NULL = 7
TNS_ABORT = 9
TNS_RESEND = 11
TNS_MARKER = 12
# A server reads at most this many bytes of connect data from the CONNECT packet
# itself; a longer descriptor follows in a DATA packet of its own (#1768).
TNS_MAX_CONNECT_DATA = 230
# Marker packet sub-types (#144). A break/cancel is an in-band INTERRUPT marker
# packet (type 12, body [1, 0, marker_type]) -- the universally-honoured way to
# interrupt a running call; the OOB urgent byte is an optimisation many servers
# (and rootless container networks) don't deliver.
TNS_MARKER_TYPE_BREAK = 1
TNS_MARKER_TYPE_RESET = 2
TNS_MARKER_TYPE_INTERRUPT = 3
# Global service option in the accept packet: the server can receive an
# out-of-band break (attention). When set we prefer OOB over the in-band
# marker for cancel()/call_timeout (#144).
TNS_GSO_CAN_RECV_ATTENTION = 0x0400
# Protocol-version-319 / large-SDU handshake (#155). seerdb advertises version
# 319 in the CONNECT; a server whose negotiated version is >= 315 switches to the
# 4-byte ("large") packet length, and a >= 318 server's ACCEPT carries an
# extended flags2 word whose HAS_END_OF_RESPONSE bit lets the client opt into the
# end-of-response framing that pipelining (#132) needs.
# The TNS protocol version each Oracle release answers with. A server reports one
# of these in its ACCEPT, and a client refuses a server below the version it
# needs -- python-oracledb will not talk to anything under 315 at all.
TNS_VERSION_11_2 = 314
TNS_VERSION_12_1 = 315
TNS_VERSION_12_2 = 316
TNS_VERSION_21_1 = 318
TNS_VERSION_23_1 = 319

# The capability thresholds ARE those releases, not numbers that happen to match
# them: the 4-byte packet length arrived in 12.1 and the extended flags2 word in
# 21.1. Writing them as aliases says so. It used to be written twice -- the
# releases here under capability names and again in server/handshake.py under
# release names -- and the cost was not cosmetic: `server_tns_version` could not
# see 315 as a release, so a Mirror asked for a 12.1 identity answered 314 and no
# modern thin client would connect to it (#1131).
TNS_VERSION_MIN_LARGE_SDU = TNS_VERSION_12_1  # 4-byte packet length from here up
TNS_VERSION_MIN_OOB_CHECK = TNS_VERSION_21_1  # accept carries the extended flags2
TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE = 0x02000000
TNS_CCAP_END_OF_RESPONSE = 0x20  # CCAP_TTC4 opt-in bit (#155/#132)
TTI_END_OF_RESPONSE = 29  # per-response terminator marker
# Request pipelining (#132). Several calls are sent back-to-back, each numbered
# with a ub8 token, then a PIPELINE_END message; the server tags each response
# with a matching TOKEN (33) marker and ends it with the EOR (29) marker.
TTI_MSG_TYPE_PIGGYBACK = 0x11  # piggyback message type (17)
TTI_TOKEN = 33  # response correlation marker
TNS_FUNC_PIPELINE_BEGIN = 199  # begin-pipeline piggyback
TNS_FUNC_PIPELINE_END = 200  # end-of-pipeline message
TNS_DATA_FLAGS_BEGIN_PIPELINE = 0x1000  # first pipelined packet
TNS_DATA_FLAGS_END_OF_RESPONSE = 0x2000  # the flag that terminates a response body
TNS_DATA_FLAGS_END_OF_REQUEST = 0x0800  # a pipelined call expecting a result
TNS_DATA_FLAGS_MORE = 0x0020  # non-final DATA fragment: more of the message follows
TNS_DATA_FLAGS_EOF = 0x0040  # EOF: final empty DATA packet, releases the session
TNS_PIPELINE_MODE_CONTINUE_ON_ERROR = 1
TNS_PIPELINE_MODE_ABORT_ON_ERROR = 2

# The wire's escape / null-value sentinel (0xFD). As a value-slot marker it flags
# an absent value — e.g. sqlplus / thick-OCI sends `fd 01` in an OUT bind's value
# slot (§ OUT-bind request marker), the wire carrying no bind direction.
TNS_ESCAPE_CHAR = 0xFD
# The longest value a single length byte may announce (python-oracledb's
# TNS_MAX_SHORT_LENGTH). The three bytes above it are markers, not lengths:
# 253 (0xFD) is the escape above, 254 (0xFE) opens a chunked value and 255
# (0xFF) is NULL. A 253-byte value behind a plain length byte is an escape where
# the server expects a length, and 12c+ rejects the call with ORA-03125 (#707).
# The same markers frame object-image attributes (dbobject).
TNS_MAX_SHORT_LENGTH = 252
TNS_LONG_LENGTH_INDICATOR = 0xFE
TNS_NULL_LENGTH_INDICATOR = 0xFF

# Server-side scrollable cursors (#181). The execute al8i4 array carries the
# scroll request: al8i4[9] gains the SCROLLABLE + NO_CANCEL_ON_EOF exec flags
# (keep the cursor open past EOF so it can scroll back), al8i4[10] the fetch
# orientation, al8i4[11] the 1-based fetch position (ABSOLUTE / RELATIVE).
TNS_EXEC_FLAGS_SCROLLABLE = 0x02
TNS_EXEC_FLAGS_NO_CANCEL_ON_EOF = 0x80
# al8i4[9] bit a query execute sets (oracledb-thin: implicit result sets); its
# absence is what the DBMS_SQL.RETURN_RESULT path checks for (#121). The
# reference thin client sets it on EVERY ordinary execute -- DDL, DML, array
# DML alike -- so its presence says nothing about what the execute wants.
TNS_EXEC_FLAGS_IMPLICIT_RESULTSET = 0x8000
# al8i4[9] bit that asks for the per-iteration affected-row counts of an array
# DML (arraydmlrowcounts, #18). THIS bit alone is the request; the two above
# and below it are unrelated flags that happen to share the word (#859).
TNS_EXEC_FLAGS_DML_ROWCOUNTS = 0x4000
# Exec-options word bit for a re-execute that re-runs the statement. A scroll
# re-execute must NOT set it: oracledb-thin's scroll re-execute uses FETCH-only
# options (0x8040), and leaving EXECUTE (0x20) on makes the server re-run the
# query — resetting the result set so the scroll orientation positions from the
# top and every orientation comes back empty. set_opts always forces 0x20 on for
# a Flag=0 select, so encode_dictionary_exec clears it for a scroll re-execute.
TNS_EXEC_OPTION_EXECUTE = 0x20
# The other exec-options word bits the execute encoders compose.
TNS_EXEC_OPTION_PARSE = 0x01
TNS_EXEC_OPTION_BIND = 0x08
TNS_EXEC_OPTION_FETCH = 0x40
TNS_FETCH_ORIENTATION_CURRENT = 0x01
TNS_FETCH_ORIENTATION_NEXT = 0x02
TNS_FETCH_ORIENTATION_FIRST = 0x04
TNS_FETCH_ORIENTATION_LAST = 0x08
TNS_FETCH_ORIENTATION_PRIOR = 0x10
TNS_FETCH_ORIENTATION_ABSOLUTE = 0x20
TNS_FETCH_ORIENTATION_RELATIVE = 0x40

# End-to-end application tracing attributes (#183): a SET_END_TO_END_ATTR
# piggyback (func TTI_SCID=135) tells the server which of module / action /
# client_identifier / client_info / dbop changed and carries the new values.
# Flag bits (which attributes the piggyback updates).
TNS_FUNC_SET_END_TO_END_ATTR = 135  # == TTI_SCID, 0x87
TNS_END_TO_END_CLIENT_IDENTIFIER = 0x0001
TNS_END_TO_END_MODULE = 0x0008
TNS_END_TO_END_ACTION = 0x0010
TNS_END_TO_END_CLIENT_INFO = 0x0100
TNS_END_TO_END_DBOP = 0x0200

# End-user security context (#460, milestone #29): a piggyback (func 205) that
# attaches an end-user identity / authorization context to the session for Deep
# Data Security (proxy / real-application-user scenarios). Carries a single
# keyword-value pair whose value is the OSON image of the context. Negotiated
# via the FEATURE_BACKPORT2 capability bit; the reference thin client restricts
# it to TLS (tcps) transports.
TNS_FUNC_END_USER_SECURITY_CTX = 205  # 0xCD
TNS_SECURITY_CONTEXT_ATTACH_FLAG = 0x01
# The bit in compile_caps[CCAP_FEATURE_BACKPORT2] that advertises it; 26ai
# advertises caps[45] = 0x03.
CCAP_FEATURE_BACKPORT2_END_USER_SEC = 0x02

# Application context (#1775): a piggyback (func 154) that sets or clears the
# attributes of one namespace, as DBMS_SESSION.SET_CONTEXT / CLEAR_CONTEXT
# would, with no round trip of its own. A client advertises it with bit 0x80 of
# its CCAP_OCI1 capability (seerdb's 0x90 has it); the server advertises
# nothing. The longest key and value the reference thin client accepts, in bytes.
TNS_FUNC_APP_CONTEXT = 154  # 0x9A
TNS_APP_CONTEXT_FLAG_SET = 0x01
TNS_APP_CONTEXT_FLAG_CLEAR = 0x02
APP_CONTEXT_KEY_MAX_LEN = 128
APP_CONTEXT_VALUE_MAX_LEN = 4000

# Transaction priority (#1776, 23ai and later): an ALTER SESSION piggyback (func
# 204) carries TXN_PRIORITY=<value> as one keyword-value pair, flag 1 for an empty
# value, which restores the default. A server refuses it (ORA-03115) unless the
# client's data-type table declares TNS_DATA_TYPE_ALTSESS. The server reports
# the session's priority as keyword 204 of a SYNC piggyback, at login and after a
# change, to a client advertising CCAP_FEATURE_BACKPORT2_TXN_PRIORITY; it
# advertises the same bit itself when it has the feature.
TNS_FUNC_ALTER_SESSION = 204  # 0xCC
TNS_DATA_TYPE_ALTSESS = 668
TNS_KEYWORD_NUM_TXN_PRIORITY = 204
CCAP_FEATURE_BACKPORT2_TXN_PRIORITY = 0x01

# Request boundaries (#464): a SESSION_STATE piggyback (func 176) that tells the
# server when a pooled logical request begins / ends, so it can reset or reclaim
# session state between requests. Body is ub8(state | EXPLICIT_BOUNDARY).
TNS_FUNC_SESSION_STATE = 176  # 0xB0
TNS_SESSION_STATE_REQUEST_BEGIN = 0x04
TNS_SESSION_STATE_REQUEST_END = 0x08
TNS_SESSION_STATE_EXPLICIT_BOUNDARY = 0x40
# The feature is negotiated by two capability bits, a compile-time one in
# compile_caps[CCAP_TTC4] and a runtime one in runtime_caps[RCAP_TTC]. The
# compile bit shares its value with the piggyback flag above, but it is a
# different field: an advertisement, where the flag marks a boundary. They stay
# two names so either can change without the other.
CCAP_TTC4_EXPLICIT_BOUNDARY = 0x40
RCAP_TTC_SESSION_STATE_OPS = 0x10

# The OER's call_status is a flag word, not a result code (§6.5). This is the bit
# a server sets while the session has an uncommitted transaction, and a client
# reads it to decide whether releasing or closing the connection owes a rollback.
# A server that never sets it tells every client there is nothing to roll back,
# so the transaction (and its locks) outlive the connection (#889).
TNS_EOCS_FLAGS_TXN_IN_PROGRESS = 0x02

# The OER's warn-flags byte (the last of the six single-byte fields after the
# error position). Bit 0x20 says the call CREATED a PL/SQL object that compiled
# with errors: the statement succeeded and the object exists, invalid (#993).
TNS_OER_WARN_COMPILATION_ERROR = 0x20

# The two ORA codes an OER carries as control flow rather than as a failure: a
# caller that raises on either of them is wrong (#1051). Decimal, unlike the
# flags and masks above -- an ORA number IS its decimal spelling, so 1403 reads
# back as the ORA-01403 a user sees and 0x57B would not.
#
# ORA-01403 is how the server says a result set is drained -- the fetch loop's
# terminator, not an error. It is only benign for a statement that produces
# rows, though: a PL/SQL block's SELECT INTO raises the same code for real, and
# masking it there turned "no rows" into None (#1039).
ORA_NO_DATA_FOUND = 1403
# ORA-24381 summarises an array-DML execute that ran with batcherrors on and
# collected per-row failures. The batch ran and the cursor is still usable; the
# rows that failed are read back through getbatcherrors() (#18).
ORA_ARRAY_DML_ERRORS = 24381

# Every other ORA code seerdb raises, answers with or tests for (#1334): the
# client, the Mirror and the example backends name them here and nowhere else.
# Each is named after Oracle's message (its PL/SQL exception, TOO_MANY_ROWS,
# where that is the handle people know) and, like the two above, decimal.
ORA_UNIQUE_CONSTRAINT_VIOLATED = 1
ORA_INVALID_SESSION_ID = 26  # missing or invalid session ID
ORA_CANNOT_KILL_CURRENT_SESSION = 27
ORA_SESSION_TERMINATED = 28  # a killed session's next call
ORA_SESSION_ID_DOES_NOT_EXIST = 30
ORA_RESOURCE_BUSY = 54  # resource busy and acquire with NOWAIT specified
ORA_INTERNAL_ERROR = 600
ORA_INVALID_SQL_STATEMENT = 900
ORA_INVALID_CREATE_COMMAND = 901
ORA_INVALID_DATATYPE = 902
ORA_INVALID_IDENTIFIER = 904
ORA_TOO_MANY_VALUES = 913
ORA_INCONSISTENT_DATATYPES = 932  # a NUMBER into a ROWID, say
ORA_TABLE_OR_VIEW_DOES_NOT_EXIST = 942
ORA_NOT_ENOUGH_VALUES = 947
ORA_NAME_ALREADY_USED = 955  # name is already used by an existing object
ORA_INVALID_CURSOR = 1001
ORA_USER_REQUESTED_CANCEL = 1013  # user requested cancel of current operation
ORA_INVALID_USERNAME_PASSWORD = 1017  # invalid username/password; logon denied
ORA_INSUFFICIENT_PRIVILEGES = 1031
ORA_ORACLE_NOT_AVAILABLE = 1034
ORA_SAVEPOINT_NEVER_ESTABLISHED = 1086
ORA_USER_DOES_NOT_EXIST = 1918  # user 'X' does not exist
ORA_USER_NAME_CONFLICT = 1920  # user name 'X' conflicts with another user or role name
ORA_CASCADE_REQUIRED = 1922  # CASCADE must be specified to drop 'X'
ORA_CANNOT_INSERT_NULL = 1400
ORA_INVALID_ROWID = 1410
ORA_TOO_MANY_ROWS = 1422  # exact fetch returns more than requested number of rows
ORA_INVALID_HEX_NUMBER = 1465
ORA_NUMERIC_OVERFLOW = 1426
ORA_VALUE_LARGER_THAN_PRECISION = 1438  # ... precision allowed for this column
ORA_DIVISOR_IS_ZERO = 1476  # divisor is equal to zero
ORA_INVALID_NUMBER = 1722
ORA_INVALID_BIND_VARIABLE_NAME = 1745  # invalid host/bind variable name
ORA_TRANSACTION_ROLLED_BACK = 2091  # a deferred constraint refused the COMMIT
ORA_CHECK_CONSTRAINT_VIOLATED = 2290
ORA_PARENT_KEY_NOT_FOUND = 2291  # integrity constraint violated - parent key not found
ORA_TYPE_HAS_DEPENDENTS = 2303  # cannot drop or replace a type with ... dependents
ORA_NUMERIC_OR_VALUE_ERROR = 6502  # PL/SQL: numeric or value error
ORA_PLSQL_COMPILATION_ERROR = 6550  # line %s, column %s: <the PLS- error>
ORA_UNIMPLEMENTED_FEATURE = 3001
ORA_UNSUPPORTED_NETWORK_DATATYPE = 3115  # ... datatype or representation
ORA_VALUE_TOO_LARGE_FOR_COLUMN = 12899
ORA_INVALID_LOB_LOCATOR = 22275  # invalid LOB locator specified
ORA_NONEXISTENT_FILE = 22285  # non-existent directory or file for FILEOPEN
ORA_LOB_NOT_OPENED = 22289  # cannot perform operation on an unopened file or LOB
ORA_LOB_ALREADY_OPENED = 22293  # LOB already opened in the same transaction
ORA_DEQUEUE_TIMEOUT = 25228  # timeout or end-of-fetch during message dequeue
ORA_LISTEN_TIMEOUT = 25254  # time-out in LISTEN while waiting for a message
ORA_PASSWORD_TOO_LONG = 28218  # password length more than 1024 bytes
ORA_NO_DATA_GUIDE = 40582  # the collection has no data-guide-enabled index
ORA_VECTOR_DIMENSION_MISMATCH = 51803  # vector dimension count must match the column's
ORA_VECTOR_INVALID_VALUE = 51805  # a dimension value that is not a number (NaN)
ORA_VECTOR_VALUE_OUT_OF_RANGE = 51806  # a dimension value outside the format's range
ORA_VECTOR_NORM_OUT_OF_RANGE = 51807  # a dense dimension value that is infinite
ORA_VECTOR_BINARY_DIMENSIONS = 51813  # a BINARY vector's dimensions: a multiple of 8

# The describe's vector-metadata flags byte (23.4+). A VECTOR column that allows
# ANY number of dimensions says so HERE, not by its dimension count -- the count
# alongside this bit is 0 and means nothing, so reporting it claims the column
# holds zero-element vectors (#1012). SPARSE marks a sparse VECTOR column.
VECTOR_FLAG_FLEXIBLE_DIM = 0x01
VECTOR_FLAG_SPARSE = 0x02

TNS_ATTENTION = 13
TNS_CONTROL = 14
TNS_MAX = 19

TNS_TYPE_CHAR = 96
TNS_TYPE_VARCHAR = 1
TNS_TYPE_VCS = 9
TNS_TYPE_NUMBER = 2
# Oracle's native signed integer (pls_integer / binary_integer). A client
# declares it for a numeric PL/SQL OUT bind, and an overloaded procedure
# resolves on it -- forwarding such a bind as VARCHAR makes the call
# ambiguous (PLS-00307) even though the value itself is fine (#888).
TNS_TYPE_INT = 3
TNS_TYPE_FLOAT = 4
TNS_TYPE_VARNUM = 6
TNS_TYPE_LONG = 8
TNS_TYPE_LONGRAW = 24
TNS_TYPE_RAW = 23
TNS_TYPE_VBI = 15
TNS_TYPE_RID = 11
TNS_TYPE_ROWID = 104
TNS_TYPE_UROWID = 208
TNS_TYPE_REFCURSOR = 102
TNS_TYPE_RSET = 116
TNS_TYPE_DATE = 12
TNS_TYPE_TIMESTAMP = 180
TNS_TYPE_TIMESTAMPTZ = 181
TNS_TYPE_TIMESTAMPLTZ = 231
TNS_TYPE_INTERVALYM = 182
TNS_TYPE_INTERVALDS = 183
TNS_TYPE_CLOB = 112
TNS_TYPE_BLOB = 113
TNS_TYPE_BFILE = 114
TNS_TYPE_BFLOAT = 100
TNS_TYPE_BDOUBLE = 101
TNS_TYPE_ADT = 109
TNS_TYPE_OPAQUE = 58  # an OCI opaque type: XMLTYPE, as sqlplus is told it (#2050)
TNS_TYPE_REF = 111
TNS_TYPE_JSON = 119  # native JSON (OSON), 21c+ (#30)
TNS_TYPE_BOOLEAN = 252  # native SQL BOOLEAN, 23ai+ (#54)
TNS_TYPE_VECTOR = 127  # native VECTOR, 23ai+ (#55)

TTI_PRO = 1
TTI_DTY = 2
TTI_FUN = 3
TTI_OER = 4
TTI_RXH = 6
TTI_RXD = 7
TTI_RPA = 8
TTI_STA = 9
TTI_ROW = 10
TTI_IOV = 11
TTI_UDS = 12
TTI_OAC = 13
TTI_LOB = 14
TTI_WRN = 15
TTI_DCB = 16
TTI_PFN = 17
TTI_FOB = 19
TTI_BVC = 21
TTI_IRD = 27  # implicit result-set describe (DBMS_SQL.RETURN_RESULT, #121)

# Two-phase commit / XA (#131). Function codes + operations + states.
TNS_FUNC_TPC_TXN_SWITCH = 103  # tpc_begin (start) / tpc_end (detach)
TNS_FUNC_TPC_TXN_CHANGE_STATE = 104  # tpc_prepare / commit / rollback / forget
TNS_TPC_TXN_START = 0x01
TNS_TPC_TXN_DETACH = 0x02
TNS_TPC_TXN_COMMIT = 0x01
TNS_TPC_TXN_ABORT = 0x02
TNS_TPC_TXN_PREPARE = 0x03
TNS_TPC_TXN_FORGET = 0x04
TNS_TPC_TXN_STATE_PREPARE = 0
TNS_TPC_TXN_STATE_REQUIRES_COMMIT = 1
TNS_TPC_TXN_STATE_COMMITTED = 2
TNS_TPC_TXN_STATE_ABORTED = 3
TNS_TPC_TXN_STATE_READ_ONLY = 4
TNS_TPC_TXN_STATE_FORGOTTEN = 5
# tpc_begin flags
TPC_BEGIN_NEW = 0x00000001
TPC_BEGIN_JOIN = 0x00000002
TPC_BEGIN_RESUME = 0x00000004
TPC_BEGIN_PROMOTE = 0x00000008
# tpc_end flags
TPC_END_NORMAL = 0x00000000
TPC_END_SUSPEND = 0x00100000
# Sessionless transactions (#133, 23ai). They reuse the func-103 switch message
# with the SESSIONLESS flag OR'd into the start/resume/detach flags, and a fixed
# magic format-id carried in the XID slot (the user txn id goes in the gtrid).
# Confirmed on the wire (23ai 23.26) against the oracledb-thin reference.
TPC_TXN_FLAGS_SESSIONLESS = 0x00000010
TNS_TPC_SESSIONLESS_FORMAT_ID = 0x4E5C3E
TNS_SESSIONLESS_TXN_ID_MAX = 64

# DRCP session purity (#130).
PURITY_DEFAULT = 0
PURITY_NEW = 1
PURITY_SELF = 2

# Server-side piggyback (#130): a response token (23) the server prepends to
# carry session-state updates — DRCP-pooled sessions get SESS_RET + OS_PID_MTS.
TTI_SVR_PIGGYBACK = 23
TNS_SERVER_PIGGYBACK_QUERY_CACHE_INVALIDATION = 1
TNS_SERVER_PIGGYBACK_OS_PID_MTS = 2
TNS_SERVER_PIGGYBACK_TRACE_EVENT = 3
TNS_SERVER_PIGGYBACK_SESS_RET = 4
TNS_SERVER_PIGGYBACK_SYNC = 5
TNS_SERVER_PIGGYBACK_LTXID = 7
TNS_SERVER_PIGGYBACK_AC_REPLAY_CONTEXT = 8
TNS_SERVER_PIGGYBACK_EXT_SYNC = 9
TNS_SERVER_PIGGYBACK_SESS_SIGNATURE = 10

# Advanced Queuing (#128).
TNS_FUNC_AQ_ENQ = 121
TNS_FUNC_AQ_DEQ = 122
TNS_FUNC_ARRAY_AQ = 145
TNS_AQ_ARRAY_ENQ = 0x01
TNS_AQ_ARRAY_DEQ = 0x02
TNS_AQ_ARRAY_FLAGS_RETURN_MESSAGE_ID = 0x01
TNS_AQ_MESSAGE_VERSION = 1
TNS_AQ_MESSAGE_ID_LENGTH = 16
TNS_AQ_EXT_KEYWORD_AGENT_NAME = 64
TNS_AQ_EXT_KEYWORD_AGENT_ADDRESS = 65
TNS_AQ_EXT_KEYWORD_AGENT_PROTOCOL = 66
TNS_AQ_EXT_KEYWORD_ORIGINAL_MSGID = 69
TNS_KPD_AQ_BUFMSG = 0x02
TNS_KPD_AQ_EITHER = 0x10
TNS_AQ_MSG_PERSISTENT = 1
TNS_AQ_MSG_BUFFERED = 2
TNS_AQ_MSG_PERSISTENT_OR_BUFFERED = 3
# dequeue mode / navigation / visibility / wait
TNS_AQ_DEQ_BROWSE = 1
TNS_AQ_DEQ_LOCKED = 2
TNS_AQ_DEQ_REMOVE = 3
TNS_AQ_DEQ_REMOVE_NODATA = 4
TNS_AQ_DEQ_FIRST_MSG = 1
TNS_AQ_DEQ_NEXT_TRANSACTION = 2
TNS_AQ_DEQ_NEXT_MSG = 3
TNS_AQ_DEQ_IMMEDIATE = 1
TNS_AQ_DEQ_ON_COMMIT = 2
TNS_AQ_ENQ_IMMEDIATE = 1
TNS_AQ_ENQ_ON_COMMIT = 2
TNS_AQ_DEQ_NO_WAIT = 0
TNS_AQ_DEQ_WAIT_FOREVER = 0xFFFFFFFF

TTI_OPEN = 2
TTI_EXEC = 4
TTI_FETCH = 5
TTI_LOGOFF = 9
TTI_COMON = 12
TTI_COMOFF = 13
TTI_COMMIT = 14
TTI_ROLLBACK = 15
TTI_CANCEL = 20
TTI_DSCRARR = 43
TTI_STRT = 48
TTI_STOP = 49
TTI_VERSION = 59
TTI_K2RPC = 67
TTI_ALL7 = 71
TTI_SQL7 = 74
TTI_3LOGON = 81
TTI_3LOGA = 82
TTI_KOD = 92
TTI_ALL8 = 94
TTI_LOBOPS = 96
TTI_DNY = 98
TTI_TXSE = 103
TTI_TXEN = 104
TTI_OCCA = 105
TTI_80SES = 107
TTI_AUTH = 115
TTI_SESS = 118
TTI_DESCRIBE = 119  # sqlplus `DESCRIBE <object>` (thick-OCI describe-object call)
TTI_CANA = 120
TTI_KPN = 125
TTI_OTCM = 127
TTI_SCID = 135
TTI_SPFP = 138
TTI_KPFC = 139
TTI_PING = 147

# Further Oracle TTC function / message-type codes seerdb does not dispatch yet —
# cataloged so the dispatch table and downstream RE have names, not bare numbers.
TNS_FUNC_REEXECUTE_AND_FETCH = 78  # combined re-execute + fetch round-trip
TNS_FUNC_DIRECT_PATH_PREPARE = 128
TNS_FUNC_DIRECT_PATH_LOAD_STREAM = 129
TNS_FUNC_DIRECT_PATH_OP = 130  # direct-path load (SQL*Loader path)
TNS_FUNC_SET_SCHEMA = 152  # ALTER SESSION SET CURRENT_SCHEMA fast-path
TNS_FUNC_REEXECUTE = 4  # re-run a cached cursor with fresh bind rows, no fetch
# The options_2 bit of a re-execute: commit on success (the client's autocommit).
TNS_EXEC_OPTION_COMMIT_REEXECUTE = 0x1
TNS_FUNC_SESSION_GET = 162  # DRCP pooled-session acquire (#130)
TNS_FUNC_SESSION_RELEASE = 163  # DRCP pooled-session release (#130)
TNS_FUNC_NOTIFY = 187  # CQN / AQ notification delivery (#129)
TNS_MSG_TYPE_ONEWAY_FN = 26  # fire-and-forget call, no response expected
TNS_MSG_TYPE_RENEGOTIATE = 28  # server asks the client to renegotiate (TLS / caps)

# TNS_CCAP_FIELD_VERSION_* values (the byte written at CCAP_FIELD_VERSION). The
# negotiated TTC field version gates the auth verifier and the version-specific
# wire formats. Kept here in the leaf constants module (rather than seerdb.common.tns)
# so seerdb.client.cursor can import the 12.1 threshold from a lightweight leaf
# without dragging in the whole encoder.
# Every field version, an extension always spelled _EXT_<n>; the two below 11.2
# serve the 9i / 10g paths (#1487).
# Oracle 9i (pre-10g O3LOGON thin auth, #90).
FIELD_VERSION_9_2 = 2
# Oracle 10g -- the oldest tier using the O5LOGON path.
FIELD_VERSION_10_2 = 4
FIELD_VERSION_11_2 = 6
FIELD_VERSION_12_1 = 7
FIELD_VERSION_12_2 = 8
FIELD_VERSION_12_2_EXT_1 = 9
FIELD_VERSION_18_1 = 10
# Oracle 18c; the layout the Mirror speaks to sqlplus from 12.1 (#1282).
FIELD_VERSION_18_1_EXT_1 = 11
FIELD_VERSION_19_1 = 12
# Written inside the FAST_AUTH envelope (#89).
FIELD_VERSION_19_1_EXT_1 = 13
# The AQ JSON-payload pointer gate (#128).
FIELD_VERSION_20_1 = 14
FIELD_VERSION_20_1_EXT_1 = 15
FIELD_VERSION_21_1 = 16
# The highest the LEGACY 3-message handshake reaches.
FIELD_VERSION_23_1 = 17
# From here on only FAST_AUTH reaches the version (#89).
FIELD_VERSION_23_1_EXT_1 = 18
FIELD_VERSION_23_1_EXT_2 = 19
FIELD_VERSION_23_1_EXT_3 = 20
FIELD_VERSION_23_1_EXT_4 = 21
FIELD_VERSION_23_1_EXT_5 = 22
FIELD_VERSION_23_3_EXT_6 = 23
FIELD_VERSION_23_4 = 24
# The highest this client and the Mirror speak: 23ai's.
FIELD_VERSION_MAX = FIELD_VERSION_23_4

# Indices into the compile-time capability array the handshake exchanges
# (TNS_CCAP_*); the feature bits at a few of them sit with the features they
# gate (CCAP_TTC4_EXPLICIT_BOUNDARY, CCAP_FEATURE_BACKPORT2_END_USER_SEC).
CCAP_SQL_VERSION = 0
CCAP_LOGON_TYPES = 4
# The O7LOGON bit of CCAP_LOGON_TYPES. A 12c-band server sets it (18c sends
# 0x6F); a modern sqlplus offered the 12c SHA-2 verifier derives its 256-bit
# key only when it is set, and fails the login without it (#1282).
CCAP_LOGON_O7LOGON = 0x20
CCAP_FEATURE_BACKPORT = 5
CCAP_FIELD_VERSION = 7  # gates the auth verifier + version-gated formats
CCAP_SERVER_DEFINE_CONV = 8
CCAP_DEQUEUE_WITH_SELECTOR = 9
CCAP_TTC1 = 15
CCAP_OCI1 = 16
CCAP_TDS_VERSION = 17
CCAP_RPC_VERSION = 18
CCAP_RPC_SIG = 19
CCAP_DBF_VERSION = 21
CCAP_LOB = 23
# A client that sets this bit of CCAP_LOB reads a LOB column value with the
# LOB's length (ub8) and chunk size (ub4) between the locator length and the
# locator; one without it reads the bare locator. sqlplus 23.26 sets it and
# sqlplus 11.2 does not, and a live 11g answers each in its own form, although
# the server does not set the bit itself (#1287).
CCAP_LOB_12C = 0x80
CCAP_TTC2 = 26
CCAP_UB2_DTY = 27  # 2-byte data-type ids (12c+)
CCAP_OCI2 = 31
CCAP_CLIENT_FN = 34
CCAP_OCI3 = 35
CCAP_TTC3 = 37
CCAP_SESS_SIGNATURE_VERSION = 39
CCAP_TTC4 = 40
CCAP_LOB2 = 42
CCAP_TTC5 = 44
CCAP_FEATURE_BACKPORT2 = 45
CCAP_VECTOR_FEATURES = 52

# Indices into the runtime capability array (TNS_RCAP_*) and the bits at them.
RCAP_COMPAT = 0
RCAP_TTC = 6
RCAP_COMPAT_81 = 2
RCAP_TTC_ZERO_COPY = 0x01
RCAP_TTC_32K = 0x04

# Oracle 23ai "fast auth" (#89): a single TNS DATA packet (message type 0x22)
# bundling the protocol, datatypes, and OSESSKEY messages in one round trip. It is
# the only way to advertise CCAP_FIELD_VERSION >= 18 — the legacy three-message
# handshake is rejected with ORA-03146 at fv >= 23.1 EXT 1. seerdb gates on the server's
# own field version (learned from its PRO reply, 23ai advertises 27), not an ACCEPT
# flag: at the protocol version seerdb sends (313) the ACCEPT carries no flag.
TNS_MSG_TYPE_FAST_AUTH = 0x22
TNS_SERVER_CONVERTS_CHARS = 0x01  # fast-auth envelope flag byte

DictionaryType = Enum(
    'DictionaryType',
    'auth chgpwd close description dty exec fetch lobops login pig pro sess spfp start stop tran',
)

# OALL8 execute-option bit that turns on array-DML batch-error mode: a per-row
# error is collected (in the OER batch-error arrays) instead of aborting the
# batch. ORed into the leading Opt word (#18).
TNS_EXEC_OPTION_BATCH_ERRORS = 0x80000

# Value the 12c+ OALL8 al8i4 array carries at element index 9 when array-DML
# row counts are requested (oracledb arraydmlrowcounts). oracledb always sends
# 0x8000 there; with arraydmlrowcounts it sets 0xC000 (the extra 0x4000 bit).
# seerdb's baseline is 0, so the whole 0xC000 is written when requested — the
# server's kpoal8Check rejects the al8pidmlrc pointer (below) as malformed
# (ORA-03137) without it. Reverse-engineered from an oracledb-thin capture (#18).
# What seerdb's own client writes into al8i4[9] when asking for array-DML row
# counts: the DML_ROWCOUNTS request bit together with IMPLICIT_RESULTSET, which
# every modern execute carries anyway. A real server accepts the pair (verified
# live on every 12c+ tier). It is a composite, not a flag: a server must test
# for DML_ROWCOUNTS alone, because a plain execute from the reference client
# carries IMPLICIT_RESULTSET on its own and is asking for nothing (#859).
TNS_AL8I4_ARRAY_DML_ROWCOUNTS = (
    TNS_EXEC_FLAGS_IMPLICIT_RESULTSET | TNS_EXEC_FLAGS_DML_ROWCOUNTS
)

TNS_LOB_OP_GET_LENGTH = 0x0001
TNS_LOB_OP_READ = 0x0002
TNS_LOB_OP_TRIM = 0x0020
TNS_LOB_OP_WRITE = 0x0040
TNS_LOB_OP_FILE_OPEN = 0x0100
TNS_LOB_OP_CREATE_TEMP = 0x0110
TNS_LOB_OP_FREE_TEMP = 0x0111
TNS_LOB_OP_FILE_CLOSE = 0x0200
TNS_LOB_OP_FILE_ISOPEN = 0x0400
TNS_LOB_OP_FILE_EXISTS = 0x0800
TNS_LOB_OP_GET_CHUNK_SIZE = 0x4000
TNS_LOB_OP_OPEN = 0x8000
# FILE_OPEN's mode for a BFILE opened to read (OCI_FILE_READONLY, as the native
# clients send it in the call's amount).
TNS_LOB_FILE_READONLY = 0x0B
TNS_LOB_OP_CLOSE = 0x10000
# `lob.isopen()`. Unlike OPEN / CLOSE this one owes an ANSWER -- the ack reply
# plus a trailing ub1, nonzero meaning open (§18.4). A server that acks it
# without the flag, or routes it to the read path as an unknown op, hands the
# client a reply it walks off the end of (#903/#887).
TNS_LOB_OP_IS_OPEN = 0x11000
TNS_LOB_OP_ARRAY = 0x80000  # OR-ed onto an op that carries an array of locators

# Bind OAC flag bits: every thin bind uses indicators; a PL/SQL associative-array
# bind (#122) also sets ARRAY, in the flag byte of the 12.2+ layout and in the
# second flag word of the 11g one (see encode_token_raw).
TNS_BIND_USE_INDICATORS = 0x01
TNS_BIND_ARRAY = 0x40

# Bind directions in the TTI_IOV response (one per bind, in bind order).
TNS_BIND_DIR_OUTPUT = 16
TNS_BIND_DIR_INPUT = 32
TNS_BIND_DIR_INPUT_OUTPUT = 48

ISO_LATIN_1_CHARSET = 31
UTF8_CHARSET = 871
AL32UTF8_CHARSET = 873
AL16UTF16_CHARSET = 2000

CharsetDict = {
    'we8iso8859p1': 31,
    'ee8iso8859p2': 32,
    'cl8iso8859p5': 35,
    'ee8mswin1250': 170,
    'cl8mswin1251': 171,
    'we8mswin1252': 178,
    'ja16euc': 830,
    'zhs16gbk': 852,
    'zht16big5': 865,
    'zht16mswin950': 867,
    'al32utf8': 873,
    'al16utf16': 2000,
}

DEFAULT_HOST = ''
DEFAULT_PORT = 1521
DEFAULT_SID = ''
# Packed releases, each what a captured server reports as AUTH_VERSION_NO and so
# what the Mirror's identity of that tier claims: major<<24 | minor<<20 |
# update<<12 | patch<<8 before 18c, major<<24 | update<<16 | revision<<12 from it
# (#2097). 11.2.0.2.0 is also the codec's auth-result default and the container
# version a modern thin client stamps on its ANO negotiation (ano); 23.26.2.0.0
# is also the per-service version a 26ai server echoes in its ANO response. 12.2.0.1.0 is not captured: there is no 12.2 testbed, so it is the
# release number of that line's first patch set.
VERSION_11_2_0_2 = 0x0B200200
VERSION_12_1_0_2 = 0x0C100200
VERSION_12_2_0_1 = 0x0C200100
VERSION_21_3_0_0 = 0x15030000
VERSION_23_26_2_0 = 0x171A2000
# The base releases a 21c and a 23ai name to a client before 18c, in sqlplus's
# version call (#2024).
VERSION_21_0_0_0 = 0x15000000
VERSION_23_0_0_0 = 0x17000000

# Default Session Data Unit (0x2000). The negotiated packet payload size; both
# the client connect defaults and the server (Mirror) framing start here.
DEFAULT_SDU = 8192

CONN_STATE_DISCONNECTED = 0
CONN_STATE_CONNECTED = 1
CONN_STATE_AUTH_NEGOTIATE = 2
CONN_STATE_AUTHENTICATED = 3

MAX_SEQ_NUM = 127
