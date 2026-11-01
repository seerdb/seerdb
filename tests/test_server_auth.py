# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side O5LOGON crypto, checked against seerdb's own client crypto.

seerdb.common.crypto.o5logon / validate are validated against real Oracle, so a
round-trip agreement between them and the server side is a strong conformance
signal without needing a live server.
"""

from __future__ import annotations

from binascii import unhexlify
from collections.abc import Callable, Iterator

import pytest

from seerdb.common.crypto import (
    PBKDF2_SDER_COUNT,
    PBKDF2_VGEN_COUNT,
    VFR_11G_SHA1,
    VFR_12C_SHA2,
    o5logon,
    server_proof,
    validate,
)
from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import (
    AUTH_SERIAL_NUM,
    decode_token_rpa,
    encode_challenge,
    encode_dictionary_auth,
    encode_dictionary_sess,
    encode_result,
    encode_rpa_kv,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    TTI_AUTH,
    TTI_OER,
    TTI_RPA,
    TTI_SESS,
    VERSION_11_2_0_2,
    VERSION_12_2_0_1,
    VERSION_23_26_2_0,
)
from seerdb.server.auth import (
    check_auth_complete,
    derive_conn_key,
    make_challenge,
    parse_auth_response,
    parse_osesskey,
    verify_password,
)


def _client_login(challenge, user: bytes, password: bytes):
    # Run seerdb's client O5LOGON against our challenge; returns the client's
    # AUTH_SESSKEY response and the ConnKey it derived.
    auth_pass, auth_sess, _speedy, _ind, conn = o5logon(
        challenge.auth_sesskey, challenge.salt, None, user, password
    )
    return auth_sess, auth_pass, conn


def test_both_sides_derive_the_same_session_key() -> None:
    password = b'pyo123'
    challenge = make_challenge(password)
    client_auth_sess, _pass, client_conn = _client_login(challenge, b'PYO', password)
    server_conn = derive_conn_key(challenge, client_auth_sess)
    # The crux: server and client independently arrive at the same ConnKey.
    assert server_conn == client_conn


def test_client_accepts_the_server_proof() -> None:
    password = b'pyo123'
    challenge = make_challenge(password)
    client_auth_sess, _pass, client_conn = _client_login(challenge, b'PYO', password)
    server_conn = derive_conn_key(challenge, client_auth_sess)
    # The client's validate() must accept our AUTH_SVR_RESPONSE — mutual auth.
    assert validate(server_proof(server_conn), client_conn)


def test_wrong_password_breaks_the_agreement() -> None:
    # A client that typed a different password derives a different ConnKey, so
    # mutual auth fails — the server proof is rejected.
    challenge = make_challenge(b'pyo123')
    client_auth_sess, _pass, client_conn = _client_login(challenge, b'PYO', b'wrongpw')
    server_conn = derive_conn_key(challenge, client_auth_sess)
    assert server_conn != client_conn
    assert not validate(server_proof(server_conn), client_conn)


def test_challenge_is_deterministic_when_seeded() -> None:
    a = make_challenge(b'pyo123', salt=bytes(16), server_session=bytes(48))
    b = make_challenge(b'pyo123', salt=bytes(16), server_session=bytes(48))
    assert a == b


# --- RPA wire layer ---


def test_encode_challenge_decodes_as_a_sess_challenge() -> None:
    challenge = make_challenge(b'pyo123')
    payload = encode_challenge(challenge)
    kind, sesskey, salt, derived, _vgen, _sder, _vfr = decode_token_rpa(payload[1:], ())
    assert kind == TTI_SESS
    assert unhexlify(sesskey) == challenge.auth_sesskey
    assert unhexlify(salt) == challenge.salt


def test_encode_result_decodes_as_an_auth_result() -> None:
    payload = encode_result(bytes(24), session_id=59, db_name='FREE')
    kind, resp, version, session_id, serial_num, unique = decode_token_rpa(
        payload[1:], ()
    )
    assert kind == TTI_AUTH
    assert version == VERSION_11_2_0_2
    # The numbers, as a client reads them (#1218), the serial included (#1234).
    assert session_id == 59
    assert serial_num == AUTH_SERIAL_NUM
    # The database's unique name, read from AUTH_SC_DBUNIQUE_NAME (#1774).
    assert unique == 'FREE'


def test_a_21c_result_also_sends_the_real_unique_name() -> None:
    # Presenting 21c or later, the reply carries the unique name a second time
    # as AUTH_SC_REAL_DBUNIQUE_NAME, as 21c and 23ai do; python-oracledb 26
    # reads only that one (#1777). Before 21c only the first.
    modern = encode_result(bytes(24), version_no=VERSION_23_26_2_0, db_name='FREE')
    older = encode_result(bytes(24), version_no=VERSION_12_2_0_1, db_name='FREE')
    assert b'AUTH_SC_REAL_DBUNIQUE_NAME' in modern
    assert b'AUTH_SC_REAL_DBUNIQUE_NAME' not in older
    assert decode_token_rpa(modern[1:], ())[5] == 'FREE'
    assert decode_token_rpa(older[1:], ())[5] == 'FREE'


def test_an_auth_result_prefers_the_real_unique_name() -> None:
    # 21c and later send AUTH_SC_REAL_DBUNIQUE_NAME beside AUTH_SC_DBUNIQUE_NAME;
    # the real one is the name python-oracledb reports (#1774).
    payload = encode_rpa_kv(
        [
            (b'AUTH_VERSION_NO', str(VERSION_11_2_0_2).encode()),
            (b'AUTH_SC_DBUNIQUE_NAME', b'CDB'),
            (b'AUTH_SC_REAL_DBUNIQUE_NAME', b'REAL'),
        ]
    )
    assert decode_token_rpa(payload[1:], ())[5] == 'REAL'


def test_an_auth_result_without_a_unique_name() -> None:
    # Before 10g the reply carries no unique name at all (#1774).
    payload = encode_rpa_kv([(b'AUTH_VERSION_NO', str(VERSION_11_2_0_2).encode())])
    assert decode_token_rpa(payload[1:], ())[5] is None


def test_encode_result_reports_max_open_cursors_at_12c() -> None:
    # A thin client sizes its cursors-to-close array from AUTH_MAX_OPEN_CURSORS;
    # a missing / zero value clamps it to 1, so the second cursor it closes
    # overruns with "IndexError: array assignment index out of range" -- the
    # statement-cache path every executemany and cursor reuse drives (#826).
    # A 12.1+ client reads it; a pre-12.1 reply goes without it, as 11g's does.
    from seerdb.common.tns import _ENCODE_FIELD_VERSION

    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_12_1)
    try:
        modern = encode_result(bytes(24), session_id=59)
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    assert b'AUTH_MAX_OPEN_CURSORS' in modern
    assert b'AUTH_MAX_OPEN_CURSORS' not in encode_result(bytes(24), session_id=59)


def test_encode_result_names_the_serial_at_every_version() -> None:
    # A real 11g's login reply carries AUTH_SERIAL_NUM beside AUTH_SESSION_ID
    # (the captured reply in test_tns_decode has 1725). Sending it only from
    # 12.1 left a pre-12.1 client with no serial to name its session by (#1234).
    from seerdb.common.tns import _ENCODE_FIELD_VERSION, decode_kv, decode_ub4

    def pairs(payload: bytes) -> dict:
        (count, rest) = decode_ub4(payload[1:])
        return dict(decode_kv(rest, count, [], {})[0])

    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_12_1)
    try:
        modern = pairs(encode_result(bytes(24), session_id=59, serial_num=4711))
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    legacy = pairs(encode_result(bytes(24), session_id=59, serial_num=4711))
    for reply in (modern, legacy):
        assert reply[b'AUTH_SESSION_ID'] == b'59'
        assert reply[b'AUTH_SERIAL_NUM'] == b'4711'


def test_parse_osesskey_recovers_the_username() -> None:
    request = encode_dictionary_sess(
        {'seq': 1, 'field_version': 6, 'env': {'user': 'PYO'}}
    )
    assert parse_osesskey(request) == b'PYO'


def test_parse_osesskey_oci_recovers_the_username() -> None:
    # sqlplus / thick-OCI (deadbeef dialect) OSESSKEY payloads captured from live
    # sqlplus 11.2 — two username lengths pin the fixed-offset layout (#265).
    from seerdb.server.auth import parse_osesskey_oci

    pyo = bytes.fromhex(
        '037602feffffffffffffff0900000001000000feffffffffffffff05000000'
        '00000000fefffffffffffffffeffffffffffffff0370796f270000000d4155'
        '54485f5445524d494e414c'
    )
    abcdefgh = bytes.fromhex(
        '037602feffffffffffffff1800000001000000feffffffffffffff05000000'
        '00000000fefffffffffffffffeffffffffffffff08616263646566676827'
        '0000000d415554485f5445524d494e414c'
    )
    assert parse_osesskey_oci(pyo) == b'pyo'
    assert parse_osesskey_oci(abcdefgh) == b'abcdefgh'


# sqlplus 10.2.0.5's OSESSKEY to 11g XE, captured through a logging proxy
# (#1764): the same layout as 11.2's, but its pointer fields carry the client's
# own 64-bit addresses where 11.2 writes the OCI indicator.
_OCI_OSESSKEY_10_2 = bytes.fromhex(
    '037602f0836729000000000900000001000000f0cb725afd7f000005000000b55f389e90'
    'c6725afd7f0000cccf725afd7f00000370796f270000000d415554485f5445524d494e41'
    '4c00000000000000002d0000000f415554485f50524f4752414d5f4e4d60000000207371'
    '6c706c7573403738313533366563613235312028544e532056312d563329000000002400'
    '00000c415554485f4d414348494e45240000000c37383135333665636132353100000000'
    '1800000008415554485f5049441200000006343533373830000000001800000008415554'
    '485f53494412000000066f7261636c6500000000'
)


def test_parse_osesskey_oci_takes_sqlplus_10_2s_addresses() -> None:
    # A pointer field is present when it is not zero: 10.2 fills it with an
    # address, and the parser refused anything but the indicator (#1764).
    from seerdb.server.auth import parse_osesskey_oci

    assert parse_osesskey_oci(_OCI_OSESSKEY_10_2) == b'pyo'
    # A zeroed pointer still means the message is not the shape expected.
    null_user = _OCI_OSESSKEY_10_2[:43] + bytes(8) + _OCI_OSESSKEY_10_2[51:]
    with pytest.raises(InterfaceError, match='no pointer at offset 43'):
        parse_osesskey_oci(null_user)


def test_encode_challenge_oci_substitutes_the_crypto_values() -> None:
    # The OCI challenge is the captured 390-byte template with AUTH_SESSKEY and
    # the salt substituted in place (#265). Validated live: sqlplus accepts it
    # and sends AUTH.
    import secrets

    from seerdb.server.auth import encode_challenge_oci, make_challenge

    challenge = make_challenge(b'pyo123', salt=secrets.token_bytes(10))
    packet = encode_challenge_oci(challenge)
    assert len(packet) == 390  # fixed-size values keep the packet length
    # the fresh crypto values are present where the template had the captured ones
    i_sk = packet.index(b'AUTH_SESSKEY') + len(b'AUTH_SESSKEY') + 5
    i_vfr = packet.index(b'AUTH_VFR_DATA') + len(b'AUTH_VFR_DATA') + 5
    assert packet[i_sk : i_sk + 96] == challenge.auth_sesskey.hex().upper().encode()
    assert packet[i_vfr : i_vfr + 20] == challenge.salt.hex().upper().encode()


def test_encode_challenge_oci_rejects_wrong_sizes() -> None:
    from seerdb.server.auth import encode_challenge_oci, make_challenge

    # A 16-byte salt (the thin default) doesn't fit the OCI template's 20-hex slot.
    with pytest.raises(InterfaceError):
        encode_challenge_oci(make_challenge(b'pyo123'))


# A live sqlplus 11.2 OCI AUTH, captured in reply to a *seeded* Mirror challenge
# (make_challenge(b'pyo123', salt=bytes(10), server_session=bytes(48))) so the
# whole crypto round-trip can be replayed and verified offline (#265). Carries
# the client's 48-byte AUTH_SESSKEY and its 32-byte AUTH_PASSWORD proof, both
# DALC-chunked uppercase-hex.
_OCI_AUTH_SEEDED = bytes.fromhex(
    '037303feffffffffffffff0900000001010000feffffffffffffff1200000000000000'
    'fefffffffffffffffeffffffffffffff0370796f240000000c415554485f534553534b'
    '455920010000fe40433044343734333430333531413144314237453646323138443537'
    '3734353246304441464139333041324232454636453146374538334446363141413434'
    '3436204237363142443545303830443336373239423138393336393036313332463430'
    '0001000000270000000d415554485f50415353574f5244c00000004034463144464434'
    '4436373242383342354233354131453833363131434246344342384243344330313239'
    '4235313735343935383134413131333344324636463500000000180000000841555448'
    '5f5254540c000000043232373300000000270000000d415554485f434c4e545f4d454d'
    '0c000000043430393600000000270000000d415554485f5445524d494e414c00000000'
    '000000002d0000000f415554485f50524f4752414d5f4e4d600000002073716c706c75'
    '73403735313036633766333964622028544e532056312d56332900000000240000000c'
    '415554485f4d414348494e45240000000c373531303663376633396462000000001800'
    '000008415554485f5049440c0000000433323630000000001800000008415554485f53'
    '494412000000066f7261636c6500000000420000001653455353494f4e5f434c49454e'
    '545f4348415253455403000000013100000000450000001753455353494f4e5f434c49'
    '454e545f4c49425f54595045030000000131000000004e0000001a53455353494f4e5f'
    '434c49454e545f4452495645525f4e414d451b0000000953514c2a504c555320000000'
    '00420000001653455353494f4e5f434c49454e545f56455253494f4e1b000000093138'
    '3636343730343000000000420000001653455353494f4e5f434c49454e545f4c4f4241'
    '545452030000000131000000001800000008415554485f41434c0c0000000438303030'
    '000000003600000012415554485f414c5445525f53455353494f4e6f00000025414c54'
    '45522053455353494f4e205345542054494d455f5a4f4e453d272b30303a3030270001'
    '0000004500000017415554485f4c4f474943414c5f53455353494f4e5f494460000000'
    '2035384238464533453933303344453938453036304138433043303030304342430000'
    '00003000000010415554485f4641494c4f5645525f49440000000000000000'
)


def test_parse_auth_response_oci_recovers_the_secrets() -> None:
    from seerdb.server.auth import parse_auth_response_oci

    user, sesskey, password = parse_auth_response_oci(_OCI_AUTH_SEEDED)
    assert user == b'pyo'
    assert len(sesskey) == 48  # client AUTH_SESSKEY, 96 hex on the wire
    assert len(password) == 32  # AUTH_PASSWORD proof, 64 hex on the wire


def test_an_oci_pair_count_is_a_ub4_whatever_follows_it() -> None:
    # The count's slot is eight bytes and the client sets only the low four:
    # 10.2 leaves address bytes above them, 11.2 whatever its buffer held. Read
    # as a ub8 they made a count in the billions and a login that never
    # finished (#2249).
    from seerdb.common.tns import decode_auth_oci_head
    from seerdb.server.auth import parse_auth_response_oci

    assert decode_auth_oci_head(_OCI_OSESSKEY_10_2)['pair_count'] == 5
    unset = _OCI_AUTH_SEEDED[:31] + bytes.fromhex('b55f389e') + _OCI_AUTH_SEEDED[35:]
    assert decode_auth_oci_head(unset)['pair_count'] == 18
    assert parse_auth_response_oci(unset) == parse_auth_response_oci(_OCI_AUTH_SEEDED)


def test_an_oci_auth_that_declares_more_pairs_than_it_carries_is_refused() -> None:
    # The pair count is the message's own word; a client that declares 2**32-1
    # pairs and sends none kept a session thread decoding empty pairs for about
    # 100 minutes, before the password was checked (#2272). It fails at once.
    import time

    from seerdb.common.tns import decode_auth_oci

    head = _OCI_AUTH_SEEDED[:27] + (2**32 - 1).to_bytes(4, 'little') + bytes(4)
    head += _OCI_AUTH_SEEDED[35:55]  # the pointers and the user, no pairs
    started = time.monotonic()
    with pytest.raises(IndexError):
        decode_auth_oci(head)
    assert time.monotonic() - started < 1


def test_an_oci_fixed_width_read_past_the_end_raises() -> None:
    # Read as 0 or "absent", an exhausted buffer let a count run (#2272).
    from seerdb.common.tns import _OCI, _OCI_WIDE

    for read, width in (
        (_OCI.read_n2, 2),
        (_OCI.read_n4, 4),
        (_OCI.read_n8, 8),
        (_OCI.read_ptr, 8),
        (_OCI.read_scale, 1),
        (_OCI_WIDE.read_wn4, 8),
    ):
        read(bytes(width))  # a whole field reads
        with pytest.raises(IndexError):
            read(bytes(width - 1))


def test_server_proof_oci_is_the_48_byte_deadbeef_form() -> None:
    from seerdb.server.auth import server_proof_oci

    conn = bytes(24)  # any 192-bit ConnKey
    proof = server_proof_oci(conn, nonce=bytes(16))
    assert len(proof) == 48  # nonce(16) + SERVER_TO_CLIENT(16) + PKCS7 pad(16)
    assert validate(proof, conn)  # decrypts to contain the SERVER_TO_CLIENT marker
    with pytest.raises(InterfaceError):
        server_proof_oci(conn, nonce=bytes(8))  # wrong nonce size


def test_encode_result_oci_validates_against_the_client() -> None:
    # The result the Mirror sends after verifying the OCI AUTH: reconstruct the
    # ConnKey from the seeded challenge + the live AUTH, encode the result, and
    # confirm the substituted AUTH_SVR_RESPONSE validates (#265).
    from binascii import unhexlify

    from seerdb.server.auth import (
        derive_conn_key,
        encode_result_oci,
        parse_auth_response_oci,
    )

    challenge = make_challenge(b'pyo123', salt=bytes(10), server_session=bytes(48))
    _user, sesskey, _password = parse_auth_response_oci(_OCI_AUTH_SEEDED)
    conn = derive_conn_key(challenge, sesskey)

    packet = encode_result_oci(conn, nonce=bytes(16))
    assert len(packet) == 1762  # fixed-size proof keeps the template length
    i = packet.find(b'AUTH_SVR_RESPONSE') + len(b'AUTH_SVR_RESPONSE') + 5
    proof = unhexlify(packet[i : i + 96])
    # if the write offset and the value framing disagreed, this proof would be
    # the template's stale one and fail against the reconstructed ConnKey.
    assert validate(proof, conn)


def test_full_oci_auth_verifies_against_live_sqlplus() -> None:
    # The OCI counterpart of the thin round-trip below, but the AUTH is REAL
    # sqlplus 11.2 bytes (not seerdb's own client encoder). Reconstruct the exact
    # seeded challenge sqlplus answered, parse its AUTH, and drive the full mutual
    # auth: the ConnKey derives, the right password verifies (a wrong one does
    # not), and our server proof validates. End-to-end conformance, offline (#265).
    from seerdb.server.auth import derive_conn_key, parse_auth_response_oci

    challenge = make_challenge(b'pyo123', salt=bytes(10), server_session=bytes(48))
    user, sesskey, password = parse_auth_response_oci(_OCI_AUTH_SEEDED)
    assert user == b'pyo'
    server_conn = derive_conn_key(challenge, sesskey)
    assert verify_password(server_conn, password, b'pyo123')
    assert not verify_password(server_conn, password, b'wrongpass')
    assert validate(server_proof(server_conn), server_conn)


def test_full_auth_roundtrip_through_seerdb_client_encoders() -> None:
    # End-to-end: our challenge -> seerdb's client AUTH message -> our parse +
    # ConnKey derivation -> our result -> the client's validate() accepts it.
    password = 'pyo123'
    challenge = make_challenge(password.encode())
    request, client_conn = encode_dictionary_auth(
        {
            'seq': 1,
            'field_version': 6,
            'auth': {
                'sess': challenge.auth_sesskey,
                'salt': challenge.salt,
                'derived_salt': None,
            },
            'env': {'user': 'PYO', 'password': password},
        }
    )
    user, client_auth_sesskey, auth_password = parse_auth_response(request)
    assert user == b'PYO'
    server_conn = derive_conn_key(challenge, client_auth_sesskey)
    assert server_conn == client_conn

    # The server verifies the client's AUTH_PASSWORD proof against the account
    # secret: the right password passes, a wrong one is rejected.
    assert verify_password(server_conn, auth_password, b'pyo123')
    assert not verify_password(server_conn, auth_password, b'wrongpass')

    # The result the server sends back, validated by the client's own check.
    _, resp, _, _, _, _ = decode_token_rpa(encode_result(server_conn)[1:], ())
    assert validate(unhexlify(resp), client_conn)


def test_parse_changepassword_and_decrypt_roundtrip() -> None:
    # A changepassword TTI_AUTH round-trips: the server parser recovers the user
    # and the two AES ciphertexts, and decrypt_password (the inverse of the
    # client's encrypt_password) recovers the plaintext passwords under the
    # login ConnKey (#21/#486).
    from seerdb.common.crypto import decrypt_password
    from seerdb.common.tns import encode_dictionary_chgpwd
    from seerdb.server.auth import parse_changepassword

    conn_key = bytes(range(24))  # a 24-byte 11g session ConnKey
    msg = encode_dictionary_chgpwd(
        {
            'seq': 1,
            'field_version': 6,
            'env': {'user': 'PYO'},
            'auth': {
                'conn_key': conn_key,
                'old_password': 'pyo123',
                'new_password': 'pyo123_chg9',
            },
        }
    )
    user, old_cipher, new_cipher = parse_changepassword(msg)
    assert user == b'PYO'
    assert decrypt_password(conn_key, old_cipher) == b'pyo123'
    assert decrypt_password(conn_key, new_cipher) == b'pyo123_chg9'


def test_parse_auth_new_password_finds_the_login_time_change() -> None:
    # A client may change the password AS IT CONNECTS (`newpassword=`): the new
    # one rides in the ordinary login AUTH beside the proof, not in a separate
    # call. The Mirror read the proof and ignored it, so the login succeeded, the
    # password never changed, and the NEXT connect with the new one was refused
    # ORA-01017 -- a failure one step removed from its cause (#826).
    #
    # The bytes come from the client's own encoder rather than by hand: the
    # key/value framing is what is under test, and a hand-built body would only
    # agree with itself.
    from seerdb.common.crypto import decrypt_password
    from seerdb.common.tns import encode_dictionary_chgpwd
    from seerdb.server.auth import parse_auth_new_password

    conn_key = bytes(range(24))
    msg = encode_dictionary_chgpwd(
        {
            'seq': 1,
            'field_version': 6,
            'env': {'user': 'PYO'},
            'auth': {
                'conn_key': conn_key,
                'old_password': 'pyo123',
                'new_password': 'the-new-one',
            },
        }
    )
    cipher = parse_auth_new_password(msg)
    assert cipher is not None
    assert decrypt_password(conn_key, cipher) == b'the-new-one'


def test_parse_auth_new_password_is_quiet_when_there_is_none() -> None:
    # An ordinary login carries no new password, and a malformed body must not
    # turn a good login into a failed one -- identity-ish metadata never raises.
    from seerdb.common.tns import encode_dictionary_sess
    from seerdb.server.auth import parse_auth_new_password

    plain = encode_dictionary_sess(
        {'seq': 1, 'field_version': 6, 'env': {'user': 'PYO'}}
    )
    assert parse_auth_new_password(plain) is None
    assert parse_auth_new_password(b'') is None
    assert parse_auth_new_password(b'\x03\x76\x01garbage') is None


def test_app_context_entries_survive_the_sorted_pairs() -> None:
    # `connect(appcontext=[(ns, attr, value), ...])` sends each entry as three
    # pairs REPEATING the same three keys, so the dict form of the message keeps
    # only the last -- and decode_kv SORTS the pairs, so the wire interleaving is
    # gone as well. What survives is each key's own order, because the sort is
    # stable, which is what makes grouping-and-zipping correct (#826).
    #
    # These pairs are exactly what a live oracledb 4.0.1 connect produced,
    # captured off the Mirror rather than imagined.
    from seerdb.server.auth import _group_app_context

    pairs = [
        (b'AUTH_APPCTX_ATTR\x00', b'ATTR1'),
        (b'AUTH_APPCTX_ATTR\x00', b'ATTR2'),
        (b'AUTH_APPCTX_ATTR\x00', b'ATTR3'),
        (b'AUTH_APPCTX_NSPACE\x00', b'CLIENTCONTEXT'),
        (b'AUTH_APPCTX_NSPACE\x00', b'CLIENTCONTEXT'),
        (b'AUTH_APPCTX_NSPACE\x00', b'CLIENTCONTEXT'),
        (b'AUTH_APPCTX_VALUE\x00', b'VALUE1'),
        (b'AUTH_APPCTX_VALUE\x00', b'VALUE2'),
        (b'AUTH_APPCTX_VALUE\x00', b'VALUE3'),
    ]
    assert _group_app_context(pairs) == [
        ('CLIENTCONTEXT', 'ATTR1', 'VALUE1'),
        ('CLIENTCONTEXT', 'ATTR2', 'VALUE2'),
        ('CLIENTCONTEXT', 'ATTR3', 'VALUE3'),
    ]


def test_app_context_keeps_each_entry_whatever_its_values_sort_as() -> None:
    # Decoded from the wire: values that do not sort in their declared order
    # stay with their own attribute. decode_kv sorted whole (key, value) pairs,
    # so a key's values came out in value order and the entries were paired up
    # wrongly -- a test with VALUE1..VALUE3 could not tell (#1582).
    from seerdb.common.tns import decode_kv, encode_kv
    from seerdb.server.auth import _group_app_context

    entries = [
        ('CLIENTCONTEXT', 'ATTR1', 'VALUE1'),
        ('clientcontext', 'Attr2', 'Mixed Case'),
        ('CLIENTCONTEXT', 'ATTR3', 'v3'),
    ]
    wire = b''.join(
        encode_kv(f'AUTH_APPCTX_{key}'.encode(), value.encode())
        for entry in entries
        for key, value in zip(('NSPACE', 'ATTR', 'VALUE'), entry, strict=True)
    )
    (pairs, _rest) = decode_kv(wire, 3 * len(entries), [])
    assert _group_app_context(pairs) == entries


def test_app_context_ignores_everything_else_in_the_auth() -> None:
    # The auth message is mostly NOT application context; a login with none at
    # all must come back empty rather than mis-pair whatever else is there.
    from seerdb.server.auth import _group_app_context

    assert _group_app_context([]) == []
    assert (
        _group_app_context(
            [
                (b'AUTH_PASSWORD', b'ABCDEF'),
                (b'SESSION_CLIENT_DRIVER_NAME', b'python-oracledb thn : 4.0.1'),
                (b'AUTH_ALTER_SESSION', b"ALTER SESSION SET TIME_ZONE='+02:00'\x00"),
            ]
        )
        == []
    )


# --- the 12.1+ PBKDF2 challenge (#829) -----------------------------------------


def _client_login_12c(challenge, user: bytes, password: bytes):
    # The same client entry point, told what a 12.1+ challenge carries: the CSK
    # salt, the two iteration counts, and the verifier type from AUTH_VFR_DATA's
    # flag. seerdb's o5logon picks its scheme from exactly these.
    auth_pass, auth_sess, _speedy, _ind, conn = o5logon(
        challenge.auth_sesskey,
        challenge.salt,
        challenge.derived_salt,
        user,
        password,
        PBKDF2_VGEN_COUNT,
        PBKDF2_SDER_COUNT,
        VFR_11G_SHA1,
    )
    return auth_sess, auth_pass, conn


def test_12c_challenge_carries_the_pbkdf2_parameters() -> None:
    # A 12.1+ client reads its whole scheme off the challenge, so all six pairs
    # have to be there -- and AUTH_VFR_DATA's flag has to say SHA-1, or a client
    # seeing both salts assumes the 256-bit scheme and derives a different key.
    challenge = make_challenge(b'pyo123', field_version=FIELD_VERSION_12_1)
    assert challenge.derived_salt is not None
    payload = encode_challenge(challenge)
    for key in (
        b'AUTH_SESSKEY',
        b'AUTH_VFR_DATA',
        b'AUTH_PBKDF2_CSK_SALT',
        b'AUTH_PBKDF2_VGEN_COUNT',
        b'AUTH_PBKDF2_SDER_COUNT',
        b'AUTH_GLOBALLY_UNIQUE_DBID',
    ):
        assert key in payload, key
    assert str(PBKDF2_VGEN_COUNT).encode('ascii') in payload
    assert str(PBKDF2_SDER_COUNT).encode('ascii') in payload


def test_12c_session_key_is_32_bytes_not_48() -> None:
    # The LENGTH selects the derivation for python-oracledb -- it takes the 11g
    # path on 48 and ignores the CSK salt entirely, which would leave the two
    # sides deriving different keys while both believed they were right.
    modern = make_challenge(b'pyo123', field_version=FIELD_VERSION_12_1)
    legacy = make_challenge(b'pyo123', field_version=FIELD_VERSION_11_2)
    assert len(modern.server_session) == 32
    assert len(legacy.server_session) == 48
    assert legacy.derived_salt is None


def test_both_sides_derive_the_same_key_under_pbkdf2() -> None:
    password = b'pyo123'
    challenge = make_challenge(password, field_version=FIELD_VERSION_12_1)
    client_auth_sess, _pass, client_conn = _client_login_12c(
        challenge, b'PYO', password
    )
    assert derive_conn_key(challenge, client_auth_sess) == client_conn


def test_wrong_password_still_breaks_the_agreement_under_pbkdf2() -> None:
    challenge = make_challenge(b'pyo123', field_version=FIELD_VERSION_12_1)
    client_auth_sess, _pass, client_conn = _client_login_12c(
        challenge, b'PYO', b'wrongpw'
    )
    assert derive_conn_key(challenge, client_auth_sess) != client_conn


def test_the_11g_challenge_is_unchanged() -> None:
    # Everything above is gated: below 12.1 the challenge is the two-pair 11g one
    # and carries no status trailer, so the captured wire stays byte-identical.
    challenge = make_challenge(b'pyo123', field_version=FIELD_VERSION_11_2)
    payload = encode_challenge(challenge)
    assert b'AUTH_PBKDF2_CSK_SALT' not in payload
    assert payload.count(bytes([TTI_OER])) == 0


def test_encode_result_carries_the_session_names() -> None:
    # A client reads instance_name / db_name / service_name (and the session id
    # and serial number) from the login reply ALONE -- never by querying -- so a
    # reply that leaves them out leaves them None for the life of the connection,
    # however correct the session otherwise is (#826).
    from seerdb.common.tns import _ENCODE_FIELD_VERSION

    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_12_1)
    try:
        payload = encode_result(
            bytes(24),
            session_id=245,
            serial_num=60722,
            instance_name='FREE',
            db_name='FREE',
            service_name='freepdb1',
        )
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    assert b'AUTH_INSTANCENAME' in payload
    assert b'FREE' in payload
    assert b'AUTH_SC_DBUNIQUE_NAME' in payload
    assert b'AUTH_SC_SERVICE_NAME' in payload
    assert b'freepdb1' in payload
    assert b'60722' in payload


def test_encode_result_omits_a_name_the_server_does_not_know() -> None:
    # A name the Mirror does not know is left out. The domain is the exception:
    # a database with no domain still sends AUTH_SC_DB_DOMAIN, empty, on every
    # bed from 10g to 26ai (#1820).
    from seerdb.common.tns import _ENCODE_FIELD_VERSION, decode_kv, decode_ub4

    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_12_1)
    try:
        payload = encode_result(bytes(24), session_id=245, instance_name='FREE')
        (count, rest) = decode_ub4(payload[1:])
        pairs = dict(decode_kv(rest, count, [], {})[0])
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    assert pairs[b'AUTH_INSTANCENAME'] == b'FREE'
    assert b'AUTH_SC_SERVICE_NAME' not in pairs
    # Present and empty, as a real server's decodes (test_tns_decode's capture).
    assert b'AUTH_SC_DB_DOMAIN' in pairs
    assert pairs[b'AUTH_SC_DB_DOMAIN'] is None


def test_a_backend_that_cannot_report_its_session_never_fails_the_login() -> None:
    # session_info is optional, and a backend that raises trying to answer must
    # not take the login down with it -- the reply falls back to the placeholders
    # it always carried (#826).
    from typing import cast

    from seerdb.server.backend import Backend, SessionInfo
    from seerdb.server.session import _backend_session_info

    class NoHook:
        pass

    class Raises:
        def session_info(self):
            raise RuntimeError('v$session is not granted')

    # Neither stands in for a whole Backend; the hook is all this reads.
    assert _backend_session_info(cast('Backend', NoHook())) == SessionInfo()
    assert _backend_session_info(cast('Backend', Raises())) == SessionInfo()


def test_the_osesskey_carries_the_callers_session_identity() -> None:
    # program / machine / terminal / osuser are informational -- nothing
    # authenticates on them -- but they are readable ONLY through this message,
    # so a caller's values have to travel here or v$session shows the driver's
    # own (#826). AUTH_SID is osuser, not a session id.
    from seerdb.common.tns import encode_dictionary_sess
    from seerdb.common.tns_consts import FIELD_VERSION_12_1
    from seerdb.server.auth import parse_client_identity

    env = {
        'user': 'PYTHONTEST',
        'program': 'newprogram',
        'machine': 'newmachine',
        'terminal': 'newterminal',
        'osuser': 'newosuser',
    }
    payload = encode_dictionary_sess(
        {'seq': 1, 'env': env, 'field_version': FIELD_VERSION_12_1}
    )
    assert parse_client_identity(payload, FIELD_VERSION_12_1) == {
        'program': 'newprogram',
        'machine': 'newmachine',
        'terminal': 'newterminal',
        'osuser': 'newosuser',
    }


def test_a_long_session_value_is_chunked_at_the_negotiated_width() -> None:
    # A value over 252 bytes is chunked: ub4 chunk lengths from 12.1, one byte
    # before. The width came from whatever an earlier connection had left in
    # the context, so a first login in a fresh one sent 1-byte lengths to a
    # 12.1+ server and drew ORA-03120 (#1816). A fresh context here is that
    # first login.
    import contextvars

    from seerdb.common.tns import encode_dictionary_sess
    from seerdb.common.tns_consts import FIELD_VERSION_11_2, FIELD_VERSION_12_1

    env = {'user': 'PYO', 'program': 'p' * 253}
    for fv, chunks in (
        (FIELD_VERSION_12_1, b'\xfe\x01\x40' + b'p' * 64),
        (FIELD_VERSION_11_2, b'\xfe\x40' + b'p' * 64),
    ):
        payload = contextvars.Context().run(
            encode_dictionary_sess, {'seq': 1, 'env': env, 'field_version': fv}
        )
        assert b'AUTH_PROGRAM_NM\x01\xfd' + chunks in payload


def test_the_osesskey_falls_back_to_what_this_process_is() -> None:
    # A caller who sets nothing keeps the previous behaviour exactly: the
    # program is app_name, the osuser is the database user, and the machine is
    # this host.
    import socket

    from seerdb.common.tns import encode_dictionary_sess
    from seerdb.common.tns_consts import FIELD_VERSION_12_1
    from seerdb.server.auth import parse_client_identity

    payload = encode_dictionary_sess(
        {
            'seq': 1,
            'env': {'user': 'PYTHONTEST', 'app_name': 'seerdb'},
            'field_version': FIELD_VERSION_12_1,
        }
    )
    identity = parse_client_identity(payload, FIELD_VERSION_12_1)
    assert identity['program'] == 'seerdb'
    assert identity['osuser'] == 'PYTHONTEST'
    assert identity['machine'] == socket.gethostname()
    assert identity['terminal'] == 'unknown'


def test_parse_client_identity_never_raises_on_rubbish() -> None:
    # Identity is metadata. A login must not fail because it could not be read.
    from seerdb.server.auth import parse_client_identity

    assert parse_client_identity(b'') == {}
    assert parse_client_identity(b'\x03\x76not an osesskey') == {}


def test_both_connections_take_the_same_identity_arguments() -> None:
    # Sync/async parity: the async connection inherits the shared logic that
    # reads these, so an attribute missing from one of them is an AttributeError
    # at connect time, not a type error here.
    import inspect

    from seerdb.client.aconnection import AsyncOracleConnect
    from seerdb.client.connection import OracleConnect

    wanted = {'program', 'machine', 'terminal', 'osuser'}
    for cls in (OracleConnect, AsyncOracleConnect):
        params = set(inspect.signature(cls.__init__).parameters)
        assert wanted <= params, cls.__name__


def test_parse_auth_alter_session_finds_the_login_time_zone() -> None:
    # From 12.1 the client pins the session time zone to its own UTC offset in
    # the login AUTH itself (AUTH_ALTER_SESSION). The Mirror read the proof and
    # dropped the statement, so SESSIONTIMEZONE reported the backend's zone.
    # Built by the client's own encoder: the key/value framing is under test.
    from seerdb.common.tns import _local_tz_clause
    from seerdb.common.tns_consts import FIELD_VERSION_12_1
    from seerdb.server.auth import parse_auth_alter_session

    challenge = make_challenge(b'pyo123')
    request, _ = encode_dictionary_auth(
        {
            'seq': 1,
            'field_version': FIELD_VERSION_12_1,
            'auth': {
                'sess': challenge.auth_sesskey,
                'salt': challenge.salt,
                'derived_salt': None,
            },
            'env': {'user': 'PYO', 'password': 'pyo123'},
        }
    )
    statement = parse_auth_alter_session(request, FIELD_VERSION_12_1)
    # The trailing NUL the client terminates it with is not part of the SQL.
    assert statement == _local_tz_clause().rstrip(b'\x00').decode()
    assert statement.startswith("ALTER SESSION SET TIME_ZONE='")


def test_parse_auth_alter_session_is_quiet_when_there_is_none() -> None:
    # Before 12.1 the client sends no such pair, and a malformed body must not
    # turn a good login into a failed one.
    from seerdb.server.auth import parse_auth_alter_session

    challenge = make_challenge(b'pyo123')
    request, _ = encode_dictionary_auth(
        {
            'seq': 1,
            'field_version': 6,
            'auth': {
                'sess': challenge.auth_sesskey,
                'salt': challenge.salt,
                'derived_salt': None,
            },
            'env': {'user': 'PYO', 'password': 'pyo123'},
        }
    )
    assert parse_auth_alter_session(request) is None
    assert parse_auth_alter_session(b'') is None
    assert parse_auth_alter_session(b'\x03\x73\x01garbage') is None


def test_oci_challenge_at_12_1_offers_the_12c_verifier() -> None:
    # From 12.1 the OCI challenge takes a 12c-band server's shape (captured from
    # 18c): the PBKDF2 salt and both iteration counts, the 12c SHA-2 verifier
    # flag, and the 144-byte trailer. A modern sqlplus refuses the 11g form from a
    # 12.1+ server (#1282).
    from seerdb.common.tns import _CHALLENGE_TRAILER_12C
    from seerdb.server.auth import encode_challenge_oci

    challenge = make_challenge(
        b'pyo123', field_version=FIELD_VERSION_12_1, verifier_type=VFR_12C_SHA2
    )
    packet = encode_challenge_oci(challenge)
    assert packet[10] == TTI_RPA and packet[11] == 6  # six key-value pairs
    for key in (
        b'AUTH_PBKDF2_CSK_SALT',
        b'AUTH_PBKDF2_VGEN_COUNT',
        b'AUTH_PBKDF2_SDER_COUNT',
    ):
        assert key in packet
    i = packet.index(b'AUTH_VFR_DATA') + len(b'AUTH_VFR_DATA')
    salt = challenge.salt.hex().upper().encode()
    assert packet[i + 5 : i + 5 + len(salt)] == salt
    assert packet[i + 5 + len(salt) : i + 9 + len(salt)] == (
        VFR_12C_SHA2.to_bytes(4, 'little')
    )
    assert len(_CHALLENGE_TRAILER_12C) == 144
    assert packet.endswith(_CHALLENGE_TRAILER_12C)


def test_oci_12c_verifier_agrees_with_the_client() -> None:
    # The 12c SHA-2 challenge derives the 256-bit ConnKey the client derives from
    # it, and the password it proves verifies (a wrong one does not) (#1282).
    from seerdb.server.auth import verify_password

    challenge = make_challenge(
        b'pyo123', field_version=FIELD_VERSION_12_1, verifier_type=VFR_12C_SHA2
    )
    auth_pass, auth_sess, _speedy, _ind, conn = o5logon(
        challenge.auth_sesskey,
        challenge.salt,
        challenge.derived_salt,
        b'PYO',
        b'pyo123',
        PBKDF2_VGEN_COUNT,
        PBKDF2_SDER_COUNT,
        VFR_12C_SHA2,
    )
    server_conn = derive_conn_key(challenge, auth_sess)
    assert len(server_conn) == 32
    assert server_conn == conn
    assert verify_password(server_conn, auth_pass, b'pyo123')
    assert not verify_password(server_conn, auth_pass, b'wrongpass')


def test_oci_result_trailer_follows_the_field_version() -> None:
    # The result's trailer grows to the 12c-band 144 bytes from 12.1, as the
    # challenge's does; below that it stays the 136-byte 11.2 form (#1282).
    from seerdb.common.tns import _RESULT_TRAILER, _RESULT_TRAILER_12C
    from seerdb.server.auth import encode_result_oci

    conn = bytes(32)
    old = encode_result_oci(conn, nonce=bytes(16))
    new = encode_result_oci(conn, nonce=bytes(16), field_version=FIELD_VERSION_12_1)
    assert old.endswith(_RESULT_TRAILER) and len(_RESULT_TRAILER) == 136
    assert new.endswith(_RESULT_TRAILER_12C) and len(_RESULT_TRAILER_12C) == 144
    assert new[2:-144] == old[2:-136]  # past the packet length, only the trailer


def _long_auth(field_version: int) -> bytes:
    # A thin AUTH whose last pair is a long connect string, as python-oracledb
    # sends one (#1770): header, user, then key/value pairs with their flags.
    from seerdb.common.tns import encode_kv, encode_sb4

    pairs = [
        (b'AUTH_SESSKEY', b'AB' * 32),
        (b'AUTH_PASSWORD', b'CD' * 32),
        (b'AUTH_CONNECT_STRING', b'(DESCRIPTION=' + b'x' * 300 + b')'),
    ]
    user = b'pyo'
    head = bytes([0x03, TTI_AUTH, 2, 1]) + encode_sb4(len(user)) + encode_sb4(0x101)
    head += bytes([1]) + encode_sb4(len(pairs)) + bytes([1, 1])
    if field_version >= FIELD_VERSION_12_1:
        head += bytes([len(user)])
    return head + user + b''.join(encode_kv(k, v, 0) for k, v in pairs)


@pytest.mark.parametrize('field_version', [FIELD_VERSION_11_2, FIELD_VERSION_12_1])
def test_a_split_auth_is_known_to_be_incomplete(field_version: int) -> None:
    # Below an SDU of about 562 a client's AUTH crosses into a second packet, cut
    # inside its connect string; the parse reads the cut value short instead of
    # failing, so the Mirror logged in on half a message and read the rest as
    # the next call (#1770). The completeness check walks every pair strictly.
    from seerdb.common.exceptions import Truncated

    whole = _long_auth(field_version)
    check_auth_complete(whole, field_version)
    assert parse_auth_response(whole, field_version)[0] == b'pyo'
    for cut in (len(whole) - 1, len(whole) - 40, 200, 20, 5):
        with pytest.raises(Truncated):
            check_auth_complete(whole[:cut], field_version)


def _whole_walk(payload: bytes, field_version: int) -> None:
    # The completeness check as it was before GHSA-vxvf-jx7x-rcx8: every pair
    # from the start with the strict primitives. AuthWalk must agree with it.
    from seerdb.common.exceptions import Truncated
    from seerdb.common.tns import decode_auth_head, decode_dalc, decode_ub4

    if len(payload) < 4:
        raise Truncated('auth message header')
    (head, rest) = decode_auth_head(payload, field_version)
    if len(head['user']) < head['user_length']:
        raise Truncated('auth message user name')
    for _ in range(head['pair_count']):
        for _field in ('key', 'value'):
            length, rest = decode_ub4(rest)
            if length:
                _, rest = decode_dalc(rest)
        _flag, rest = decode_ub4(rest)


def _outcome(walk: Callable[[bytes], object], payload: bytes) -> str:
    try:
        walk(payload)
    except Exception as exc:  # the kind of refusal is what is compared
        return type(exc).__name__
    return 'whole'


def _auth_head(field_version: int, pair_count: int) -> bytes:
    # A thin AUTH's head and user, as _long_auth builds them.
    from seerdb.common.tns import encode_sb4

    user = b'pyo'
    head = bytes([0x03, TTI_AUTH, 2, 1]) + encode_sb4(len(user)) + encode_sb4(0x101)
    head += bytes([1]) + encode_sb4(pair_count) + bytes([1, 1])
    if field_version >= FIELD_VERSION_12_1:
        head += bytes([len(user)])
    return head + user


def _auths(field_version: int) -> list[bytes]:
    # Thin AUTHs with short values, a chunked one (past 252 bytes, framed as the
    # field version frames it), an empty value, the absent-value marker, and
    # pairs of three zero integers.
    from seerdb.common.tns import encode_kv, encode_sb4

    pairs = [
        (b'AUTH_SESSKEY', b'AB' * 32),
        (b'AUTH_TOKEN', b't' * 700),
        (b'AUTH_EMPTY', b''),
        (b'AUTH_CONNECT_STRING', b'(DESCRIPTION=' + b'x' * 300 + b')'),
    ]
    absent = encode_sb4(3) + bytes([3]) + b'KEY' + encode_sb4(1) + bytes([0xFD, 1, 0])
    return [
        _long_auth(field_version),
        _auth_head(field_version, len(pairs))
        + b''.join(encode_kv(k, v, 0) for k, v in pairs),
        _auth_head(field_version, 1) + absent,
        _auth_head(field_version, 50) + b'\x00\x00\x00' * 50,
    ]


@pytest.fixture
def _codec_at(request: pytest.FixtureRequest) -> Iterator[int]:
    # The codec's field version for the test's: a chunked value is framed by it.
    from seerdb.common.tns import _DECODE_FIELD_VERSION, _ENCODE_FIELD_VERSION

    field_version = request.param
    tokens = (
        _DECODE_FIELD_VERSION.set(field_version),
        _ENCODE_FIELD_VERSION.set(field_version),
    )
    yield field_version
    _DECODE_FIELD_VERSION.reset(tokens[0])
    _ENCODE_FIELD_VERSION.reset(tokens[1])


@pytest.mark.parametrize(
    '_codec_at', [FIELD_VERSION_11_2, FIELD_VERSION_12_1], indirect=True
)
def test_the_auth_walk_agrees_with_a_whole_walk(_codec_at: int) -> None:
    # GHSA-vxvf-jx7x-rcx8: the resumable walk tells a whole AUTH from a cut one
    # as walking the whole message from its start does, at every cut, whether
    # it starts afresh or goes on from the shorter message before.
    from seerdb.server.auth import AuthWalk

    field_version = _codec_at
    for whole in _auths(field_version):
        assert _outcome(AuthWalk(field_version), whole) == 'whole'
        grown = AuthWalk(field_version)
        for cut in range(len(whole) + 1):
            expected = _outcome(lambda b: _whole_walk(b, field_version), whole[:cut])
            assert _outcome(AuthWalk(field_version), whole[:cut]) == expected, cut
            assert _outcome(grown, whole[:cut]) == expected, cut


@pytest.mark.parametrize(
    '_codec_at', [FIELD_VERSION_11_2, FIELD_VERSION_12_1], indirect=True
)
def test_the_auth_walk_refuses_what_a_whole_walk_refuses(_codec_at: int) -> None:
    # The same answer on pairs of arbitrary bytes, at every cut -- but for a
    # chunk of a negative length, which the whole walk read as the last bytes
    # of what it had, and the resumable one refuses.
    import random

    from seerdb.server.auth import AuthWalk

    field_version = _codec_at
    rng = random.Random(1770)
    alphabet = (0, 1, 2, 3, 7, 64, 0x81, 0xFD, 0xFE, 0xFF)
    for _ in range(300):
        payload = _auth_head(field_version, rng.randrange(1, 6)) + bytes(
            rng.choice(alphabet) for _ in range(rng.randrange(1, 60))
        )
        grown = AuthWalk(field_version)
        for cut in range(len(payload) + 1):
            fresh = _outcome(AuthWalk(field_version), payload[:cut])
            if fresh == 'DataError':
                break
            expected = _outcome(lambda b: _whole_walk(b, field_version), payload[:cut])
            assert fresh == expected
            assert _outcome(grown, payload[:cut]) == expected


def test_a_split_auth_is_walked_once(monkeypatch) -> None:
    # GHSA-vxvf-jx7x-rcx8: an AUTH read packet by packet is walked from where
    # the last packet left off, not from its start for every packet, so the
    # integers read stay in proportion to the message, not to its square.
    from seerdb.common.exceptions import Truncated
    from seerdb.server import auth

    calls = 0
    decode = auth.decode_ub4

    def counted(data: bytes) -> tuple[int, bytes]:
        nonlocal calls
        calls += 1
        return decode(data)

    monkeypatch.setattr(auth, 'decode_ub4', counted)
    pairs = 20_000
    whole = _auth_head(FIELD_VERSION_12_1, pairs) + b'\x00\x00\x00' * pairs
    packets = range(8192, len(whole), 8192)
    walk = auth.AuthWalk(FIELD_VERSION_12_1)
    for end in packets:
        with pytest.raises(Truncated):
            walk(whole[:end])
    walk(whole)
    # Each pair's three integers once, and a cut one again per packet.
    assert calls <= 3 * pairs + len(packets) + 1
