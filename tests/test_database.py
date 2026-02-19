from pathlib import Path
import sqlite3
import tempfile

import pytest

import mypass.database as mpd

def test_initialize_fails_if_file_exists():
    with tempfile.NamedTemporaryFile(suffix='.db') as f:
        with pytest.raises(FileExistsError):
            mpd.initialize(Path(f.name), 'test_password')

def test_initialize_succeeds_if_file_missing():
    testdb = Path(tempfile.mktemp(suffix='.db'))
    try:

        # NOTE: There is no way to guarantee testdb doesn't exist here.
        # But this test should pass almost always.

        mpd.initialize(testdb, 'test_password')
    except:
        assert False

@pytest.fixture
def testdb():
    testdb = Path(tempfile.mktemp(suffix='.db'))
    mpd.initialize(testdb, 'test_password') # NOTE: This may fail rarely as above.
    yield testdb

def test_authentication_succeeds_with_correct_password(testdb):
    with mpd.authenticated(testdb, 'test_password'):
        return
    assert False

def test_authentication_fails_with_wrong_password(testdb):
    with pytest.raises(mpd.AuthenticationError):
        with mpd.authenticated(testdb, 'wrong_password'):
            pass

@pytest.fixture
def authdb(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        yield adb

def test_get_on_empty_database_fails(authdb):
    with pytest.raises(mpd.VaultNotFoundError):
        authdb['hello']

def test_set_get(authdb):
    authdb['hello'] = b'world'
    assert b'world' == authdb['hello']

def test_set_persists(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        adb['hello'] = b'world'

    with mpd.authenticated(testdb, 'test_password') as adb:
        assert b'world' == adb['hello']

def test_set_set_get(authdb):
    authdb['hello'] = b'world'
    authdb['hello'] = b'world!'
    assert b'world!' == authdb['hello']

def test_nonexistent_key_fails(authdb):
    authdb['hello'] = b'world'
    with pytest.raises(mpd.VaultNotFoundError):
        authdb['hell0']

def test_multiple_set_get(authdb):
    for i in range(10):
        authdb[f"hello{i}"] = f"world{i}".encode('utf-8')

    for i in range(10):
        assert f"world{i}".encode('utf-8') == authdb[f"hello{i}"]

def test_verify_succeeds_on_fresh_database(testdb):
    with mpd.verified(testdb, 'test_password'):
        return
    assert False

def test_verify_fails_with_wrong_password(testdb):
    with pytest.raises(mpd.AuthenticationError):
        with mpd.verified(testdb, 'wrong_password'):
            pass

def test_verify_fails_on_nonexistent_database():
    with pytest.raises(FileNotFoundError):
        with mpd.verified(Path('/tmp/nonexistent.db'), 'test_password'):
            pass

def test_verify_succeeds_after_set(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        adb['hello'] = b'world'

    with mpd.verified(testdb, 'test_password'):
        return
    assert False

def test_verify_detects_tampered_secret(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        adb['hello'] = b'world'

    connection = sqlite3.connect(testdb)
    connection.execute("UPDATE vaults SET secret = 'tampered' WHERE name = 'hello'")
    connection.commit()
    connection.close()

    with pytest.raises(mpd.IntegrityError):
        with mpd.verified(Path(testdb), 'test_password'):
            pass

def test_verify_detects_tampered_vault_name(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        adb['hello'] = b'world'

    connection = sqlite3.connect(testdb)
    connection.execute("UPDATE vaults SET name = 'hell0' WHERE name = 'hello'")
    connection.commit()
    connection.close()

    with pytest.raises(mpd.IntegrityError):
        with mpd.verified(Path(testdb), 'test_password'):
            pass  

def test_verify_detects_swapped_secrets(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        adb['a'] = b'alpha'
        adb['b'] = b'beta'

    connection = sqlite3.connect(testdb)
    cur = connection.cursor()
    cur.execute("SELECT secret FROM vaults WHERE name = ?", ('a',))
    secret_a = cur.fetchone()[0]
    cur.execute("SELECT secret FROM vaults WHERE name = ?", ('b',))
    secret_b = cur.fetchone()[0]

    cur.execute("UPDATE vaults SET secret = ? WHERE name = ?", (secret_b, 'a'))
    cur.execute("UPDATE vaults SET secret = ? WHERE name = ?", (secret_a, 'b'))
    connection.commit()
    connection.close()

    with pytest.raises(mpd.IntegrityError):
        with mpd.verified(Path(testdb), 'test_password'):
            pass

def test_verify_detects_tampered_main_row(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        adb['hello'] = b'world'

    connection = sqlite3.connect(testdb)
    connection.execute("UPDATE main SET last_updated = 'tampered' WHERE version = ?", ('0.2',))
    connection.commit()
    connection.close()

    with pytest.raises(mpd.IntegrityError):
        with mpd.verified(Path(testdb), 'test_password'):
            pass

def test_verify_detects_deleted_vaults(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        adb['one'] = b'1'
        adb['two'] = b'2'

    connection = sqlite3.connect(testdb)
    connection.execute("DELETE FROM vaults WHERE name = ?", ('two',))
    connection.commit()
    connection.close()

    with pytest.raises(mpd.IntegrityError):
        with mpd.verified(Path(testdb), 'test_password'):
            pass

def test_delitem(authdb):
    authdb['hello'] = b'world'
    del authdb['hello']
    with pytest.raises(mpd.VaultNotFoundError):
        authdb['hello']

def test_delitem_nonexistent(authdb):
    with pytest.raises(mpd.VaultNotFoundError):
        del authdb['hello']

def test_delitem_persists(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        adb['hello'] = b'world'

    with mpd.authenticated(testdb, 'test_password') as adb:
        del adb['hello']

    with mpd.authenticated(testdb, 'test_password') as adb:
        with pytest.raises(mpd.VaultNotFoundError):
            adb['hello']

def test_len_empty(authdb):
    assert len(authdb) == 0

def test_len_after_set(authdb):
    authdb['hello'] = b'world'
    assert len(authdb) == 1

def test_len_after_multiple_set(authdb):
    for i in range(5):
        authdb[f"key{i}"] = f"val{i}".encode('utf-8')
    assert len(authdb) == 5

def test_len_after_overwrite(authdb):
    authdb['hello'] = b'world'
    authdb['hello'] = b'world!'
    assert len(authdb) == 1

def test_len_after_delete(authdb):
    authdb['hello'] = b'world'
    del authdb['hello']
    assert len(authdb) == 0

def test_iter_empty(authdb):
    assert list(authdb) == []

def test_iter_single(authdb):
    authdb['hello'] = b'world'
    assert list(authdb) == ['hello']

def test_iter_multiple(authdb):
    authdb['banana'] = b'1'
    authdb['apple'] = b'2'
    authdb['cherry'] = b'3'
    assert list(sorted(authdb)) == ['apple', 'banana', 'cherry']

def test_iter_iter(authdb):
    authdb['banana'] = b'1'
    authdb['apple'] = b'2'
    authdb['cherry'] = b'3'
    assert list(sorted(authdb)) == ['apple', 'banana', 'cherry']
    assert list(sorted(authdb)) == ['apple', 'banana', 'cherry']

def test_contains_true(authdb):
    authdb['hello'] = b'world'
    assert 'hello' in authdb

def test_contains_false(authdb):
    assert 'hello' not in authdb

def test_contains_after_delete(authdb):
    authdb['hello'] = b'world'
    del authdb['hello']
    assert 'hello' not in authdb

def test_relock_changes_password_and_preserves_vaults(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        adb['hello'] = b'world'
        adb['foo'] = b'bar'

    mpd.relock(testdb, 'test_password', 'new_password')

    with pytest.raises(mpd.AuthenticationError):
        with mpd.authenticated(testdb, 'test_password'):
            pass

    with mpd.verified(testdb, 'new_password') as vdb:
        assert vdb['hello'] == b'world'
        assert vdb['foo'] == b'bar'

def test_relock_fails_with_wrong_old_password_and_keeps_db(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        adb['keep'] = b'data'

    with pytest.raises(mpd.AuthenticationError):
        mpd.relock(testdb, 'wrong_password', 'new_password')

    with mpd.verified(testdb, 'test_password') as vdb:
        assert vdb['keep'] == b'data'

