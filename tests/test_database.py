from pathlib import Path
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
    try:
        mpd.authenticated(testdb, 'test_password')
    except:
        assert False

def test_authentication_fails_with_wrong_password(testdb):
    with pytest.raises(mpd.AuthenticationError):
        mpd.authenticated(testdb, 'wrong_password')

@pytest.fixture
def authdb(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        yield adb

def test_get_on_empty_database_fails(authdb):
    with pytest.raises(mpd.VaultNotFoundError):
        authdb.get('hello')

def test_set_get(authdb):
    authdb.set('hello', b'world')
    assert b'world' == authdb.get('hello')

def test_set_persists(testdb):
    with mpd.authenticated(testdb, 'test_password') as adb:
        adb.set('hello', b'world')

    with mpd.authenticated(testdb, 'test_password') as adb:
        assert b'world' == adb.get('hello')

def test_set_set_get(authdb):
    authdb.set('hello', b'world')
    authdb.set('hello', b'world!')
    assert b'world!' == authdb.get('hello')

def test_nonexistent_key_fails(authdb):
    authdb.set('hello', b'world')
    with pytest.raises(mpd.VaultNotFoundError):
        authdb.get('hell0')

def test_multiple_set_get(authdb):
    for i in range(10):
        authdb.set(f"hello{i}", f"world{i}".encode('utf-8'))

    for i in range(10):
        assert f"world{i}".encode('utf-8') == authdb.get(f"hello{i}")

