"""Tools to work with mypass databases.

A mypass database can be used to store secrets encrypted and
authenticated using a main password. The database is a key-value store
where keys are stored in plain-text and values are encrypted using the
main password. The keys are called vaults which should be human-readable
strings. The values are called secrets which can be arbitrary binary
data.

The database format provides secrecy and integrity. Here, secrecy means
that the format leaks no information about values without the main
password. Integrity means that the database cannot be modified in an
undetectable manner without knowing the main password.

All mypass databases are sqlite3 databases using utf-8 encoding.

SCHEMA
------

The database consists of two tables: main and vaults.

The main table has the following columns:

  - version (text) : This column should be the string '0.2'.

  - last_updated (text) : The UTC time in ISO 8601 format when the
    database was last updated.

  - pwhash (text) : The string computed by nacl.pwhash.str().

  - enc_salt (text) : The salt (base64) used for computing the main key
    from main password.

  - mac_salt (text): The salt (base64) used for computing the mac.

  - mac (text) : The MAC (base64) for the entire database.

The vaults table has the following columns:

  - name (text) : The name of the vault. A human-readable string.
  - secret (text) : Base64 encoded encrypted secret bytes.

The main table has only one row. main.pwhash is computed using
nacl.pwhash.str(). main.mac is computed using blake2b algorithm with the
main password and main.mac_salt as inputs to create a key. The column
vaults.secret is encrypted using nacl.secret.Aead with vaults.name as
AAD with main password and main.enc_salt as inputs to create a key.

Usage
-----

Initialize a database in file "xyz.db" and encrypt all secrets using the
password "hunter2":

    initialize("xyz.db", "hunter2")

Acquire the database "xyz.db" using the password "hunter2" and access
secrets after decrypting and authenticating.

    with authenticated("xyz.db", "hunter2") as adb:
        print('foo =>', adb['foo'].decode('utf-8'))

Same as above but also verify that no tampering has occurred before
reading any data from the database:

    with verified("xyz.db", "hunter2") as vdb:
        for vault in vdb:
            print(vault)

Change the password used to encrypt secrets.

    relock("xyz.db", "hunter2", "hunter3")

Make an authenticated encrypted backup of database "xyz.db" into a file
"xyz.db.bak":

    with open("xyz.db.bak", "wb") as bakfile:
        backup(f"{name}.db", "hunter3", "Keep calm and carry on.", bakfile)

Restore a backup.

    aad = restore(bakfile, "hunter3", "xyz.db")
    print("The backup with message \"{aad}\" is restored.")
"""

import base64
import collections.abc
import contextlib
import datetime
import io
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Tuple

import nacl.hash
import nacl.pwhash
import nacl.secret
import nacl.utils

PROGNAME='mypass'
VERSION = '0.2'

def initialize(dbpath: str | Path, password: str) -> None:
    """Initialize an empty database at dbpath.

Parameters:
    dbpath (str | Path): Path to the database file.
    password (str): Password to protect the database.

Returns:
    None: On success.

Raises:
    FileExistsError: If a file already exists at dbpath.
    DatabaseError: If database creation failed.

Usage:

    Call initialize("xyz.db", "hunter2") to create an empty key-value
store in a file named "xyz.db". All secrets will be encrypted and
authenticated using the password "hunter2".
    """

    dbpath = _to_path(dbpath)

    if dbpath.exists():
        raise FileExistsError(f"File {dbpath} already exists.")

    try:

        connection = sqlite3.connect(dbpath, autocommit=False)
    
        cursor = connection.cursor()
    
        schema = """
            PRAGMA journal_mode = DELETE;

            CREATE TABLE IF NOT EXISTS main (
              version TEXT PRIMARY KEY CHECK (version == '0.2')
            , last_updated TEXT NOT NULL
            , pwhash TEXT NOT NULL
            , enc_salt TEXT NOT NULL
            , mac_salt TEXT NOT NULL
            , mac TEXT NOT NULL
            );
    
            CREATE TABLE IF NOT EXISTS vaults (
              name TEXT NOT NULL PRIMARY KEY
            , secret TEXT NOT NULL
            );
        """
    
        cursor.executescript(schema)

        now = _utcnowiso()

        pwhash = nacl.pwhash.str(password.encode('utf-8')).decode('utf-8')

        _, enc_salt = _encrypt(f"{PROGNAME}".encode('utf-8'), f"{PROGNAME}".encode('utf-8'), password)

        mac, mac_salt = _kmac (
            VERSION.encode('utf-8') + now.encode('utf-8') + pwhash.encode('utf-8') + enc_salt,
            password
        )

        cursor.execute (
            """
            INSERT
            INTO main (version, last_updated, pwhash, enc_salt, mac_salt, mac)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (VERSION, now, pwhash, _b64text(enc_salt), _b64text(mac_salt), _b64text(mac))
        )

        cursor.close()
        connection.commit()
        connection.close()

    except Exception as e:
        raise DatabaseError(f"Failed to create database at {dbpath}: {e}")
    

@contextlib.contextmanager
def authenticated(dbpath: str | Path, password: str):
    """Acquire an authenticated database from dbpath using password.

Parameters:
    dbpath (str | Path): Path to the database file.
    password (str): Password to authenticate.

Raises:
    FileNotFoundError: If there is no file at dbpath.
    DatabaseError: If some database operation failed.
    AuthenticationError: If password verification failed.

Usage:

    This is a context manager for authenticated databases. Within the
context manager, the database is available as a key-value store that
maps string keys to values of type bytes. All methods of MutableMapping
are available. The values are encrypted using password before storage.
This context manager should be used to access existing databases when
the goal is to add or remove very few key-value mappings or fetch the
secret in plain-text for a key.

        with authenticated("xyz.db", "hunter2") as adb:
            adb['foo'] = b'bar'
            del adb['baz']

    Upon exit, all changes are written back to "xyz.db" or one of the
exceptions is raised.
    """

    dbpath = _to_path(dbpath)
    db = _Database(dbpath)
    db._authenticate(password)
    yield db
    db._writeback()

@contextlib.contextmanager
def verified(dbpath: str | Path, password: str):
    """Acquire a fully verified database from dbpath using password.

Parameters:
    dbpath (str | Path): Path to the database file.
    password (str): Password to verify the database.

Raises:
    FileNotFoundError: If there is no file at dbpath.
    DatabaseError: If some database operation failed.
    AuthenticationError: If password verification failed.
    IntegrityError: If the database is corrupt.

Usage:

    This is a context manager for acquiring fully verified databases.
Within the context manager, the database is available using the same
interface as that of authenticated(). The verified() context manager
should be used when accessing only the vault names without looking at
the associated secrets, for example, when listing all the vault names.
An authenticated, but unverified database could have vault names that
have been inserted by an attacker. The time taken to acquire a fully
verified database increases with the number of key-value mappings in the
database.

        with verified("xyz.db", "hunter2") as vdb:
            for vault in vdb:
                print(vault)

    Upon exit, all changes are written back to "xyz.db" or one of the
exceptions is raised.
"""

    dbpath = _to_path(dbpath)
    db = _Database(dbpath)
    db._authenticate(password)
    db._verify()
    yield db
    db._writeback()


def relock(dbpath: str | Path, old_password: str, new_password: str):
    """Relock the database using a new password.

Parameters:
    dbpath (str | Path): Path to the database file.
    old_password (str): Old password locking the database.
    new_password (str): New password to lock the database

Returns:
    None: On success.

Raises:
    FileNotFoundError: If there is no file at dbpath.
    IntegrityError: If the database is corrupt.
    AuthenticationError: If old_password verification failed..
    DatabaseError: If some database operation failed.
    """

    dbpath = _to_path(dbpath)

    temp_path = None

    try:
        fd, temp_name = tempfile.mkstemp(suffix='.db', dir=dbpath.parent)
        temp_path = Path(temp_name)
        os.close(fd)
        temp_path.unlink()

        initialize(temp_path, new_password)
        with verified(dbpath, old_password) as old_db:
            with verified(temp_path, new_password) as temp_db:
                for vault in old_db:
                    temp_db[vault] = old_db[vault]
        os.replace(temp_path, dbpath)
    except FileExistsError:
        raise DatabaseError(f"Failed to relock database {dbpath}.")
    finally:
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


def backup(dbpath: str | Path, aad: str, password: str, fobj: io.BytesIO) -> None:
    """Backup the database into a file-like object.

All contents of the database are encrypted and authenticated in the
file-like object. In particular, the keys are encrypted as well.

Parameters:
    dbpath (str | Path): Path to the database file.
    aad (str): Authenticated associated data in the backup file.
    password (str): Old password locking the database.

Returns:
    None: On success.

Raises:
    FileNotFoundError: If there is no file at dbpath.
    IntegrityError: If the database is corrupt.
    AuthenticationError: If password verification failed..
    ValueError: If the aad is too long.
    """

    dbpath = _to_path(dbpath)

    aad_bytes = aad.encode('utf-8')
    n = len(aad_bytes)
    if n > 255:
        raise ValueError(f"AAD is too long (must be at most 255 bytes).")

    with verified(dbpath, password) as vdb:
        dbbytes = vdb._connection.serialize()
        ciphertext, salt = _encrypt(dbbytes, aad, password)
        fobj.write(_BACKUP_MAGIC)
        fobj.write(int.to_bytes(n))
        fobj.write(aad_bytes)
        fobj.write(salt)
        fobj.write(ciphertext)

def restore(infile: io.BytesIO, password: str, dbpath: Path) -> str:
    """Restore a database into dbpath from infile.

Parameters:
    infile (io.BytesIO): Binary file-like object storing backup.
    password (str): The main password for the database.
    dbpath (Path): Path to the restored database file.

Returns:
    str: Authenticated associated data upon successful restore.

Raises:
    IntegrityError: If the backup in infile or the restored database is corrupt.
    AuthenticationError: If password verification failed.
    DatabaseError: If writing to dbpath failed.
    """

    if infile.read(len(_BACKUP_MAGIC)) != _BACKUP_MAGIC:
        raise IntegrityError("Corrupt header in backup.")

    n = int.from_bytes(infile.read())
    aad_bytes = infile.read(n)
    if len(aad_bytes) != n:
        raise IntegrityError("Corrupt backup.")

    try:
        aad = aad_bytes.decode('utf-8')
    
        salt = infile.read(_BACKUP_SALT_LEN)
        ciphertext = infile.readall()
    
        plaintext = _decrypt(ciphertext, aad, password, salt)
    except UnicodeDecodeError:
        raise IntegrityError("Corrupt AAD in backup.")
    except nacl.exceptions.CryptoError:
        raise AuthenticationError("Failed to decrypt backup.")

    with tempfile.NamedTemporaryFile(suffix='.db', mode='wb', dir=dbpath.parent) as temp_file:
        temp_file.write(plaintext)
        with verified(temp_file.name, password):
            pass

        try:
            os.replace(temp_file.name, dbpath)
        except OSError:
            raise DatabaseError("Failed to make database {dbpath}.")

    return aad

class DatabaseError(Exception):
    pass

class AuthenticationError(Exception):
    pass

class IntegrityError(Exception):
    pass

class VaultNotFoundError(KeyError):
    pass

def _to_path(p: str | Path) -> Path:
    """Make a Path object from p."""

    if isinstance(p, str):
        return Path(p)
    return p

def _b64text(b: bytes) -> str:
    """A Python string of the base64 encoding of bytes b."""

    return base64.b64encode(b).decode('utf-8')

def _textb64(s: str) -> bytes:
    """Bytes by decoding base64 string."""

    return base64.b64decode(s.encode('utf-8'))

def _utcnowiso() -> str:
    """Return current UTC time in ISO format."""

    return datetime.datetime.now(datetime.UTC).isoformat()

def _kmac(b: bytes, password: str, salt: None | bytes = None) -> Tuple[bytes, bytes]:
    """Compute keyed MAC of bytes b using a key derived from password and salt."""

    if salt is None:
        salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)

    key = nacl.pwhash.argon2id.kdf (
        nacl.hash.BLAKE2B_KEYBYTES,
        password.encode('utf-8'),
        salt,
        opslimit=nacl.pwhash.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.MEMLIMIT_INTERACTIVE
    )

    return (
        nacl.hash.blake2b (
            b,
            key=key,
            person=f"{PROGNAME}-{VERSION}".encode('utf-8'),
            encoder=nacl.encoding.RawEncoder
        ),
        salt
    )

def _encrypt(plain: bytes, aad: bytes, password: str, salt: None | bytes = None) -> Tuple[bytes, bytes]:
    """Encrypt plain with authenticated associated data aad using password and salt."""

    if salt is None:
        salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)

    key = nacl.pwhash.argon2id.kdf (
        nacl.secret.Aead.KEY_SIZE,
        password.encode('utf-8'),
        salt,
        opslimit=nacl.pwhash.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.MEMLIMIT_INTERACTIVE
    )

    box = nacl.secret.Aead(key, nacl.encoding.RawEncoder)

    return (box.encrypt(plain, aad), salt)

def _decrypt(secret: bytes, aad: bytes, password: str, salt: bytes) -> bytes:
    """Decrypt secret after authenticating aad using password and salt."""

    key = nacl.pwhash.argon2id.kdf (
        nacl.secret.Aead.KEY_SIZE,
        password.encode('utf-8'),
        salt,
        opslimit=nacl.pwhash.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.MEMLIMIT_INTERACTIVE
    )

    box = nacl.secret.Aead(key, nacl.encoding.RawEncoder)

    return box.decrypt(secret, aad)

class _Database(collections.abc.MutableMapping):
    """An mypass database.
    """

    def __init__(self, dbpath: Path):
        """
        """
        if not dbpath.exists():
            raise FileNotFoundError(f"No database found at {dbpath}.")
 
        try:
            self._dbpath = dbpath
            self._connection = sqlite3.connect(dbpath, autocommit=False)
            dbbytes = self._connection.serialize()
            self._connection.deserialize(dbbytes)
        except sqlite3.Error:
            raise DatabaseError(f"Failed to load {dbpath}.")
 
        try:
            result_row = self._connection.execute (
                "SELECT pwhash, enc_salt, mac_salt FROM main WHERE version = ?",
                (VERSION,)
            ).fetchone()
            if result_row is None:
                raise DatabaseError(f"Failed to fetch main row from database {dbpath}.")
            self._pwhash = result_row[0]
            self._enc_salt = _textb64(result_row[1])
        except sqlite3.Error:
            raise DatabaseError(f"Some operation on database {dbpath} failed.")
 
        self._password = None

    def _authenticate(self, password: str):

        try:
            nacl.pwhash.verify(self._pwhash.encode('utf-8'), password.encode('utf-8'))
        except nacl.exceptions.InvalidkeyError:
            raise AuthenticationError(f"Failed to authenticate {self._dbpath} using given password.")
 
        self._password = password
 
    def _verify(self):

        assert self._password is not None

        try:
            result_row = self._connection.execute(
                "SELECT mac_salt, mac FROM main WHERE version = ?",
                (VERSION,)
            ).fetchone()
        except sqlite3.Error:
            raise DatabaseError(f"Some operation on database {self._dbpath} failed.")

        if result_row is None:
            raise DatabaseError(f"Failed to fetch main row from database {dbpath}.")

        mac_salt, mac = result_row

        expected_mac, _ = _kmac(self._all_bytes(), self._password, _textb64(mac_salt))

        if expected_mac != _textb64(mac):
            raise IntegrityError(f"Database {self._dbpath} failed verification.")

    def _writeback(self):

        if self._connection.total_changes > 0:
            try:
                self._connection.execute (
                    "UPDATE main SET last_updated = ? WHERE version = ?",
                    (_utcnowiso(), VERSION)
                )
                mac, mac_salt = _kmac(self._all_bytes(), self._password) # TODO: Can connection read uncommitted data?
                self._connection.execute (
                    "UPDATE main SET mac_salt = ?, mac = ? WHERE version = ?",
                    (_b64text(mac_salt), _b64text(mac), VERSION)
                )
                self._connection.commit()
                with tempfile.NamedTemporaryFile(suffix='.db', mode='wb', dir=self._dbpath.parent) as tempdbfile:
                    tempdb = sqlite3.connect(f"{tempdbfile.name}")
                    with tempdb:
                        self._connection.backup(tempdb)
                    tempdb.close()
                    self._connection.close()
                    os.replace(tempdbfile.name, self._dbpath)
            except sqlite3.Error:
                self._connection.close()
                raise DatabaseError(f"Failed to write changes to database {self._dbpath}")

        self._connection.close()
        del self._password

    def __getitem__(self, name: str) -> bytes:
        """Get the plain-text secret stored in vault name."""

        assert self._password is not None

        try:
            result_row = self._connection.execute("SELECT secret FROM VAULTS WHERE name = ?",  (name,)).fetchone()
            if result_row is None:
                raise VaultNotFoundError(f"Vault {name} not found in database {self._dbpath}.")
            ciphertext = result_row[0]

            plaintext = _decrypt(_textb64(ciphertext), name.encode('utf-8'), self._password, self._enc_salt)
            return plaintext
        except sqlite3.Error:
            raise DatabaseError(f"Database {self._dbpath} could not be read.")
        except nacl.exceptions.CryptoError:
            raise IntegrityError(f"Possibly corrupt secret in vault {name} in {self._dbpath}.")

    def __setitem__(self, name: str, plaintext: bytes):
        """Store plaintext encrypted and authenticated in vault name.

The secret is stored using authenticated encryption where the name is
the authenticated, associated data. This means that an attacker cannot
replace, in an undetectable manner, the stored cipher-text with another
cipher-text originally stored along with a different vault name.
        """

        assert self._password is not None

        ciphertext, _ = _encrypt(plaintext, name.encode('utf-8'), self._password, self._enc_salt)

        self._connection.execute (
            "INSERT OR REPLACE INTO vaults (name, secret) VALUES (?, ?)",
            (name, _b64text(ciphertext))
        )

    def __delitem__(self, name: str):
        """Delete vault name from the database."""

        assert self._password is not None

        try:
            cursor = self._connection.execute (
                "DELETE FROM vaults WHERE name = ?",
                (name, )
            )
            if cursor.rowcount == 0:
                raise VaultNotFoundError(f"Vault {name} not found in database {self._dbpath}.")
        except sqlite3.Error:
            raise DatabaseError(f"Vault {name} could not be deleted from database {self._dbpath}.")

    def __iter__(self):
        """Iterator over vaults."""

        assert self._password is not None

        try:
            rows = self._connection.execute("SELECT name FROM vaults ORDER BY name").fetchall()
            return iter(row[0] for row in rows)
        except sqlite3.Error:
            raise DatabaseError(f"Database {self._dbpath} could not be read.")

    def __len__(self):
        """Return the number of vaults in the database."""

        try:
            result_row = self._connection.execute(
                "SELECT COUNT(*) FROM vaults"
            ).fetchone()
            return result_row[0]
        except sqlite3.Error:
            raise DatabaseError(f"Database {self._dbpath} could not be read.")

    def __contains__(self, name):

        try:
            result_row = self._connection.execute(
                "SELECT 1 FROM vaults WHERE name = ?", (name,)
            ).fetchone()
            return result_row is not None
        except sqlite3.Error:
            raise DatabaseError(f"Database {self._dbpath} could not be read.")

    def _all_bytes(self) -> bytes:
        """Return bytes to compute MAC."""

        try:
            result_row = self._connection.execute (
                "SELECT version, last_updated, pwhash, enc_salt FROM MAIN WHERE version = ?",
                (VERSION,)
            ).fetchone()
            if result_row is None:
                raise DatabaseError(f"Failed to fetch main row from database {self._dbpath}.")
    
            version, last_updated, pwhash, enc_salt = result_row
    
            data = version.encode('utf-8') + last_updated.encode('utf-8') + pwhash.encode('utf-8') + _textb64(enc_salt)
    
            for row in self._connection.execute("SELECT name, secret FROM vaults ORDER BY name"):
                name = row[0]
                secret = row[1]
                data = data + name.encode('utf-8') + _textb64(secret)
    
            return data
        except sqlite3.Error:
            raise DatabaseError(f"Database operation failed on {self._dbpath}.")

_BACKUP_MAGIC = b'mypass-0.2-backup'
_BACKUP_SALT_LEN = nacl.pwhash.argon2id.SALTBYTES
