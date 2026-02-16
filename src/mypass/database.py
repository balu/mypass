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
"""

import base64
import collections.abc
import datetime
import io
from pathlib import Path
import sqlite3
from typing import Tuple

import nacl.hash
import nacl.pwhash
import nacl.secret
import nacl.utils

PROGNAME='mypass'
VERSION = '0.2'

class DatabaseError(Exception):
    pass

class AuthenticationError(Exception):
    pass

class IntegrityError(Exception):
    pass

class VaultNotFoundError(KeyError):
    pass

def b64text(b: bytes) -> str:
    """A Python string of the base64 encoding of bytes b."""
    return base64.b64encode(b).decode('utf-8')

def textb64(s: str) -> bytes:
    """Bytes by decoding base64 string."""
    return base64.b64decode(s.encode('utf-8'))

def utcnowiso() -> str:
    """Return current UTC time in ISO format."""
    return datetime.datetime.now(datetime.UTC).isoformat()

def kmac(b: bytes, password: str, salt: None | bytes = None) -> Tuple[bytes, bytes]:
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

def encrypt(plain: bytes, aad: bytes, password: str, salt: None | bytes = None) -> Tuple[bytes, bytes]:
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

def decrypt(secret: bytes, aad: bytes, password: str, salt: bytes) -> bytes:
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

def initialize(dbpath: Path, password: str) -> None:
    """Initialize an empty database at dbpath.

Parameters:
    dbpath (Path): Path to the database file.
    password (str): Password to protect the database.

Returns:
    None: On success.

Raises:
    FileExistsError: If a file already exists at dbpath.
    DatabaseError: If database creation failed.
    """

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

        now = utcnowiso()

        pwhash = nacl.pwhash.str(password.encode('utf-8')).decode('utf-8')

        _, enc_salt = encrypt(f"{PROGNAME}".encode('utf-8'), f"{PROGNAME}".encode('utf-8'), password)

        mac, mac_salt = kmac (
            VERSION.encode('utf-8') + now.encode('utf-8') + pwhash.encode('utf-8') + enc_salt,
            password
        )

        cursor.execute (
            """
            INSERT
            INTO main (version, last_updated, pwhash, enc_salt, mac_salt, mac)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (VERSION, now, pwhash, b64text(enc_salt), b64text(mac_salt), b64text(mac))
        )

        cursor.close()
        connection.commit()
        connection.close()

    except Exception as e:
        raise DatabaseError(f"Failed to create database at {dbpath}: {e}")
    
class AuthenticatedDatabase(collections.abc.MutableMapping):
    """An authenticated database.
    """

    def __init__(self, dbpath: Path, password: str):
       """
       """
       if not dbpath.exists():
           raise FileNotFoundError(f"No database found at {dbpath}.")

       try:
           self._connection = sqlite3.connect(dbpath, autocommit=False)
       except:
           raise DatabaseError(f"Failed to establish connection to {dbpath}.")

       try:
           result_row = self._connection.execute (
               "SELECT pwhash, enc_salt, mac_salt FROM main WHERE version = ?",
               (VERSION,)
           ).fetchone()
           if result_row is None:
               raise DatabaseError(f"Failed to fetch main row from database {dbpath}.")
           pwhash = result_row[0]
           nacl.pwhash.verify(pwhash.encode('utf-8'), password.encode('utf-8'))
       except nacl.exceptions.InvalidkeyError:
           raise AuthenticationError(f"Failed to unlock {dbpath} using given password.")
       except sqlite3.Error:
           raise DatabaseError(f"Some operation on database {dbpath} failed.")

       self._dbpath = dbpath
       self._enc_salt = textb64(result_row[1])
       self._password = password

    def __enter__(self):
        """
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup after database operations.

This function recomputes the database MAC if required and commits all
changes if no exception occured. Otherwise, all changes that happened
within the context are rolled back.
"""

        if exc_type is None:
            if self._connection.total_changes > 0:
                try:
                    self._connection.execute (
                        "UPDATE main SET last_updated = ? WHERE version = ?",
                        (utcnowiso(), VERSION)
                    )
                    mac, mac_salt = kmac(self._all_bytes(), self._password) # TODO: Can connection read uncommitted data?
                    self._connection.execute (
                        "UPDATE main SET mac_salt = ?, mac = ? WHERE version = ?",
                        (b64text(mac_salt), b64text(mac), VERSION)
                    )
                    self._connection.commit()
                    self._connection.close()
                    return False
                except sqlite3.Error:
                    self._connection.close()
                    raise DatabaseError(f"Failed to commit changes to database {self._dbpath}")

        self._connection.close()
        del self._password
        return False

    def __getitem__(self, name: str) -> bytes:
        """Get the plain-text secret stored in vault name."""

        try:
            result_row = self._connection.execute("SELECT secret FROM VAULTS WHERE name = ?",  (name,)).fetchone()
            if result_row is None:
                raise VaultNotFoundError(f"Vault {name} not found in database {self._dbpath}.")
            ciphertext = result_row[0]

            plaintext = decrypt(textb64(ciphertext), name.encode('utf-8'), self._password, self._enc_salt)
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

        ciphertext, _ = encrypt(plaintext, name.encode('utf-8'), self._password, self._enc_salt)

        self._connection.execute (
            "INSERT OR REPLACE INTO vaults (name, secret) VALUES (?, ?)",
            (name, b64text(ciphertext))
        )

    def __delitem__(self, name: str):
        """Delete vault name from the database."""

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
    
            data = version.encode('utf-8') + last_updated.encode('utf-8') + pwhash.encode('utf-8') + textb64(enc_salt)
    
            for row in self._connection.execute("SELECT name, secret FROM vaults ORDER BY name"):
                name = row[0]
                secret = row[1]
                data = data + name.encode('utf-8') + textb64(secret)
    
            return data
        except sqlite3.Error:
            raise DatabaseError(f"Database operation failed on {self._dbpath}.")

def authenticated(dbpath: Path, password: str):
    """Acquire an authenticated database at dbpath using password.

Parameters:
    dbpath (Path): Path to the database file.
    password (str): Password to authenticate.

Returns:
    AuthenticatedDatabase: On success.

Raises:
    FileNotFoundError: If there is no file at dbpath.
    DatabaseError: If some database operation failed.
    AuthenticationError: If password verification failed.
    """

    return AuthenticatedDatabase(dbpath, password)

def verify(dbpath: Path, password: str):
    """Verify the database at dbpath using password.

The database is secure if and only if it has been created or modified
with knowledge of password.

Parameters:
    dbpath (Path): Path to the database file.
    password (str): Password to verify the database.

Returns:
    Bool: True if and only if database is secure.

Raises:
    FileNotFoundError: If there is no file at dbpath.
    DatabaseError: If some database operation failed.
    AuthenticationError: If password verification failed.
    """

    with authenticated(dbpath, password) as adb:
        try:
            result_row = adb._connection.execute(
                "SELECT mac_salt, mac FROM main WHERE version = ?",
                (VERSION,)
            ).fetchone()
        except sqlite3.Error:
            raise DatabaseError(f"Some operation on database {dbpath} failed.")

        if result_row is None:
            raise DatabaseError(f"Failed to fetch main row from database {dbpath}.")

        mac_salt, mac = result_row

        expected_mac, _ = kmac(adb._all_bytes(), password, textb64(mac_salt))

        return expected_mac == textb64(mac)

def relock(dbpath: Path, old_password: str, new_password: str):
    """Relock the database using a new password.

Parameters:
    dbpath (Path): Path to the database file.
    old_password (str): Old password locking the database.
    new_password (str): New password to lock the database

Returns:
    None: On success.

Raises:
    FileNotFoundError: If there is no file at dbpath.
    IntegrityError: If the database is corrupt.
    AuthenticationError: If old_password verification failed..
    """

    pass

def backup(dbpath: Path, password: str, fobj: io.FileIO):
    """Backup the database into a file-like object.

All contents of the database are encrypted and authenticated in the
file-like object. In particular, the keys are encrypted as well.

Returns:
    None: On success.

Raises:
    FileNotFoundError: If there is no file at dbpath.
    IntegrityError: If the database is corrupt.
    AuthenticationError: If password verification failed..
    """
    pass

def restore(infile: io.FileIO, password: str, outfile: io.FileIO):
    """Restore a database into outfile from infile.

Returns:
    None: On success.

Raises:
    FileExistsError: If there is a file at dbpath.
    IntegrityError: If the backup in fobj or the restored database is corrupt.
    AuthenticationError: If password verification failed..
    """
    pass
