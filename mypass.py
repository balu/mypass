import argparse as ap
from contextlib import contextmanager
from dataclasses import dataclass
import dataset as ds
from datetime import datetime, timezone, timedelta
from dateutil.relativedelta import relativedelta
from dateutil.relativedelta import relativedelta
import json
import keyring
import nacl
from nacl.bindings.utils import sodium_memcmp
from nacl.encoding import HexEncoder
import nacl.pwhash
import nacl.secret
import nacl.utils
import os
import os.path as ospath
import parsimonious as parsi
import pathlib
import pyclip
import questionary as q
import re
import rich.console
from rich.live import Live
import rich.table as rt
from rich.text import Text
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time

PROG = "mypass"

VERSION = "0.1"

CONFIG_DIR="config"

DB_DIR="db"

DEFAULT_DB=ospath.join(DB_DIR, "default.db")

class UserCancelled(Exception):
    pass

class WrongPassword(Exception):
    pass

class CorruptSecret(Exception):
    pass

class NoVault(Exception):
    pass

class ParseError(Exception):
    pass

err = rich.console.Console(stderr=True, style="bold red")
out = rich.console.Console()

def command(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            return
        except EOFError:
            return
        except UserCancelled:
            return
        except WrongPassword:
            err.print("Wrong password.")
            return
        except NoVault:
            err.print("No vault found.")
            return
        except ParseError:
            err.print("Parse error.")
            return
        except CorruptSecret:
            err.print("Secret corrupted.")
            return
        except Exception as e:
            err.print("Unexpected error:", e)
            return
    return wrapper


_is_wordlist_loaded = False
_wordlist = []

def _word(filename=ospath.join(CONFIG_DIR, "wordlist.txt")):
    if not _is_wordlist_loaded:
        with open(filename, "r") as file:
            _wordlist = list(map(lambda line: line.strip(), file.readlines()))
    return _wordlist[secrets.randbelow(len(_wordlist))]

SPECIAL_STRINGS = {
    r'\a': "abcdefghijklmnopqrstuvwxyz",
    r'\A': "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    r'\d': "0123456789",
    r'\s': r"""~`!@#$%^*()-_=+[]{};:'"\|,<.>/?""",
    r'\w': _word,
}

class Pattern:
    def generate(p: 'Pattern') -> str:
        match p:
            case _Literal(c):
                return c
            case _Or(ps):
                return Pattern.generate(secrets.choice(ps))
            case _Concat(ps):
                return "".join(map(Pattern.generate, ps))
            case _Count(p, l, u, sep):
                c = l + secrets.randbelow(u-l+1)
                return Pattern.generate(sep).join((Pattern.generate(p) for _ in range(c)))
            case _Special(key):
                what = SPECIAL_STRINGS[key]
                if isinstance(what, str):
                    return secrets.choice(what)
                else:
                    return what()
            case _:
                assert False, f"Unknown pattern {p}"

    def parse(format: str) -> 'Pattern':
        grammar = parsi.Grammar (
        r"""
        pattern = or
        or      = or1 / concat
        or1     = concat "+" or
        concat  = (count / atom)*
        count   = count1 / count2 / count3
        count1  = atom "{" ~r"[0-9]+" "}"
        count2  = atom "{" ~r"[0-9]+" "," ~r"[0-9]+" "}"
        count3  = atom "{" ~r"[0-9]+" "," ~r"[0-9]*" "," pattern "}"
        atom    = literal / escaped / special / paren
        paren   = "(" pattern ")"
        literal = ~r"([^\+\\\{\}\(\)\,])+"
        escaped = ~r"\\[\+\\\{\}\(\),]"
        special = ~r"\\[aAdsw]"
        """
        )
        class PatternVisitor(parsi.NodeVisitor):
            def generic_visit(self, node, children):
                return children or node

            def visit_special(self, node, children):
                return _Special(node.text)

            def visit_escaped(self, node, children):
                def unescape(text):
                    return text[1:]

                return _Literal(unescape(node.text))

            def visit_literal(self, node, children):
                return _Literal(node.text)

            def visit_paren(self, node, children):
                return children[1]

            def visit_atom(self, node, children):
                return children[0]

            def visit_count3(self, node, children):
                a, _, l, _, u, _, s, _ = children
                l = int(l.text)
                if not u.text:
                    u = l
                else:
                    u = int(u.text)
                return _Count(a, l, u, s)

            def visit_count2(self, node, children):
                a, _, l, _, u, _ = children
                return _Count(a, int(l.text), int(u.text), _Literal(''))

            def visit_count1(self, node, children):
                a, _, l, _ = children
                return _Count(a, int(l.text), int(l.text), _Literal(''))

            def visit_count(self, node, children):
                return children[0]

            def visit_concat(self, node, children):
                return _Concat(list(map(lambda c: c[0], children)))

            def visit_or1(self, node, children):
                def flatten(p):
                    match p:
                        case _Or(cs): return cs
                    return [p]

                c, _, o = children
                return _Or([*flatten(c), *flatten(o)])

            def visit_or(self, node, children):
                return children[0]

            def visit_pattern(self, node, children):
                return children[0]

        try:
            return PatternVisitor().visit(grammar.parse(format))
        except parsi.exceptions.ParseError:
            raise ParseError()

@dataclass
class _Literal(Pattern):
    c: str

@dataclass
class _Special(Pattern):
    c: str

@dataclass
class _Or(Pattern):
    children: Pattern

@dataclass
class _Concat(Pattern):
    children: list[Pattern]

@dataclass
class _Count(Pattern):
    what:  Pattern
    lower: int
    upper: int
    sep:   Pattern

def _generate(format):
    return Pattern.generate(Pattern.parse(format))

@command
def generate(format):
    out.print(_generate(format))

def _to_utf8(s: str) -> bytes:
    return s.encode('utf-8')

def _from_utf8(b: bytes) -> str:
    return b.decode('utf-8')

def _salt():
    return nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)

def _key(password: str, salt: bytes) -> bytes:
    return nacl.pwhash.argon2id.kdf (
        32,
        _to_utf8(password),
        salt=salt
    )

def _encrypt(plain: bytes, key: bytes) -> bytes:
    box    = nacl.secret.SecretBox(key)
    cipher = box.encrypt(plain)
    return cipher

def _decrypt(cipher: bytes, key: bytes) -> bytes:
    box = nacl.secret.SecretBox(key)
    return box.decrypt(cipher)

def _make_vault (
        name:   str,
        ctime:  str,
        secret: str,
        key:    bytes

) -> dict:
    uname, uctime, usecret = list(map(_to_utf8, [name, ctime, secret]))
    cipher = _encrypt(uname+uctime+usecret, key)
    return dict (
        name=name,
        ctime=ctime,
        secret=cipher
    )

def _extract_secret (
        name:   str,
        ctime:  str,
        secret: bytes,
        key:    bytes
) -> str:
    uname, uctime = list(map(_to_utf8, [name, ctime]))
    prefix = uname + uctime
    decrypted = _decrypt(secret, key)
    if not decrypted.startswith(prefix):
        raise CorruptSecret()
    return _from_utf8(decrypted[len(prefix):])

def _db(name):
    return ds.connect(f'sqlite:///{ospath.join(DB_DIR, name+".db")}')

@contextmanager
def authenticated(dbname):

    he = HexEncoder()

    def _verify(password: str, db):
        pwhash = db['main'].find_one()['pwhash']
        try:
            nacl.pwhash.verify(pwhash, _to_utf8(password))
            return True
        except nacl.exceptions.InvalidkeyError:
            return False

    db = _db(dbname)
    password = keyring.get_password(PROG, f"password({dbname})")
    if password and _verify(password, db):
        key = he.decode(keyring.get_password(PROG, f"key({dbname})"))
        yield (db, key)
    else:
        password = q.password(f'Unlock password for {dbname}').ask()
        if password is None:
            raise UserCancelled()
        if _verify(password, db):
            salt = db['main'].find_one()['salt']
            key = _key(password, salt)
            keyring.set_password(PROG, f"password({dbname})", password)
            keyring.set_password(PROG, f"key({dbname})", he.encode(key))
            yield (db, key)

def _secret(name: str, dbname="default") -> str:
    with authenticated(dbname) as (db, key):
        row = db['vaults'].find_one(name=name)
        if row:
            return _extract_secret(key=key, **row)
        raise NoVault()

def _policy(name: str, db, key: bytes):
    row = db['vault_policy'].find_one(name=name)
    if row:
        uname, uformat, uuinterval, uctime = list(map(_to_utf8, [name, row['format'], row['uinterval'], row['ctime']]))
        stored_digest = row['digest']
        data = _decrypt(stored_digest, key)
        if data != uname+uformat+uuinterval+uctime:
            raise CorruptSecret()
        return row

@command
def show(name: str, time_limit=10, dbname="default"):

    s = _secret(name, dbname=dbname)

    if time_limit is None:
        out.print(s)
        return

    with Live(s, transient=True, auto_refresh=False, console=out) as live:
        time.sleep(time_limit)

def _now():
    return datetime.now(timezone.utc).isoformat()

@command
def init(dbname="default"):

    dbfile = pathlib.Path(ospath.join(DB_DIR, dbname+".db"))
    if dbfile.exists():
        if not q.confirm("Database exists. Do you want to overwrite").unsafe_ask():
            return
        dbfile.unlink()

    try:
        connection = sqlite3.connect(dbfile)
        cursor = connection.cursor()
        schema = """
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "vaults" (
	"name"	TEXT NOT NULL,
	"ctime"	TEXT NOT NULL,
	"secret"	BLOB NOT NULL,
	PRIMARY KEY("name")
);
CREATE TABLE IF NOT EXISTS "vault_policy" (
	"name"	TEXT NOT NULL,
	"format"	TEXT NOT NULL,
	"uinterval"	TEXT NOT NULL,
	"ctime"	TEXT NOT NULL,
	"digest"	BLOB NOT NULL,
	PRIMARY KEY("name")
);
CREATE TABLE IF NOT EXISTS "main" (
	"version"	TEXT NOT NULL CHECK("version" == '0.1'),
	"pwhash"	BLOB NOT NULL,
	"salt"	BLOB NOT NULL,
	PRIMARY KEY("version")
);
COMMIT;
        """
        cursor.executescript(schema)
        connection.commit()
        connection.close()
    except Exception as e:
        err.print('Failed to create database file:', e)
        dbfile.unlink()
        return

    retries = 0
    while retries < 3:
        password1 = q.password('Set unlock password').unsafe_ask()
        password2 = q.password('Retype unlock password').unsafe_ask()
        if password1 == password2:
            break
        err.print("Passwords do not match.")
        retries = retries + 1
    if retries == 3:
        return

    db = _db(dbname)
    pwhash = nacl.pwhash.str(_to_utf8(password1))
    db['main'].insert(dict (
        version=VERSION,
        pwhash=pwhash,
        salt=_salt()
    ))

def _serialize_rd(rd):
    return f'{{ "years":{rd.years}, "months":{rd.months}, "days":{rd.days} }}'

def _deserialize_rd(text):
    return relativedelta(**json.loads(text))

def _ask_relative_delta():
    reply = q.text('Update interval').unsafe_ask()
    mat = re.match(r'((?P<years>[0-9]+)y)?((?P<months>[0-9]+)m)?((?P<days>[0-9]+)d)?', reply)
    if mat and mat.group(0):
        y = (y:=mat.group('years'))  and int(y) or 0
        m = (m:=mat.group('months')) and int(m) or 0
        d = (d:=mat.group('days'))   and int(d) or 0
        return relativedelta(years=y,months=m,days=d)
    raise ParseError()

@command
def set_policy(name: str, dbname="default", **kwargs):
    db = _db(dbname)
    format = kwargs.get('format', None)
    update = kwargs.get('update', None)

    overwrite = False
    if db['vault_policy'].find_one(name=name):
        if q.confirm(f'Vault {name} already has a policy. Overwrite').unsafe_ask():
            overwrite = True
        else:
            return

    if format is None:
        tries = 0
        while tries < 3:
            format = q.text('Format').unsafe_ask()
            try:
                Pattern.parse(format)
            except ParseError:
                err.print(f"Failed to parse {format}.")
                tries = tries + 1
                continue
            break
        if tries == 3:
            return
    if update is None:
        tries = 0
        while tries < 3:
            try:
                update = _ask_relative_delta()
            except ParseError:
                err.print("Failed to parse update interval.")
                tries = tries + 1
                continue
            break
        if tries == 3:
            return

    with authenticated(dbname) as (db, key):
        ctime = _now()
        if overwrite:
            uinterval = _serialize_rd(update)
            uname, uformat, uuinterval, uctime = list(map(_to_utf8, [name, format, uinterval, ctime]))
            digest = _encrypt(uname+uformat+uuinterval+uctime, key)
            new_policy = dict (
                name=name,
                format=format,
                uinterval=uinterval,
                ctime=ctime,
                digest=digest
            )
            db['vault_policy'].update(new_policy, ['name'])
        else:
            uinterval = _serialize_rd(update)
            uname, uformat, uuinterval, uctime = list(map(_to_utf8, [name, format, uinterval, ctime]))
            digest = _encrypt(uname+uformat+uuinterval+uctime, key)
            new_policy = dict (
                name=name,
                format=format,
                uinterval=uinterval,
                ctime=ctime,
                digest=digest
            )
            db['vault_policy'].insert(new_policy)

@command
def insert(name: str, **kwargs):
    dbname = kwargs.get('dbname', "default")
    multiline = bool(kwargs.get('multiline', False))
    db = _db(dbname)

    overwrite = False
    if old_row := db['vaults'].find_one(name=name):
        if q.confirm(f'Vault {name} already exists. Overwrite').unsafe_ask():
            overwrite = True
        else:
            return

    with authenticated(dbname) as (db, key):
        p = _policy(name, db, key)
        secret = None
        if p and p['format']:
            if q.confirm(f'Auto-generate secret for vault {name}').unsafe_ask():
                secret = _generate(p['format'])
        if secret is None:
            if multiline:
                # TODO: delete_on_close for Python 3.12
                with tempfile.NamedTemporaryFile(mode='w', delete=True) as fp:
                    editor = os.environ.get("EDITOR", "vi")
                    try:
                        subprocess.run([editor, fp.name], check=True)
                    except subprocess.CalledProcessError:
                        return
                    if q.confirm('Save contents of file as secret').unsafe_ask():
                        with open(fp.name, 'r') as rfp:
                            secret = rfp.read()
                    else:
                        return
            else:
                secret = q.password(f'Secret for {name}').unsafe_ask()
        if overwrite:
            if q.confirm(f'The old secret for {name} will be permanently deleted. Do you wish to see it').unsafe_ask():
                out.print(_extract_secret(key=key, **old_row))
            db['vaults'].update(_make_vault(key=key, name=name, secret=secret, ctime=_now()), keys=['name'])
        else:
            db['vaults'].insert(_make_vault(key=key, name=name, secret=secret, ctime=_now()))

@command
def edit(name: str, dbname="default"):
    db = _db(dbname)
    old_row = db['vaults'].find_one(name=name)
    if not old_row:
        err.print(f"No vault {name} to edit.")
    with authenticated(dbname) as (db, key):
        old_secret = _extract_secret(key=key, **old_row)
        with tempfile.NamedTemporaryFile(mode='x+', delete=True) as temp:
            temp.write(old_secret)
            temp.flush()
            editor = os.environ.get("EDITOR", "vi")
            try:
                subprocess.run([editor, temp.name], check=True)
            except subprocess.CalledProcessError:
                return
            temp.seek(0)
            secret = temp.read()
    db['vaults'].update(_make_vault(key=key, name=name, secret=secret, ctime=_now()), keys=['name'])

@command
def ls(dbname="default", **kwargs):
    long = kwargs.get('long', False)
    with authenticated(dbname) as (db, key):
        if long:
            t = rt.Table(show_header=False, box=None, padding=(0, 4, 0, 0))
            for s in db['vaults']:
                name = s['name']
                ctime = datetime.fromisoformat(s['ctime'])
                expires = None
                if p := _policy(name, db, key):
                    expires = ctime+_deserialize_rd(p['uinterval'])
                now = datetime.now(timezone.utc)
                if expires and expires-now <= timedelta(days=7):
                    name = Text(name, style="bold red")
                elif expires and expires-now <= timedelta(days=30):
                    name = Text(name, style="yellow")
                else:
                    name = Text(name, style="green")
                ctime = ctime.strftime('%Y-%m-%d')
                if expires:
                    expires = expires.strftime('%Y-%m-%d')
                else:
                    expires = 'never'
                t.add_row(name, ctime, expires)
            out.print(t)
        else:
            for s in db['vaults']:
                out.print(s['name'])

@command
def list_databases():
    for path in pathlib.Path(DB_DIR).iterdir():
        if path.suffix == '.db':
            out.print(path.stem)

@command
def reencrypt(dbname="default"):
    with authenticated(dbname) as (db, old_key):
        retries = 0
        while retries < 3:
            password1 = q.password("New password").unsafe_ask()
            password2 = q.password("Retype new password").unsafe_ask()
            if password1 == password2:
                break
            err.print("Passwords do not match")
            retries = retries + 1
        if retries == 3:
            err.print("Too many attempts")
            return

        new_password = password1
        new_salt     = _salt()
        new_key      = _key(new_password, new_salt)
        new_ctime    = _now()

        def reencrypt_secret(old_row):
            secret = _extract_secret(key=old_key, **old_row)
            return _make_vault (
                key=new_key,
                name=old_row['name'],
                ctime=new_ctime,
                secret=secret
            )

        def reencrypt_policy(old_policy):
            name=old_policy['name']
            format=old_policy['format']
            uinterval=old_policy['uinterval']
            ctime=old_policy['ctime']
            uname, uformat, uuinterval, uctime = list(map(_to_utf8, [name, format, uinterval, ctime]))
            new_digest = _encrypt(uname+uformat+uuinterval+uctime, new_key)
            return dict (
                name=name,
                format=format,
                uinterval=uinterval,
                digest=new_digest
            )

        db.begin()
        main = dict (
            version=VERSION,
            pwhash=nacl.pwhash.str(_to_utf8(new_password)),
            salt=new_salt
        )
        db['main'].update(main, ['version'])
        db['vaults'].update_many (
            list(map(reencrypt_secret, db['vaults'])),
            ['name']
        )
        db['vault_policy'].update_many (
            list(map(reencrypt_policy, db['vault_policy'])),
            ['name']
        )
        db.commit()

@command
def clip(name, dbname="default"):
    pyclip.copy(_secret(name, dbname=dbname))

@command
def rename(vfrom, vto, dbname="default"):
    with authenticated(dbname) as (db, key):
        vault = db['vaults'].find_one(name=vfrom)
        vault_policy = db['vault_policy'].find_one(name=vfrom)

        if not vault and not vault_policy:
            return

        new_vault = None
        if vault:
            new_vault = _make_vault (
                key=key,
                name=vto,
                ctime=vault['ctime'],
                secret=_extract_secret(key=key, **vault)
            )

        new_vault_policy = None
        if vault_policy:
            name=vto
            format=vault_policy['format']
            uinterval=vault_policy['uinterval']
            ctime=vault_policy['ctime']
            uname, uformat, uuinterval, uctime = map(_to_utf8, [name, format, uinterval, ctime])
            new_vault_policy = dict (
                name=name,
                format=format,
                uinterval=uinterval,
                ctime=ctime,
                digest=_encrypt(uname+uformat+uuinterval+uctime, key)
            )

        db.begin()
        if new_vault:
            db['vaults'].insert(new_vault)
            db['vaults'].delete(**vault)
        if new_vault_policy:
            db['vault_policy'].insert(new_vault_policy)
            db['vault_policy'].delete(**vault_policy)
        db.commit()

if __name__ == "__main__":

    mp_parser = ap.ArgumentParser(prog=PROG)
    subparsers = mp_parser.add_subparsers(help='sub-command help', dest='subcommand')

    generate_parser = subparsers.add_parser('generate', help='generate secrets')
    generate_parser.add_argument('format', help='format of the secret', nargs='?', default=r'\w{6,6, }')

    init_parser = subparsers.add_parser('init', help='initialize database')
    init_parser.add_argument('dbname', help='name of the database', nargs='?', default='default')

    insert_parser = subparsers.add_parser('insert', help='insert secret into vault')
    insert_parser.add_argument('--db', dest='dbname', help='name of the database', default='default')
    insert_parser.add_argument('--multiline', action='store_true', help='multiline secret (opens $EDITOR for obtaining secret)')
    insert_parser.add_argument('vault', help='vault name')

    edit_parser = subparsers.add_parser('edit', help='edit secret in vault')
    edit_parser.add_argument('--db', dest='dbname', help='name of the database', default='default')
    edit_parser.add_argument('vault', help='vault name')

    show_parser = subparsers.add_parser('show', help='show secret')
    show_parser.add_argument('--time-limit', dest='time_limit', help='time (in seconds) after which the secret should be erased from the terminal', default='10')
    show_parser.add_argument('--db', dest='dbname', help='name of the database', default='default')
    show_parser.add_argument('vault', help='vault name')

    ls_parser = subparsers.add_parser('ls', help='list vault names')
    ls_parser.add_argument('--db', dest='dbname', help='name of the database', default='default')
    ls_parser.add_argument('-l', '--long', action='store_true', help='long listing')

    list_databases_parser = subparsers.add_parser('list-databases', help='list available databases')

    set_policy_parser = subparsers.add_parser('set-policy', help='set vault policy')
    set_policy_parser.add_argument('--db', dest='dbname', help='name of the database', default='default')
    set_policy_parser.add_argument('-f', '--format', help='password format', default=None)
    set_policy_parser.add_argument('-u', '--update-interval', dest='update', help='how often should the secret be updated', default=None)
    set_policy_parser.add_argument('vault', help='vault name to which the policy is applied')

    reencrypt_parser = subparsers.add_parser('reencrypt', help='reencrypt using a new password')
    reencrypt_parser.add_argument('--db', dest='dbname', help='name of the database', default='default')

    clip_parser = subparsers.add_parser('clip', help='put secret into clipboard')
    clip_parser.add_argument('--db', dest='dbname', help='name of the database', default='default')
    clip_parser.add_argument('vault', help='vault name')

    rename_parser = subparsers.add_parser('rename', help='rename a vault')
    rename_parser.add_argument('--db', dest='dbname', help='name of the database', default='default')
    rename_parser.add_argument('--from', dest='vfrom', help='current name')
    rename_parser.add_argument('--to', dest='vto', help='new name')

    args = mp_parser.parse_args()
    match args.subcommand:
        case "generate":
            generate(args.format)
        case "init":
            init(dbname=args.dbname)
        case "insert":
            insert(args.vault, dbname=args.dbname, multiline=args.multiline)
        case "edit":
            edit(args.vault, dbname=args.dbname)
        case "show":
            if args.time_limit == 'none':
                t = None
            else:
                try:
                    t = int(args.time_limit)
                except:
                    err.print("time-limit should be an integer or 'none'.")
                    sys.exit(1)
            show(args.vault, time_limit=t, dbname=args.dbname)
        case "ls":
            ls(dbname=args.dbname, long=args.long)
        case "list-databases":
            list_databases()
        case "set-policy":
            set_policy(args.vault, dbname=args.dbname, format=args.format, update=args.update)
        case "reencrypt":
            reencrypt(dbname=args.dbname)
        case "clip":
            clip(name=args.vault, dbname=args.dbname)
        case "rename":
            rename(vfrom=args.vfrom, vto=args.vto, dbname=args.dbname)
