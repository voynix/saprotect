import sqlite3

from hashlib import sha1
from os import walk
from os.path import abspath, join
from sys import argv
from time import time

DATA_TABLE_NAME = 'files'
SAPROTECT_TABLE_NAME = 'sapro'
METADATA_TABLE_NAME = 'metadata'

CHUNK_SIZE = 4096

class DB_Manager(object):
    def __init__(self):
        self.conn = None
        self.curs = None


    def __enter__(self):
        self.connect_to_db()
        self.create_tables()
        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect_from_db()


    def connect_to_db(self, db='prot.sql'):
        self.conn = sqlite3.connect(db)
        self.curs = self.conn.cursor()


    def disconnect_from_db(self):
        self.conn.commit()
        self.conn.close()


    def create_tables(self):
        command = '''CREATE TABLE IF NOT EXISTS {}
                    (filename TEXT, path TEXT, hash TEXT, old_hash TEXT,
                    time TEXT, old_time TEXT)'''.format(DATA_TABLE_NAME)
        self.curs.execute(command)
        self.curs.execute('''CREATE TABLE IF NOT EXISTS {}
                        (version TEXT, hash TEXT)'''.format(SAPROTECT_TABLE_NAME))
        self.curs.execute('''CREATE TABLE IF NOT EXISTS {}
                        (start TEXT, end TEXT, files_scanned INTEGER)'''.format(METADATA_TABLE_NAME))
        self.conn.commit()


    def upsert_file(self, filename, path, hash):
        command = 'SELECT COUNT(*) FROM {} WHERE filename = ? AND path = ?'.format(DATA_TABLE_NAME)
        self.curs.execute(command, (filename, path))
        count = self.curs.fetchone()[0]
        if count == 0:
            self.curs.execute('''INSERT INTO {}(filename, path, hash, time)
                                 VALUES (?, ?, ?, ?)'''.format(DATA_TABLE_NAME), (filename, path, hash, time()))
        else:
            self.curs.execute('''UPDATE {} SET old_hash = hash, old_time = time
                                 WHERE filename = ? AND path = ?'''.format(DATA_TABLE_NAME), (filename, path))
            self.curs.execute('''UPDATE {} SET hash = ?, time = ?
                                 WHERE filename = ? AND path = ?'''.format(DATA_TABLE_NAME),
                              (hash, time(), filename, path))
        self.conn.commit()


    def check_files(self, show_hashes=False, clean=False):
        self.curs.execute('SELECT * FROM {} WHERE NOT hash = old_hash'.format(DATA_TABLE_NAME))
        errors = 0
        if not clean:
            print 'MISMATCHES'
            print '-' * 40
        for row in self.curs:
            errors += 1
            if show_hashes:
                print '{} ({} != {})'.format(row[1], row[2], row[3])
            else:
                print row[1]
        if not clean:
            print '-' * 40
            if errors == 1:
                print '1 mismatch found'
            else:
                print '{:d} mismatches found'.format(errors)


    def dump_database(self):
        self.curs.execute('SELECT * FROM {}'.format(DATA_TABLE_NAME))
        for row in self.curs:
            print row


def protect_directory(directory, db):
    # TODO: set onerror to something useful
    files_scanned = 0
    for root, dirlist, filelist in walk(directory, followlinks=True):  # follow symlinks
        for f in filelist:
            # TODO: check for access first? (redundant with onerror above?)
            path = join(root, f)
            print 'hashing {}'.format(path)
            with open(path, 'r') as source:
                s = sha1()
                chunk = source.read(CHUNK_SIZE)
                while chunk != '':
                    s.update(chunk)
                    chunk = source.read(CHUNK_SIZE)
                digest = s.hexdigest()
                print 'storing {}'.format(path)
                db.upsert_file(f, path, digest)
            files_scanned += 1
    return files_scanned

if __name__ == '__main__':
    if len(argv) < 2:
        print 'USAGE: {} PATH/TO/PROTECT/'.format(argv[0])
        exit(1)

    with DB_Manager() as dbm:
        directory = abspath(argv[1])
        print str(protect_directory(directory, dbm)), 'files scanned'
        dbm.dump_database()
        dbm.check_files()
