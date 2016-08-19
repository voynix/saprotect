import argparse
import sqlite3

from hashlib import sha1
from os import walk
from os.path import abspath, basename, exists, expanduser, isdir, join
from time import asctime, localtime, time

DATABASE_FILE_PATH = expanduser('~/.prot.sql')

DATA_TABLE_NAME = 'files'
METADATA_TABLE_NAME = 'metadata'

STATUS_OK = 0
STATUS_MISMATCH = 1
STATUS_REMEDIATE_NEW = 2
STATUS_REMEDIATE_OLD = 3
STATUS_NEW = 4

CHUNK_SIZE = 4096

VERSION = '1.4.0'
HASH = 'SHA-1'

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


    def connect_to_db(self, db=DATABASE_FILE_PATH):
        try:
            self.conn = sqlite3.connect(db)
        except:
            print u'Could not connect to database {}'.format(db)
            print 'Exiting'
            exit(1)
        self.curs = self.conn.cursor()


    def disconnect_from_db(self):
        self.conn.commit()
        self.conn.close()


    def create_tables(self):
        command = '''CREATE TABLE IF NOT EXISTS {}
                    (filename TEXT, path TEXT, hash TEXT, old_hash TEXT,
                    time TEXT, old_time TEXT, status INTEGER)'''.format(DATA_TABLE_NAME)
        self.curs.execute(command)
        self.curs.execute('''CREATE TABLE IF NOT EXISTS {}
                        (start TEXT, end TEXT, files_scanned INTEGER, files_added INTEGER,
                         files_updated INTEGER, files_mismatched INTEGER)'''.format(METADATA_TABLE_NAME))
        self.conn.commit()


    def upsert_file(self, filename, path, hash):
        command = u'SELECT * FROM {} WHERE path = ?'.format(DATA_TABLE_NAME)
        self.curs.execute(command, (path,))
        row = self.curs.fetchone()
        if row is None:
            self.curs.execute(u'''INSERT INTO {}(filename, path, hash, time, status)
                                 VALUES (?, ?, ?, ?, ?)'''.format(DATA_TABLE_NAME),
                              (filename, path, hash, time(), STATUS_NEW))
        elif row[6] != STATUS_MISMATCH:  # note: only update if status is not mismatch
            if row[6] == STATUS_REMEDIATE_OLD:
                old_hash = row[3]
                status = STATUS_OK if old_hash == hash else STATUS_MISMATCH
                self.curs.execute(u'''UPDATE {} SET hash = ?, time = ?, status = ?
                                     WHERE path = ?'''.format(DATA_TABLE_NAME), (hash, time, status, path))
            else:
                old_hash = row[2]
                status = STATUS_OK if old_hash == hash else STATUS_MISMATCH
                self.curs.execute(u'''UPDATE {} SET hash = ?, time = ?, old_hash = hash, old_time = time, status = ?
                                     WHERE path = ?'''.format(DATA_TABLE_NAME), (hash, time(), status, path))
        self.conn.commit()


    def remediate(self, path, status):
        if exists(path):
            if isdir(path):
                for root, dirlist, filelist in walk(path, followlinks=True):
                    for f in filelist:
                        path = join(root, f)
                        self.curs.execute(u'''SELECT status FROM {} WHERE path = ?'''.format(DATA_TABLE_NAME), (path,))
                        row = self.curs.fetchone()
                        if row is not None and row[0] == STATUS_MISMATCH:
                            self.curs.execute(u'''UPDATE {} SET status = ? WHERE path = ?'''.format(DATA_TABLE_NAME),
                                              (status, path))
                            self.conn.commit()
                        else:
                            print u'{} has no mismatch; skipping'.format(path)
            else:
                self.curs.execute(u'''SELECT status FROM {} WHERE path = ?'''.format(DATA_TABLE_NAME), (path,))
                row = self.curs.fetchone()
                if row is not None and row[0] == STATUS_MISMATCH:
                    self.curs.execute(u'''UPDATE {} SET status = ? WHERE path = ?'''.format(DATA_TABLE_NAME),
                                      (status, path))
                    self.conn.commit()
                else:
                    print u'{} has no mismatch; skipping'.format(path)


    def get_mismatches(self, show_hashes=False, clean=False):
        self.curs.execute('SELECT * FROM {} WHERE status = {:d}'.format(DATA_TABLE_NAME, STATUS_MISMATCH))
        errors = 0
        if not clean:
            print 'MISMATCHES'
            print_sep()
        for row in self.curs:
            errors += 1
            if show_hashes:
                print u'{} ({} != {})'.format(row[1], row[2], row[3])
            else:
                print row[1]
        if not clean:
            print_sep()
            print '{:d} {} found'.format(errors, 'mismatch' if errors == 1 else 'mismatches')
        return errors


    def get_info(self, clean=False):
        self.curs.execute('SELECT * FROM {} ORDER BY start DESC'.format(METADATA_TABLE_NAME))
        (start, end, scanned, added, updated, mismatched) = self.curs.fetchone()
        if not clean:
            print 'LAST SCAN {} {}'.format(asctime(localtime(float(start))), asctime(localtime(float(end))))
            print_sep()
        print '{:d} file{} added'.format(added, 's' if added != 1 else '')
        print '{:d} file{} updated'.format(updated, 's' if updated != 1 else '')
        print '{:d} file{} with hash mismatches'.format(mismatched, 's' if mismatched != 1 else '')
        if not clean:
            print_sep()
            print '{:d} total file{} scanned'.format(scanned, 's' if scanned != 1 else '')


    def show_duplicates(self, filename, clean=False):
        self.curs.execute(u'''SELECT path, hash FROM {} where filename = ?'''.format(DATA_TABLE_NAME), (filename,))
        if not clean:
            print filename
            print_sep()
        for row in self.curs:
            print row[0], row[1]
        if not clean:
            print_sep()


    def check_presence(self, path):
        self.curs.execute(u'''SELECT * FROM {} WHERE path = ?'''.format(DATA_TABLE_NAME), (path,))
        return self.curs.fetchone() is not None


    def add_record(self, start_time, end_time, scanned):
        self.curs.execute('SELECT COUNT(*) FROM {} WHERE status = {:d} AND time > {:f}'.format(DATA_TABLE_NAME,
                                                                                               STATUS_NEW, start_time))
        added = self.curs.fetchone()[0]
        self.curs.execute('SELECT COUNT(*) FROM {} WHERE NOT status = {:d} AND time > {:f}'.format(DATA_TABLE_NAME,
                                                                                                   STATUS_NEW, start_time))
        updated = self.curs.fetchone()[0]
        self.curs.execute('SELECT COUNT(*) FROM {} WHERE status = {:d}'.format(DATA_TABLE_NAME, STATUS_MISMATCH))
        mismatched = self.curs.fetchone()[0]
        self.curs.execute('''INSERT INTO {} VALUES (?, ?, ?, ?, ?, ?)'''.format(METADATA_TABLE_NAME),
                          (start_time, end_time, scanned, added, updated, mismatched))
        self.conn.commit()


    def get_num_mismatches(self):
        self.curs.execute('''SELECT COUNT(*) FROM {} WHERE status = {:d}'''.format(DATA_TABLE_NAME, STATUS_MISMATCH))
        return self.curs.fetchone()[0]


    def dump_database(self):
        self.curs.execute('SELECT * FROM {}'.format(DATA_TABLE_NAME))
        for row in self.curs:
            print row


def protect_directory(directory, db, add_only=False):
    files_scanned = 0
    for root, dirlist, filelist in walk(directory, followlinks=True):  # follow symlinks
        for f in filelist:
            files_scanned += 1
            path = join(root, f)
            if add_only and db.check_presence(path):
                print u'skipping {}'.format(path)
                continue
            print u'hashing {}'.format(path)
            with open(path, 'r') as source:
                s = sha1()
                chunk = source.read(CHUNK_SIZE)
                while chunk != '':
                    s.update(chunk)
                    chunk = source.read(CHUNK_SIZE)
                digest = s.hexdigest()
                print u'storing {}'.format(path)
                db.upsert_file(f, path, digest)
    return files_scanned


def protect_file(path, db, add_only=False):
    f = basename(path)
    if add_only and db.check_presence(path):
        print u'skipping {}'.format(path)
        return
    print u'hashing {}'. format(path)
    with open(path, 'r') as source:
        s = sha1()
        chunk = source.read(CHUNK_SIZE)
        while chunk != '':
            s.update(chunk)
            chunk = source.read(CHUNK_SIZE)
        digest = s.hexdigest()
        print u'storing {}'.format(path)
        db.upsert_file(f, path, digest)


def print_sep():
    print '-' * 40


if __name__ == '__main__':
    # TODO: for mismatches, find duplicates across folders?
    parser = argparse.ArgumentParser(description='Record file hashes and check on changes')
    parser.add_argument('-v', '--version', version='saprotect {} using {}'.format(VERSION, HASH), action='version',
                        help='show version information')
    parser.add_argument('-a', '--add-only', action='store_true',
                        help='when given with -p, only record files not already present in the database; '
                             '\does nothing otherwise')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-p', '--protect', metavar='TARGET', nargs='+',
                        help='record the hashes of the TARGETs and print any mismatches found')
    group.add_argument('-r', '--remediate-old', metavar='TARGET', nargs='+',
                        help='resolve hash mismatches on the TARGETs in favor of the old hash')
    group.add_argument('-R', '--remediate-new', metavar='TARGET', nargs='+',
                        help='resolve hash mismatches on the TARGETs in favor of the new hash')
    group.add_argument('-d', '--show_duplicates', metavar='FILE',
                       help='show hashes for all files with name FILE in the database')
    group.add_argument('-m', '--list-mismatches', action='store_true', help='show files with mismatched hashes')
    arguments = parser.parse_args()

    with DB_Manager() as dbm:
        if arguments.protect is not None:
            if dbm.get_num_mismatches() > 0:
                print 'ERROR: Remediate mismatches below first!'
                dbm.get_mismatches()
                exit(0)
            files_scanned = 0
            start_time = time()
            for target in arguments.protect:
                target = abspath(unicode(target))
                if exists(target):
                    if isdir(target):
                        files_scanned += protect_directory(target, dbm, arguments.add_only)
                    else:
                        protect_file(target, dbm, arguments.add_only)
                        files_scanned += 1
            end_time = time()
            dbm.add_record(start_time, end_time, files_scanned)
        elif arguments.remediate_old is not None:
            for target in arguments.remediate_old:
                target = abspath(unicode(target))
                if exists(target):
                    dbm.remediate(target, STATUS_REMEDIATE_OLD)
        elif arguments.remediate_new is not None:
            for target in arguments.remediate_new:
                target = abspath(unicode(target))
                if exists(target):
                    dbm.remediate(target, STATUS_REMEDIATE_NEW)
        elif arguments.list_mismatches:
            dbm.get_mismatches(True)
        elif arguments.show_duplicates is not None:
            dbm.show_duplicates(unicode(arguments.show_duplicates))
        else:
            dbm.get_info()
