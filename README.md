# saprotect

## An Inquiry
### What?
**saprotect** checks your files for bit-rot so you can take appropriate action to preserve your data
### Why?
Your data are probably important and bit-rot is bad
### Where?
Your nearest Python 2 interpreter (ok, **saprotect** is only tested on OS X and Linux, so it may not work on Windows; if you try it there, let me know how it goes)
### How?
**saprotect** hashes your files and stores the hashes in a database. Everytime you tell it to recheck your files it rehashes them; if the new hashes doesn't match the old hash an alert is raised
## The Details
**saprotect** stores its hashes in a SQLite database called `.prot.sql` in your home directory (`~/.prot.sql`). This file will almost certainly not be large enough to cause you any troubles. (eg, during testing, after protecting >2K files the database was ~750KB in size)
### General Commands
* To see some statistics about the last protection run and the state of the database: `python saprotect.py`
* To add or check files or folders: `python saprotect.py -p <FILES> <FOLDERS>`
* To only add files not already in the database: `python saprotect.py -a -p <FILES> <FOLDERS>`
* To see help: `python saprotect.py -h`

### Remediation
When hash mismatches are detect you will need to tell **saprotect** how to remediate the issue.

* To declare the old hash of files or folders correct (eg, when the bit-rot has occured and a file has become corrupted): `python saprotect.py -r <FILES> <FOLDERS>`
* To declare the new hash of files or folders correct (eg, when you have deliberately changed a file and its new contents are correct): `python saprotect.py -R <FILES> <FOLDERS>`

Note that if you use `-r` you are responsible for restoring the old contents of the file. **saprotect** takes a strict read-only stance with respect to your files and will not make any changes for you

## License
Released under a MIT license