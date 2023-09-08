>>> sqlite3 -version
3.32.3 2020-06-18 14:16:19 02c344aceaea0d177dd42e62c8541e3cab4a26c757ba33b3a31a43ccc7d4aapl

>>> sqlite3 -help
Usage: sqlite3 [OPTIONS] FILENAME [SQL]
FILENAME is the name of an SQLite database. A new database is created
if the file does not previously exist.
OPTIONS include:
   -append              append the database to the end of the file
   ...
   -vfs NAME            use NAME as the default VFS

>>> man sqlite3     # read SQLite manpage in terminal

>>> sqlite3 mydata.db
SQLite version 3.32.3 2020-06-18 14:16:19
Enter ".help" for usage hints.
sqlite> .help

In SQLite Read-Eval-Print-Loop (REPL)

>>> .databases
main: .../mydata.db

>>> .fullschema
CREATE TABLE IF NOT EXISTS "User" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "email" TEXT NOT NULL,
    "name" TEXT
);
.
/* No STAT tables available */

>>> .tables
Post    User    _prisma_migrations

>>> SELECT * from User;
1|alice@example.net|Alice
.
3|eve@example.net|Eve

>>> .quit

Back to operating system shell, trun on human friendly ``column`` output mode, and enable header output by default.

>>> sqlite3 -column -header mydata.db

in SQLite REPL

>>> SELECT * from User;
id          email              name
----------  -----------------  ----------
1           alice@example.net  Alice
.
3           eve@example.net    Eve