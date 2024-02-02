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

>>> select * from User;
1|alice@example.net|Alice
.
3|eve@example.net|Eve

>>> .quit

Back to operating system shell, trun on human friendly ``column`` output mode, and enable header output by default.

>>> sqlite3 -column -header mydata.db

in SQLite REPL

>>> select * from User;
id          email              name
----------  -----------------  ----------
1           alice@example.net  Alice
.
3           eve@example.net    Eve

>>> select typeof(value) from json_each('{"a": {"pi": 3.142}}');
text

>>> select typeof(value) from json_tree('{"a": {"e": 2.718}}');
text
text
real

Import data from CSV file
--------------------------------

In SQLite REPL
>>> create table foo(a, b);
>>> .mode csv
>>> .import test.csv foo

if the first line of your csv file contains the column names, then you can omit the first create table command and sqlite will use the column names from the csv file
SQLite> .import test.csv foo --csv

From CLI
>>> sqlite3 -header -csv input.db "select * from table_name;" > table_name.csv
>>> sqlite3 -header -csv input.db < query.sql > data.csv

You can use LiteCLI for a much better terminal experience when using SQLite.

Reference
------------

2013, https://stackoverflow.com/questions/14947916/import-csv-to-sqlite
