``Linux``
----------
Install PostgreSQL with your distribution's package managing tool.

Default data path should be at ``/var/lib/postgres/``

``macOS``
----------

Start PostgreSQL with specified data path (default at /usr/local/var/postgres/ )

>>> pg_ctl --pgdata="$HOME/project/pgsql/play/mydb/data" start
waiting for server to start....2023-07-18 16:25:58.892 CST [99466] LOG:  starting PostgreSQL 14.8 (Homebrew) on x86_64-apple-darwin20.6.0, compiled by Apple clang version 13.0.0 (clang-1300.0.29.30), 64-bit
2023-07-18 16:25:58.896 CST [99466] LOG:  listening on IPv6 address "::1", port 5432
2023-07-18 16:25:58.896 CST [99466] LOG:  listening on IPv4 address "127.0.0.1", port 5432
2023-07-18 16:25:58.897 CST [99466] LOG:  listening on Unix socket "/tmp/.s.PGSQL.5432"
2023-07-18 16:25:58.910 CST [99507] LOG:  database system was shut down at 2023-03-26 23:18:06 CST
2023-07-18 16:25:58.931 CST [99466] LOG:  database system is ready to accept connections

>>> lsof -nP -iTCP:5432 -sTCP:LISTEN
COMMAND    PID  USER        FD   TYPE             DEVICE SIZE/OFF NODE NAME
postgres 19121  username    7u  IPv6 0xc0ed9f98f8ad7859      0t0  TCP [::1]:5432 (LISTEN)
postgres 19121  username    8u  IPv4 0xc0ed9f98f0d1d561      0t0  TCP 127.0.0.1:5432 (LISTEN)

Start a PostgreSQL CLI client and manage database "postgres"

>>> psql postgres

>>> export DB_URI="postgresql://<role>:<password>@localhost:5432/<name.of.database>"

>>> psql "$DB_URI"

Find out running database instance data path

>>> SHOW data_directory;
                data_directory
----------------------------------------------
 .../project/pgsql/slowstart/mydb/data

Stop the PostgreSQL server

>>> pg_ctl -D /usr/local/var/postgres stop

For GUI app, use https://postgresapp.com

Graph (web UI) admin app https://www.pgadmin.org

Custom database directory:

>>> initdb mydb/data
The files belonging to this database system will be owned by user "...".
.
The database cluster will be initialized with locale "zh_CN.UTF-8"
.
creating directory mydb/data ... ok
.
syncing data to disk ... ok
.
Success. You can now start the database server using:
.
    pg_ctl -D mydb/data -l logfile start

>>> pg_ctl --pgdata=mydb/data --log=mydb/mydb.log start
waiting for server to start.... done
server started

>>> pg_ctl --pgdata=mydb/data --log=mydb/mydb.log stop
waiting for server to shut down.... done
server stopped

Run as daemon service
------------------------

manually

>>> ln -sf /usr/local/opt/postgresql/*.plist ~/Library/LaunchAgents

>>> launchctl load ~/Library/LaunchAgents/homebrew.mxcl.postgresql.plist

through Homebrew

>>> brew services list

>>> brew services start postgresql@14

>>> brew services stop postgresql@14

>>> psql posgres
psql (14.8 (Homebrew))
...
postgres=#

The ``user`` below in the database is an actual user (both on the OS, and in the database).

>>> \?
General
  \copyright             show PostgreSQL usage and distribution terms
...
  \lo_unlink LOBOID      large object operations

>>> \list
                         List of databases
   Name    | Owner | Encoding | Collate | Ctype | Access privileges
-----------+-------+----------+---------+-------+-------------------
 postgres  | user  | UTF8     | C       | C     |
...

>>> \dS
                      List of relations
   Schema   |              Name               | Type  | Owner
------------+---------------------------------+-------+-------
 pg_catalog | pg_aggregate                    | table | user
 ...
 pg_catalog | pg_roles                        | view  | user
 ...
 pg_catalog | pg_user                         | view  | user
 ...
 pg_catalog | pg_views                        | view  | user
(134 rows)

For each relation (table, view, materialized view, index, sequence, or foreign table) or composite type matching the pattern, show all columns, their types, the tablespace (if not the default) and any special attributes such as NOT NULL or defaults. Associated indexes, constraints, rules, and triggers are also shown. For foreign tables, the associated foreign server is shown as well. (“Matching the pattern” is defined in Patterns below.) 

>>> \dS+
                                      List of relations
   Schema   |     Name     | Type  | Owner | Persistence | Access method |    Size    | Description
------------+--------------+-------+-------+-------------+---------------+------------+-------------
 pg_catalog | pg_aggregate | table | user  | permanent   | heap          | 56 kB      |
 pg_catalog | pg_am        | table | user  | permanent   | heap          | 40 kB      |
 pg_catalog | pg_amop      | table | user  | permanent   | heap          | 88 kB      |
 ...
 pg_catalog | pg_proc      | table | user  | permanent   | heap          | 840 kB     |
 ...
 pg_catalog | pg_statistic | table | user  | permanent   | heap          | 256 kB     |
 ...
 pg_catalog | pg_user      | view  | user  | permanent   |               | 0 bytes    |
 ...
 pg_catalog | pg_views     | view  | user  | permanent   |               | 0 bytes    |
(134 rows)

>>> SELECT rolname FROM pg_roles;

>>> select * from pg_roles;
          rolname          | ...| rolconnlimit | rolpassword ...| rolconfig | oid
---------------------------+-...|           -1 | ********    ...|           |   10
 pg_database_owner         | ...|           -1 | ********    ...|           | 6171
 pg_read_all_data          | ...|           -1 | ********    ...|           | 6181
 pg_write_all_data         | ...|           -1 | ********    ...|           | 6182
 pg_monitor                | ...|           -1 | ********    ...|           | 3373
 pg_read_all_settings      | ...|           -1 | ********    ...|           | 3374
 pg_read_all_stats         | ...|           -1 | ********    ...|           | 3375
 pg_stat_scan_tables       | ...|           -1 | ********    ...|           | 3377
 pg_read_server_files      | ...|           -1 | ********    ...|           | 4569
 pg_write_server_files     | ...|           -1 | ********    ...|           | 4570
 pg_execute_server_program | ...|           -1 | ********    ...|           | 4571
 pg_signal_backend         | ...|           -1 | ********    ...|           | 4200
(12 rows)

>>> select * from pg_user;
 usename | usesysid |...|  passwd  | valuntil | useconfig
---------+----------+...+----------+----------+-----------
 user    |       10 |...| ******** |          |
(1 row)

>>> postgres=# \dnS
      List of schemas
        Name        | Owner
--------------------+-------
 information_schema | user
 pg_catalog         | user
 pg_toast           | user
 public             | user
(4 rows)

>>> \doS+
...
(804 rows)

>>> \dTS
                  List of data types
   Schema   |  Name   |            Description
------------+---------+-----------------------------------
 pg_catalog | "any"   | pseudo-type representing any type
 pg_catalog | "char"  | single character
 pg_catalog | aclitem | access control list
 ...
 pg_catalog | xml     | XML content
(107 rows)

>>> \du
                              List of roles
 Role name |                         Attributes                         | Member of 
-----------+------------------------------------------------------------+-----------
 user      | Superuser, Create role, Create DB, Replication, Bypass RLS | {}

>>> \duS
                      List of roles
         Role name         |   Attributes |  Member of
---------------------------+--------------+-------------
 user                      | Superuser,...| {}
 pg_database_owner         | Cannot login | {}
 pg_execute_server_program | Cannot login | {}
 pg_monitor                | Cannot login | {pg_read...
 ...
 pg_write_server_files     | Cannot login | {}

>>> pg_ctl --pgdata=mydb/data stop


Reference
----------
Latest `psql`_ document

.. _psql: https://www.postgresql.org/docs/current/app-psql.html

https://jsdw.me/posts/postgres/