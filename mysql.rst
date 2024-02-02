>>> brew install mysql@8.0 # install version with long term support

::

 We've installed your MySQL database without a root password. To secure it run:
     mysql_secure_installation
 
 MySQL is configured to only allow connections from localhost by default
 
 To connect run:
     mysql -u root
 
 mysql@8.0 is keg-only, which means it was not symlinked into /usr/local,
 because this is an alternate version of another formula.
 
 If you need to have mysql@8.0 first in your PATH, run:
   echo 'export PATH="/usr/local/opt/mysql@8.0/bin:$PATH"' >> ~/.profile
 
 For compilers to find mysql@8.0 you may need to set:
   export LDFLAGS="-L/usr/local/opt/mysql@8.0/lib"
   export CPPFLAGS="-I/usr/local/opt/mysql@8.0/include"
 
 For pkg-config to find mysql@8.0 you may need to set:
   export PKG_CONFIG_PATH="/usr/local/opt/mysql@8.0/lib/pkgconfig"
 
 To start mysql@8.0 now and restart at login:
   brew services start mysql@8.0
 Or, if you don't want/need a background service you can just run:
   /usr/local/opt/mysql@8.0/bin/mysqld_safe --datadir=/usr/local/var/mysql
 
 if MySQL server startup failed (not listening at default/specified port), check /usr/local/var/mysql/(hostname).local.err log file for reason of failure.One case is that older MySQL server version can not started at datadir from newer version, with error log like "downgrade is not allowed'

``/usr/local/etc/my.cnf`` ::
 
 [mysqld]
 datadir=/Volumes/my/directory/path/

>>> /usr/local/opt/mysql@8.0/bin/mysqld --initialize-insecure --user=meow --basedir=/usr/local/opt/mysql@8.0 --datadir="$HOME/project/database/mysql/db0" --tmpdir=/tmp
2024-01-19T06:36:25.088375Z 0 [System] [MY-013169] [Server] /usr/local/opt/mysql@8.0/bin/mysqld (mysqld 8.0.34) initializing of server in progress as process 6613
2024-01-19T06:36:25.093418Z 0 [Warning] [MY-010159] [Server] Setting lower_case_table_names=2 because file system for .../project/database/mysql/db0/ is case insensitive
2024-01-19T06:36:25.101935Z 1 [System] [MY-013576] [InnoDB] InnoDB initialization has started.
2024-01-19T06:36:25.674080Z 1 [System] [MY-013577] [InnoDB] InnoDB initialization has ended.
2024-01-19T06:36:26.779805Z 6 [Warning] [MY-010453] [Server] root@localhost is created with an empty password ! Please consider switching off the --initialize-insecure option.
2024-01-19T06:36:27.826397Z 0 [System] [MY-013172] [Server] Received SHUTDOWN from user <via user signal>. Shutting down mysqld (Version: 8.0.34).

>>> /usr/local/mysql/bin/mysqld_safe --datadir="$HOME/project/database/mysql/db0 --user=mysql

>>> mysqladmin --user=root --password shutdown

>>> mysqladmin -u root shutdown # if no password for root (eg. on localhost)

>>> mycli --host=<hostname.or.ip> --port=3306 --user=root

>>> mycli --user=root # if no password for root (eg. on localhost)

>>> status;
--------------
mycli 1.27.0, running on CPython 3.12.0
.
+----------------------+---------------------------+
| Connection id:       | 8                         |
| Current database:    |                           |
| Current user:        | root@localhost            |
| Current pager:       | less                      |
| Server version:      | 8.0.34 Homebrew           |
| Protocol version:    | 10                        |
| Connection:          | Localhost via UNIX socket |
| Server characterset: | utf8mb4                   |
| Db characterset:     | utf8mb4                   |
| Client characterset: | utf8mb3                   |
| Conn. characterset:  | utf8mb3                   |
| UNIX socket:         | /tmp/mysql.sock           |
| Uptime:              | 15 sec                    |
+----------------------+---------------------------+.
Connections: 1  Queries: 12  Slow queries: 0  Opens: 159  Flush tables: 3  Open tables: 80  Queries per second avg: 0.800
--------------
Time: 0.064s

>>> mysql --user=root --execute="select version();" # from operating system (OS) command line REPL

>>> select version(); # in MySQL client REPL (same output as above)
+-----------+
| version() |
+-----------+
| 8.0.34    |
+-----------+
.
1 row in set
Time: 0.011s

>>> mysql --user=root --execute="show variables like '%version%';" # from operating system (OS) command line REPL
>>> show variables like '%version%'; # in MySQL client REPL (same output as above)
+--------------------------+-----------------+
| Variable_name            | Value           |
+--------------------------+-----------------+
| admin_tls_version        | TLSv1.2,TLSv1.3 |
| immediate_server_version | 999999          |
| innodb_version           | 8.0.34          |
| original_server_version  | 999999          |
| protocol_version         | 10              |
| replica_type_conversions |                 |
| slave_type_conversions   |                 |
| tls_version              | TLSv1.2,TLSv1.3 |
| version                  | 8.0.34          |
| version_comment          | Homebrew        |
| version_compile_machine  | x86_64          |
| version_compile_os       | macos11.7       |
| version_compile_zlib     | 1.2.13          |
+--------------------------+-----------------+
.
13 rows in set
Time: 0.056s

>>> mysql --host=hostname --user=user --password --execute="show variables like '%version%';"
Enter password:
+-------------------------+------------------------------+
| Variable_name           | Value                        |
+-------------------------+------------------------------+
.
| version_compile_os      | Linux                        |
+-------------------------+------------------------------+

>>> mysql --user=root --execute="select version();" --xml
<?xml version="1.0"?>
.
<resultset statement="select version()" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <row>
        <field name="version()">8.0.34</field>
  </row>
</resultset>

Grouping Rows with GROUP BY, 2009, https://www.sqlsnippets.com/en/topic-13100.html
Using GROUP BY with ROLLUP, CUBE, and GROUPING SETS, 2012, http://msdn.microsoft.com/en-us/library/bb522495.aspx
2012 https://learn.microsoft.com/en-us/previous-versions/sql/sql-server-2008-r2/bb522495(v=sql.105)

Exporting MySQL query result to spreadsheet
================================================

2012, https://stackoverflow.com/questions/10295228/exporting-results-of-a-mysql-query-to-excel

Server side data export

>>> SELECT ... FROM someTable WHERE etc
	INTO OUTFILE 'someTableExport.csv' CHARACTER SET utf8mb4
	FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"' ESCAPED BY ''
	LINES TERMINATED BY '\r\n'; -- use absolute file path to export other directory than MySQL 'datadir';

The following didn't work, tested on 2024-01-31

`0x22`: `"`, `0x2c`: `,` `0x0d`: `\r`, `0x0a`: `\n`
>>> mysqldump --host=serverHostName --user=mysqlUserName --password --tab="/tmp/" --fields-escaped-by='' --fields-optionally-enclosed-by=0x22 --fields-terminated-by=0x2C --lines-terminated-by=0x0D0A --databases databaseName --tables table1 table2 table3
Warning: A partial dump from a server that has GTIDs will by default include the GTIDs of all transactions, even those that changed suppressed parts of the database. If you don't want to restore GTIDs, pass --set-gtid-purged=OFF. To make a complete dump, pass --all-databases --triggers --routines --events.
Warning: A dump from a server that has GTIDs enabled will by default include the GTIDs of all transactions, even those that were executed during its extraction and might not be represented in the dumped data. This might result in an inconsistent data dump.
In order to ensure a consistent backup of the database, pass --single-transaction or --lock-all-tables or --master-data.
SET @MYSQLDUMP_TEMP_LOG_BIN = @@SESSION.SQL_LOG_BIN;
SET @@SESSION.SQL_LOG_BIN= 0;
.
SET @@GLOBAL.GTID_PURGED=/*!80000 '+'*/ '9d3a57ce-8cf5-11ee-a60b-0cda411d6d09:1-267700,
e0e14eb8-9d4d-11ee-b011-0050569969e3:1-12632629';
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1290: The MySQL server is running with the --secure-file-priv option so it cannot execute this statement when executing 'SELECT INTO OUTFILE'

Client side data export

>>> mysql --host=hostname --user=user --password --execute="show variables like '%version%';" --xml > mysql.server.version.info.xml

>>> mysql --host=hostname --user=user --password < my.query.sql > query.result.txt

>>> mysqlsh --user="mysqlUserName" --host="serverHostName" --port=3306 --schema="databaseName"
# Once connected, run this:
util.exportTable("tableName", "file:///C:/Users/You/Desktop/test.csv", { dialect: "csv", fieldsEscapedBy: ""})

>>> select table_name, table_rows, table_comment from information_schema.tables
	where table_schema = 'db_name' into outfile 'sink.test/db_name.meta.csv'
	CHARACTER SET utf8mb4 FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"'
	ESCAPED BY '' LINES TERMINATED BY '\r\n';
(1290, 'The MySQL server is running with the --secure-file-priv option so it cannot execute this statement')

>>> mysqladmin --user=root ping
mysqld is alive
>>> mysqladmin --user=root processlist
+----+-----------------+-----------+----+---------+------+------------------------+------------------+
| Id | User            | Host      | db | Command | Time | State                  | Info             |
+----+-----------------+-----------+----+---------+------+------------------------+------------------+
| 5  | event_scheduler | localhost |    | Daemon  | 5305 | Waiting on empty queue |                  |
| 17 | root            | localhost |    | Query   | 0    | init                   | show processlist |
+----+-----------------+-----------+----+---------+------+------------------------+------------------+

>>> mysqladmin --user=root status
Uptime: 5398  Threads: 2  Questions: 37  Slow queries: 0  Opens: 176  Flush tables: 3  Open tables: 97  Queries per second avg: 0.006

>>> mysqladmin --user=root version
mysqladmin  Ver 8.0.34 for macos11.7 on x86_64 (Homebrew)
Copyright (c) 2000, 2023, Oracle and/or its affiliates.
.
Server version          8.0.34
Protocol version        10
Connection              Localhost via UNIX socket
UNIX socket             /tmp/mysql.sock
Uptime:                 1 hour 30 min 52 sec
.
Threads: 2  Questions: 39  Slow queries: 0  Opens: 176  Flush tables: 3  Open tables: 97  Queries per second avg: 0.007

Reference
------------

Reset MySQL Root Password in Mac OS, 2024, https://gist.github.com/zubaer-ahammed/c81c9a0e37adc1cb9a6cdc61c4190f52

2010, https://stackoverflow.com/questions/3938966/how-can-i-access-the-table-comment-from-a-mysql-table

https://dev.mysql.com/doc/mysql-infoschema-excerpt/8.0/en/information-schema-tables-table.html

Oracle Lifetime Support policy, https://www.oracle.com/support/lifetime-support/

10.10.1 Unicode Character Sets, https://dev.mysql.com/doc/refman/8.0/en/charset-unicode-sets.html

11.3.2 The CHAR and VARCHAR Types, https://dev.mysql.com/doc/refman/8.0/en/char.html

Limits on Table Column Count and Row Size, https://dev.mysql.com/doc/refman/8.0/en/column-count-limit.html

11.6 Data Type Default Values, https://dev.mysql.com/doc/refman/8.0/en/data-type-defaults.html

import data to MySQL database, https://dev.mysql.com/doc/refman/8.0/en/load-data.html

Chapter 15 https://dev.mysql.com/doc/refman/8.0/en/innodb-storage-engine.html

https://mariadb.com/kb/en/aria-storage-engine/

