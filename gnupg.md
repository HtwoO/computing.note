Rotate keys

>>> gpg --edit-key <key-id>
gpg (GnuPG) 2.2.27; Copyright (C) 2021 Free Software Foundation, Inc.
...
sec  rsa2048/<sub-key-id>
     created: 2019-04-03  expired: 2022-04-06  usage: SC
     trust: unknown       validity: expired
ssb  rsa2048/<sub-key-id>
     created: 2019-04-03  expired: 2022-04-06  usage: E
[ expired] (1). Example Debian Team <deb-team@example.net>

Inside GnuPG interactive session:

gpg> expire
Changing expiration time for the primary key.
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Thu 06 Apr 2023 11:55:08 AM HKT
Is this correct? (y/N) y
sec  rsa2048/<sub-key-id>
     created: 2019-04-03  expired: 2023-04-06  usage: SC
     trust: unknown       validity: expired
ssb  rsa2048/<sub-key-id>
     created: 2019-04-03  expired: 2022-04-06  usage: E
[ expired] (1). Example Debian Team <deb-team@example.net>

gpg> key 1
sec  rsa2048/<sub-key-id>
     created: 2019-04-03  expired: 2023-04-06  usage: SC
     trust: unknown       validity: expired
ssb* rsa2048/<sub-key-id>
     created: 2019-04-03  expired: 2022-04-06  usage: E
[ expired] (1). Example Debian Team <deb-team@example.net>

gpg> expire
Changing expiration time for a subkey.
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Thu 06 Apr 2023 11:59:48 AM HKT
Is this correct? (y/N) y
sec  rsa2048/<sub-key-id>
     created: 2019-04-03  expired: 2023-04-06  usage: SC
     trust: unknown       validity: expired
ssb* rsa2048/<sub-key-id>
     created: 2019-04-03  expired: 2023-04-06  usage: E
[ expired] (1). Example Debian Team <deb-team@example.net>

gpg> save
