Debian ``debootstrap``
------------------------

Check ``/usr/share/debootstrap/scripts/`` for supported distribution

>>> debootstrap --components=main,contrib,non-free \
    --merged-usr --variant=minbase bullseye \
    /srv/OS/debian-11.amd64 http://mirrors.bfsu.edu.cn/debian/

>>> debootstrap --arch=arm64 --components=main \
    --merged-usr --variant=minbase sid \
    /srv/OS/debian-sid.arm64 http://opentuna.cn/debian/

>>> debootstrap --components=main,universe,restricted \
    --include=systemd \
    --merged-usr --variant=minbase bionic \
    /srv/OS/ubuntu-18 http://opentuna.cn/ubuntu/

>>> sudo debootstrap --cache-dir=/srv/box/deb.cache/debian-10/ buster /srv/box/ostree/debian-10.$(date +%F) http://mirrors.bfsu.edu.cn/debian/
I: Target architecture can be executed
I: Retrieving InRelease
I: Checking Release signature
I: Valid Release signature (key id 6D33866EDD8FFA41C0143AEDDCC9EFBF77E11517)
I: Retrieving Packages
I: Validating Packages
I: Resolving dependencies of required packages...
I: Resolving dependencies of base packages...
...
I: Retrieving systemd 241-7~deb10u8
I: Validating systemd 241-7~deb10u8
...
I: Chosen extractor for .deb packages: dpkg-deb
I: Extracting libacl1...
...
I: Installing core packages...
I: Unpacking required packages...
...
I: Configuring required packages...
I: Configuring debian-archive-keyring...
...
I: Unpacking the base system...
I: Unpacking apt-utils...
...
I: Configuring systemd...
I: Base system installed successfully.

Necessary Debian package for a system on (amd64) bare metal

bootloader: ``grub-efi`` or ``grub-pc``, none if ``systemd-boot (bootctl)`` is to be used

Kernel tool: ``initramfs-tools``

`LUKS`_ tool: ``cryptsetup``

Debian: ``linux-image-amd64``

Ubuntu: ``linux-image-generic``

Change hostname of the rootfs

>>> vi <rootfs>/etc/hostname

Change root password:

>>> systemd-nspawn -D <rootfs>
>>> chroot <rootfs>

Customize your preferred mirror

>>> rsync debian-11.{bfsu,opentuna}.list \
    <rootfs>/etc/apt/sources.list.d/

Tool for system admin

>>> apt-get --yes install --no-install-recommends bash-completion \
    ca-certificates efibootmgr gnupg htop sudo tree zstd

Tool for network admin

>>> apt-get --yes install --no-install-recommends ncat nftables

Server remote management

>>> apt-get --yes install --no-install-recommends openssh-server

Basic development package

>>> apt-get --yes install --no-install-recommends python3 build-essential

Tool for every day use

>>> apt-get --yes install --no-install-recommends curl file ncdu rsync tmux vim wget

Some regularly used package ``dbus`` ``iproute2`` ``linux-image-amd64`` ``locales`` ``sudo`` ``systemd-sysv`` ``usrmerge``

Nvidia driver and CUDA on Ubuntu 20.04: ``nvidia-headless-470``, ``nvidia-driver-470`` ``nvidia-headless-470-server`` ``nvidia-utils-470-server``

>>> apt install --no-install-recommends linux-headers-generic \
    nvidia-headless-470 nvidia-utils-470
...
The following NEW packages will be installed:
  binutils binutils-common binutils-x86-64-linux-gnu bzip2 cpp cpp-9 dctrl-tools distro-info-data dkms dpkg-dev gcc gcc-9 gcc-9-base libasan5 libatomic1 libbinutils  libcc1-0 libctf-nobfd0 libctf0 libdpkg-perl libgcc-9-dev libgdbm-compat4 libgdbm6 libgomp1 libisl22 libitm1 liblsan0 libmpc3 libmpfr6 libnvidia-cfg1-470 libnvidia-compute-470 libpciaccess0 libperl5.30 libquadmath0 libtsan0 libubsan1 lsb-release make nvidia-compute-utils-470 nvidia-dkms-470 nvidia-headless-470 nvidia-headless-no-dkms-470 nvidia-kernel-common-470 nvidia-kernel-source-470 patch perl perl-modules-5.30 xz-utils
0 upgraded, 48 newly installed, 0 to remove and 0 not upgraded.
Need to get 107 MB of archives.
After this operation, 382 MB of additional disk space will be used.

>>> apt-get --yes install --no-install-recommends linux-headers-generic \
    nvidia-driver-470 nvidia-utils-470
...
0 upgraded, 113 newly installed, 0 to remove and 0 not upgraded.
Need to get 290 MB of archives.
After this operation, 1202 MB of additional disk space will be used.

>>> nvidia-xconfig --query-gpu-info
>>> nvidia-debugdump --list

Cleanup

Remove package repo used by ``debootstrap`` if the system is to be used as a clean image

>>> rm <rootfs>/etc/apt/sources.list

Do NOT install recommended packages

>>> sudo apt-get install --no-install-recommends <foo>

persistent setting ``APT::Install-Recommends``, create a file (for example ``/etc/apt/apt.conf.d/31norecommend``) and add the following content in it ::

    APT::Install-Recommends "0";

>>> printf 'APT::Install-Recommends "0";' \
    | sudo tee /etc/apt/apt.conf.d/31norecommend

Working around DST Root CA X3 Expiration (September 2021)

Move ``/usr/share/ca-certificates/mozilla/DST_Root_CA_X3.crt`` away and then update CA store on your system

>>> sudo mv /usr/share/ca-certificates/mozilla/DST_Root_CA_X3.crt ~/
>>> sudo update-ca-certificates --verbose
Updating certificates in /etc/ssl/certs...
W: /usr/share/ca-certificates/mozilla/DST_Root_CA_X3.crt not found, but listed in /etc/ca-certificates.conf.
...
Importing into legacy system store:
I already trust 126, your new list has 125
1 previously trusted certificates were removed.
Certificate removed: O=Digital Signature Trust Co., CN=DST Root CA X3
...
Importing into BTLS system store:
...
Certificate removed: O=Digital Signature Trust Co., CN=DST Root CA X3
Import process completed.

Or add an ``!`` before ``mozilla/DST_Root_CA_X3.crt`` line in ``/etc/ca-certificates.conf`` and then update CA store on your system

>>> sudo cp -a /etc/ca-certificates.conf{,.orig}
>>> sudo sed -i 's@mozilla/DST_Root_CA_X3@!mozilla/DST_Root_CA_X3@' /etc/ca-certificates.conf
>>> sudo update-ca-certificates
Updating certificates in /etc/ssl/certs...
0 added, 1 removed; done.
...
Removing debian:DST_Root_CA_X3.pem
...

You can also do the above interactively by running

>>> sudo dpkg-reconfigure ca-certificates

Get list of Debian package installed on a system

>>> dpkg --list | sed -e '1,5d' | awk '{print $2}'

Use ``reportbug`` to send a bug report to Debian with email

Considering that most user may not have an email client setup properly to send email from a terminal, I record the following step for a manual bug report with regular web email client like Gmail or Microsoft Outlook.

You can use interactive mode to generate ``~/.reportbugrc``, but below is a file with example content, you should change certain field according to your system environment. ::

    reportbug_version "7.5.3~deb10u1"
    mode standard
    ui text
    email "zcat1@exmaple.net"
    offline
    smtphost "smtp.gmail.com"
    smtptls

With proper setting in the above config file, you can not send bug reports with the following command, replace ``<package>`` with actual package name (on your system). ``reportbug`` will collect informations about the package in question.

>>> reportbug --no-query-bts --quiet --severity=normal --subject=none \
    --tag=none --template --list-cc none <package>

In the following, I use ``dbus`` as an example.

>>> reportbug --no-query-bts --quiet --severity=normal --subject=none \
    --tag=none --template --list-cc none dbus
*** Welcome to reportbug.  Use ? for help at prompts. ***
Note: bug reports are publicly archived (including the email address of the submitter).
Detected character set: UTF-8
...
Using 'Debian <zcat1@exmaple.net>' as your from address.
...
Rewriting subject to 'dbus: none'
Saving a backup of the report at /tmp/reportbug-dbus-backup-20230205115405-eyhjz84p
...

With the above command, you can find the generated bug report template at ``/tmp/reportbug-dbus-backup-...``. Now you can copy the content of the file to your favorite editor and edit it. You should remove the first paragraph of the file, then fill in the steps to reproduce the bug you are encounter by answering the questions in the template ``reportbug`` has just generated for you. ::

   * What led up to the situation?
   * What exactly did you do (or not do) that was effective (or ineffective)?
   * What was the outcome of this action?
   * What outcome did you expect instead?

After that, you can copy the content of the file and paste it to your email client. Then choose a descriptive subject for the bug, and then send the bug report to ``submit@bugs.debian.org`` (as shown in the template).

Enable unattended-upgrades (security upgrade)

>>> sudo apt install unattended-upgrades

Reference
----------
.. _LUKS: https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup

https://wiki.debian.org/UnattendedUpgrades

https://letsencrypt.org/docs/dst-root-ca-x3-expiration-september-2021/

https://wiki.debian.org/Suspend