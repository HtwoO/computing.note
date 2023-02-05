System administration tip and trick
####################################

Hardware management
--------------------

Windows

Hard drive (to be filled when I be on a Windows machine)

>>>

General computing environment
--------------------------------

Keyboard shortcut
==================

``Linux``

dump current X11 keyboard mapping to a file?

>>> xmodmap -pke > ~/.config/xmodmap.$(date +%m%d.%H%M)

``macOS``

Use readline's ``Alt+b`` and ``Alt+f`` shortcut for word jump in the terminal in Visual Studio Code (Codium) on macOS

Search for ``meta`` in VS Code's preferences, and enable the checkbox under ``Terminal › Integrated: Mac Option Is Meta``

``Windows``

>>> systeminfo

Equivalent of ``uptime`` on Linux

>>> (get-date) - (gcim Win32_OperatingSystem).LastBootUpTime

Get running PowerShell version

>>> $PSVersionTable.PSVersion
Major  Minor  Build  Revision
-----  -----  -----  --------
5      1      17763  2268

>>> $PSVersionTable
Name                           Value
----                           -----
PSVersion                      5.1.17763.2268
PSEdition                      Desktop
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
BuildVersion                   10.0.17763.2268
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1

Query system time setting

>>> w32tm /query /configuration

On Windows server 2019

>>> Get-PSRepository
Name                      InstallationPolicy   SourceLocation
----                      ------------------   --------------
PSGallery                 Untrusted            https://www.powershellgallery.com/api/v2

>>> Get-PackageProvider -ListAvailable

>>> [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
>>> Enable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" -Position 0

>>> Register-PSRepository -Default -Verbose

Show system-wide proxy settings in ``cmd.exe``

>>> netsh winhttp show proxy

>>> netsh winhttp set proxy proxy.example.net:8080

Show user-specific proxy settings from ``cmd.exe``:

>>> reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

Get user-specific proxy settings in PowerShell

>>> Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

Add ``-UseBasicParsing`` to prevent ``Internet Explorer`` popup window

>>> Invoke-WebRequest http://z.cn -UseBasicParsing

Proxy setting in PowerShell and check proxying status for a URL

>>> [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy('http://[user:pass@]proxy.example.net:port')
>>> [System.Net.WebRequest]::DefaultWebProxy = $null
>>> [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($null)
>>> ([System.Net.WebRequest]::GetSystemWebproxy()).GetProxy("https://google.com")
>>> ([System.Net.WebRequest]::GetSystemWebproxy()).IsBypassed("https://google.com")

Power management
-------------------

Disable suspend and hibernation on Linux

>>> sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

Revert above change

>>> sudo systemctl unmask sleep.target suspend.target hibernate.target hybrid-sleep.target

On Windows

Reboot computer

>>> shutdown /r /t 0

List existing power scheme

>>> powercfg -l
Existing Power Schemes (* Active)
-----------------------------------
Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced) *
Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)
Power Scheme GUID: a1841308-3541-4fab-bc81-f71556f20b4a  (Power saver)

Set power scheme (used when no one is logged in)

>>> powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e

Set power configuration to "High Performance"

>>> powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

Turn hibernation off

>>> powercfg -hibernate OFF

Service management
-------------------

List running service on Windows

>>> net start

Add remote Windows shared data

>>> net use \\fs1.example.net
System error 1272 has occurred.
.
You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.

>>> net use \\fs1.example.net /user:domain\username

Process management
-------------------

Tools on Linux: ``top`` ``htop``

Tools on Windows: Task Manager (GUI)

>>> taskmgr

>>> tasklist

with PowerShell

>>> Get-Process

>>> taskkill /f /pid 3312

Find out network service list

On Linux with ``iproute2`` utility ``ss``

>>> sudo ss -nptl

>>> sudo ss -nptl | grep ':443'

On macOS with ``lsof`` or ``netstat``

>>> sudo lsof -P | grep -i 'listen'
>>> sudo lsof -i -nP | grep -i 'listen'
>>> sudo netstat -an | grep -i 'listen'

Windows PowerShell

>>> netstat -abno | find /i "listening "
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       2308
...
  TCP    [::1]:1434             [::]:0                 LISTENING       4492

Findout PID (Process ID) listening on a port (PowerShell 5 on Windows 10 or Server 2016)

>>> Get-Process -Id (Get-NetTCPConnection -LocalPort 443).OwningProcess
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1973       0     1848     790384  20,491.48      4   0 System

>>> Get-Process -Id (Get-NetUDPEndpoint -LocalPort 53).OwningProcess

>>> Get-NetTCPConnection -LocalPort 443 | Format-List
LocalAddress   : ::
LocalPort      : 443
...
OwningProcess  : 4
CreationTime   : 2022/3/9 10:31:36
OffloadState   : InHost

>>> Get-NetTCPConnection -LocalPort 443 | Format-Table -Property LocalAddress, LocalPort, State, OwningProcess
LocalAddress LocalPort  State OwningProcess
------------ ---------  ----- -------------
::                 443 Listen             4

GUI tool: ``resmon.exe``, `TCPView`_ from `sysinternals`_

>>> Get-Command ping
CommandType     Name           Version    Source
-----------     ----           -------    ------
Application     PING.EXE       10.0.14... C:\Windows\system32\PING.EXE

>>> Get-Command winget
Get-Command : 无法将“winget”项识别为 cmdlet、函数、脚本文件或可运行程序的名称。请检查名称的拼写，如果包括路径，请确保路径正确，然后再试一次。
所在位置 行:1 字符: 1
+ Get-Command winget
+ ~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (winget:String) [Get-Command], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException,Microsoft.PowerShell.Commands.GetCommandCommand

Install Powershell 7

>>> Install-Module -Name PowerShellGet

Install ``OpenSSH.Server`` on Windows server 2019 and later

>>> Add-WindowsCapability -Online -Name OpenSSH.Server
>>> Start-Service sshd
>>> Set-Service sshd -StartupType Automatic

Important data management
---------------------------

Default certificate store location for each platform:

OS X 10.11 macOS: ``/usr/local/etc/openssl/certs``

RHEL:  	``/etc/pki/tls/cert.pem``

Debian, SUSE Linux Enterprise, Ubuntu: ``/etc/ssl/certs``

Windows

with Windows PowerShell:

>>> ls CERT:
Location   : CurrentUser
StoreNames : {TrustedPublisher, ClientAuthIssuer, Root, UserDS...}
...
Location   : LocalMachine
StoreNames : {TrustedPublisher, ClientAuthIssuer, Root, TrustedDevices…}

>>> ls CERT:\CurrentUser
Name : TrustedPublisher
...
Name : Trust
Name : Disallowed

Export Windows certificate:

>>> $array = @()
>>> Get-ChildItem -Path Cert:\LocalMachine -Recurse | Where-Object {$_.PSISContainer -eq $false} | foreach-object ({
        $obj = New-Object -TypeName PSObject
        $obj | Add-Member -MemberType NoteProperty -Name “PSPath” -Value $_.PSPath
        $obj | Add-Member -MemberType NoteProperty -Name “FriendlyName” -Value $_.FriendlyName
        $obj | Add-Member -MemberType NoteProperty -Name “Issuer” -Value $_.Issuer
        $obj | Add-Member -MemberType NoteProperty -Name “NotAfter” -Value $_.NotAfter
        $obj | Add-Member -MemberType NoteProperty -Name “NotBefore” -Value $_.NotBefore
        $obj | Add-Member -MemberType NoteProperty -Name “SerialNumber” -Value $_.SerialNumber
        $obj | Add-Member -MemberType NoteProperty -Name “Thumbprint” -Value $_.Thumbprint
        $obj | Add-Member -MemberType NoteProperty -Name “DnsNameList” -Value $_.DnsNameList
        $obj | Add-Member -MemberType NoteProperty -Name “Subject” -Value $_.Subject
        $obj | Add-Member -MemberType NoteProperty -Name “Version” -Value $_.Version
        $array += $obj
        $obj = $null
    })
$array | Export-Csv -Path “c:\Windows.Server.2016.LocalMachine.CA.list.csv”

>>> $array = @()
>>> Get-ChildItem -Path Cert:\CurrentUser -Recurse | Where-Object {$_.PSISContainer -eq $false} | foreach-object ({
        $obj = New-Object -TypeName PSObject
        $obj | Add-Member -MemberType NoteProperty -Name “PSPath” -Value $_.PSPath
        $obj | Add-Member -MemberType NoteProperty -Name “FriendlyName” -Value $_.FriendlyName
        $obj | Add-Member -MemberType NoteProperty -Name “Issuer” -Value $_.Issuer
        $obj | Add-Member -MemberType NoteProperty -Name “NotAfter” -Value $_.NotAfter
        $obj | Add-Member -MemberType NoteProperty -Name “NotBefore” -Value $_.NotBefore
        $obj | Add-Member -MemberType NoteProperty -Name “SerialNumber” -Value $_.SerialNumber
        $obj | Add-Member -MemberType NoteProperty -Name “Thumbprint” -Value $_.Thumbprint
        $obj | Add-Member -MemberType NoteProperty -Name “DnsNameList” -Value $_.DnsNameList
        $obj | Add-Member -MemberType NoteProperty -Name “Subject” -Value $_.Subject
        $obj | Add-Member -MemberType NoteProperty -Name “Version” -Value $_.Version
        $array += $obj
        $obj = $null
    })
$array | Export-Csv -Path “c:\Windows.10.1709.CurrentUser.CA.list.csv”

Data storage mangement
------------------------

``BTRFS``

>>> btrfs subvolume snapshot -r /srv/OS/ubuntu-20.amd64.base{,.$(date +%F)}
>>> btrfs send /srv/OS/ubuntu-20.amd64.base.2021-08-25 | btrfs receive -v /data/OS/

``DNS (Domain Name Service)``
--------------------------------

Need to check what is managing DNS resolution, for example what generated ``/etc/resolv.conf``

``Bind9``

dump and view cache

>>> sudo rndc dumpdb -cache
>>> less /var/cache/bind/named_dump.db

Clear all cache or just one domain name cache

>>> sudo rndc flush
>>> sudo rndc flushname example.net

``dnsmasq``

>>> sudo pkill -USR1 dnsmasq # dump statistics to it's log

>>> dig +short chaos txt cachesize.bind
>>> dig +short chaos txt misses.bind
>>> dig +short chaos txt hits.bind

Use ``-q`` or ``--log-queries`` when starting ``dnsmasq`` to log the statistics

macOS

>>> sudo dscacheutil -flushcache
>>> sudo killall -HUP mDNSResponder

OS X 10.5 or earlier

>>> sudo lookupd -flushcache

Windows

>>> ipconfig /flushdns

Boot menu management
--------------------

Managing EFI boot menu with ``efibootmgr``

Create a boot entry

>>> efibootmgr --create --label 'Ubuntu 20.04' --disk /dev/sda --part 1 \
    --loader /EFI/systemd/systemd-bootx64.efi --verbose

Delete a boot entry

>>> efibootmgr --bootnum 5 --delete-bootnum

Change boot order

>>> efibootmgr --bootorder 0000,0003,0001

Set next boot entry

>>> efibootmgr --bootnext 0003

Networking
------------

Network adapter driver

>>> journalctl --dmesg | grep --context=3 --color --ignore-case ethernet
Aug 26 10:11:31 Mobile-Deb kernel: igb: Intel(R) Gigabit Ethernet Network Driver - version 5.4.0-k
Aug 26 10:11:31 Mobile-Deb kernel: igb: Copyright (c) 2007-2014 Intel Corporation.

>>> sudo modinfo igb
filename:       /lib/modules/4.19.0-17-amd64/kernel/drivers/net/ethernet/intel/igb/igb.ko
version:        5.4.0-k
license:        GPL
description:    Intel(R) Gigabit Ethernet Network Driver
author:         Intel Corporation, <e1000-devel@lists.sourceforge.net>
...
parm:           max_vfs:Maximum number of virtual functions to allocate per physical function (uint)
parm:           debug:Debug level (0=none,...,16=all) (int)

Linux low level interface

>>> cat /sys/class/net/eno1/carrier
0
>>> cat /sys/class/net/eno1/operstate
down
>>> cat /sys/class/net/eth0/operstate
up
>>> cat /sys/class/net/eth0/carrier
1

Alternative: ``nmcli`` ``systemd-networkd`` ``lshw`` ``ethtool``

>>> nmcli device status
DEVICE   TYPE      STATE        CONNECTION
eth0     ethernet  connected    Wired connection 2
eno1     ethernet  unavailable  --
lo       loopback  unmanaged    --

>>> networkctl
IDX LINK             TYPE               OPERATIONAL SETUP
  1 lo               loopback           carrier     unmanaged
  2 ens3             ether              routable    configured
...
  5 docker0          bridge             no-carrier  unmanaged

When set up multiple DHCP interfaces using ``systemd-networkd``, all but one of them should have their ``UseRoutes`` under ``[DHCP]`` section set to ``false``.
https://unix.stackexchange.com/questions/554107/set-routing-metrics-for-static-ips-with-systemd-networkd
https://github.com/systemd/systemd/issues/928

>>> sudo apt install lshw
>>> sudo lshw -class network -short
H/W path               Device     Class          Description
============================================================
/0/100/1c.3/0          eno1       network        Ethernet interface
/0/100/1c.4/0          rename3    network        I210 Gigabit Network Connection

>>> sudo ethtool -i eth0
driver: igb
...
supports-priv-flags: yes

Log network traffic data with ``vnstat``

>>> sudo apt-get --yes install --no-install-recommends vnstat
>>> vnstat --iface br0  # show summary of an interface
>>> vnstat --iface br0 --days   # show daily traffic
>>> vnstat --iface br0 --live   # show live traffic
>>> vnstat --add --iface enX0   # add an interface to monitor
Adding interface "enX0" to database for monitoring.
vnStat daemon will automatically start monitoring "enX0" within 5 minutes if the daemon process is currently running.

>>> vnstat
                      rx      /      tx      /     total    /   estimated
 enX0: Not enough data available yet.
 eth0 [disabled]:
       2022-01    339.53 GiB  /  352.96 GiB  /  692.49 GiB

``squid``

>>> squidclient [-h 127.0.0.1 -p 3128] mgr:info
>>> squidclient -h 127.0.0.1 -p 3142 mgr:utilization

``SSH``

>>> ssh-keyscan -t rsa,ecdsa,ed25519 >> ~/.ssh/known_hosts

Append host key into known_hosts

>>> ssh-keyscan hostname >> ~/.ssh/known_hosts

Append hashed host key into known_hosts

>>> ssh-keyscan -H hostname >> ~/.ssh/known_hosts

``strace``

>>> strace -o cmd.strace.$(date +%Y%m%d.%H%M).log -rt <cmd>

`stress-ng`_

>>> stress-ng --mq 0 -t 30s --times --perf

Forcing memory pressure

>>> stress-ng --brk 2 --stack 2 --bigheap 2

Target certain `temperature`_

>>> stress-ng --cpu 0 --tz -t 60

Use ``xev`` to monitor X event

>>> xev

Troubleshooting
-------------------

Enable persistent journal with systemd on Linux

>>> sudo mkdir -p /var/log/journal
>>> sudo systemd-tmpfiles --create --prefix /var/log/journal
>>> sudo systemctl restart systemd-journald

List log name on Windows

>>> wevtutil enum-logs

Display the three most recent events from the Application log in textual format

>>> wevtutil query-events Application /c:3 /rd:true /f:text

Export log to file

>>> wevtutil epl c:\mylog1.txt

Note to reader:

I have all kinds of computing notes recorded in this file, but may separate accordingly later. BTW, I decided to not use plural at times, but hesitate at others p_q

Reference
----------
https://phoenixnap.com/kb/linux-cpu-temp

.. _TCPView: https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview
.. _sysinternals: https://docs.microsoft.com/en-us/sysinternals
.. _LUKS: https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup
.. _stress-ng: https://wiki.ubuntu.com/Kernel/Reference/stress-ng
.. _temperature: https://askubuntu.com/questions/15832/how-do-i-get-the-cpu-temperature

https://stackoverflow.com/questions/48198/how-can-you-find-out-which-process-is-listening-on-a-tcp-or-udp-port-on-windows

Differences between Windows PowerShell 5.1 and PowerShell 7.x
https://docs.microsoft.com/en-us/powershell/scripting/whats-new/differences-from-windows-powershell

PowerShell 7 module compatibility
https://docs.microsoft.com/en-us/powershell/scripting/whats-new/module-compatibility