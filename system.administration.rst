System administration tip and trick
####################################

Hardware management
--------------------

``Windows``

Hard drive (to be filled when I be on a Windows machine)

``macOS``

>>> sysctl -a | grep machdep.cpu
machdep.cpu.address_bits.physical: 39
machdep.cpu.address_bits.virtual: 48
...
machdep.cpu.thread_count: 4
machdep.cpu.vendor: GenuineIntel

Check certain CPU feature

>>> sysctl -a | grep 'machdep.cpu.features' | grep --ignore-case 'sse'
machdep.cpu.features: FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE SSE3 PCLMULQDQ DTES64 MON DSCPL VMX EST TM2 SSSE3 FMA CX16 TPR PDCM SSE4.1 SSE4.2 x2APIC MOVBE POPCNT AES PCID XSAVE OSXSAVE SEGLIM64 TSCTMR AVX1.0 RDRAND F16C

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

Reboot a remote host and specify the reason in system event log

>>> shutdown /s /t 30 /c "Reconfigure myapp" /d p:4:1

Shutdown computer now

>>> shutdown /s /t 0

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

interactive tool on Linux: ``top`` ``htop``

>>> top --sort-override=%MEM    # top -o %MEM   # sort by memory usage in descending order 按内存耗用从大到小排序

interactive tool on macOS: ``top`` ``htop``

>>> top -o mem  # sort by memory usage in descending order 按内存耗用从大到小排序

Tools on Windows: Task Manager (GUI)

>>> taskmgr

>>> tasklist

with PowerShell

>>> Get-Process

With Windows command line including cmd.exe

>>> taskkill /f /pid 3312

>>> taskkill /pid 1230 /pid 1241 /pid 1253

To end the process with the process ID 2134 and any child processes that it started, but only if those processes were started by the Administrator account
>>> taskkill /pid 2134 /t /fi "username eq administrator"

Find out network service list

On Linux with ``iproute2`` utility ``ss``

>>> sudo ss -nptl

>>> sudo ss -nptl | grep ':443'

On macOS with ``lsof`` or ``netstat``

>>> sudo lsof -P | grep --ignore-case 'listen'
launchd   1       root   7u   unix 0x322fedbd02b82565   0t0   /private/tmp/com.apple.launchd.MOMbYSsODV/Listeners
.
sesinetd  96036   _www   6u   IPv4 0x322fedbd18819bc5   0t0   TCP *:1715 (LISTEN)

>>> sudo lsof -i -nP | grep --ignore-case 'listen'
launchd       1           root    8u  IPv6 0x322fedbd02e6f175      0t0    TCP *:22 (LISTEN)
.
dns-sd     4696           _www    6u  IPv4 0x322fedbd18819bc5      0t0    TCP *:1715 (LISTEN)

>>> sudo netstat -ano | grep --ignore-case 'listen'
tcp6   0   0  *.8080     *.*    LISTEN   1729
.

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

You can use GUI tools ``Keychain Access.app`` or ``钥匙串访问.app`` in Chinese to access certificate data on your system. ``security`` command can be used to manage certificate data from the terminal.

macOS system certificate: ``/System/Library/Keychains/``

macOS certificate: ``/Library/Keychains/``

macOS user certificate: ``~/Library/Keychains/``

Certificate for Homebrew and terminal application? (on OS X 10.11 ~ macOS 11.6): ``/usr/local/etc/openssl/cert.pem``

>>> /usr/bin/security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain

RHEL: ``/etc/pki/tls/cert.pem``

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

on Linux

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

``Linux``

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

network routing with ``route`` command in ``iproute2`` package

>>> ip route
default via 192.168.42.129 dev usb0  src 192.168.42.115
...

>>> ip route add w.x.y.z/m via a.b.c.d dev $INTERFACE

if ``ping`` or ``ping6`` complains about "missing cap_net_raw+p capability or setuid?", check with ``getcap`` that it has ``cap_net_raw=ep``, ``getcap`` returns nothing if ``ping`` does not have the capability,

>>> /usr/sbin/getcap /usr/bin/ping
/usr/bin/ping cap_net_raw=ep

or kernel ``net.ipv4.ping_group_range`` parameter with ``sysctl`` like the following:

>>> /usr/sbin/sysctl net.ipv4.ping_group_range
net.ipv4.ping_group_range = 1   0

https://blog.lilydjwg.me/2013/10/29/non-privileged-icmp-ping.41390.html

If your kernel support this feature, you need to change it to include the group id (gid) of the active user running ``ping``:

>>> sudo sysctl --write net.ipv4.ping_group_range='0 1000'
net.ipv4.ping_group_range = 0 1000

``macOS``

``networksetup -setmanual networkservice ip subnet router``
>>> networksetup -setmanual 'AX88179' 10.3.3.3 255.255.255.0 10.3.3.254

``networksetup -setv6manual ip prefixlength router``

``ipconfig set interface-name (MANUAL | INFORM) ip-address subnet-mask``
>>> ipconfig set en4 MANUAL ip-address subnet-mask

>>> networksetup -setdhcp "Ethernet"

``ipconfig set interface-name DHCP``
>>> ipconfig set en4 DHCP

``ipconfig set interface-name AUTOMATIC-V6``
``ipconfig set interface-name MANUAL-V6 ipv6-address prefix-length``

>>> networksetup -getinfo 'AX88179'
Manual Configuration
IP address: 10.3.3.3
Subnet mask: 255.255.255.0
Router: 10.3.3.254
IPv6: Automatic
IPv6 IP address: none
IPv6 Router: none
Ethernet Address: 00:...:20

>>> sudo route -n add -net w.x.y.z/m a.b.c.d
>>> sudo netstat -nr
Routing tables
...
Internet:
Destination     Gateway         Flags     Netif   Expire
default         10.3.3.1        UGScg      en4
...
Internet6:
Destination     Gateway         Flags     Netif   Expire
default         fe80::%utun0    UGcIg     utun0       
default         fe80::%utun1    UGcIg     utun1
ff02::%en4/32   link#13         UmCI      en4

>>> sudo route delete default -interface en4
Password:
delete net default: gateway en4

>>> sudo route add default 10.3.3.1

>>> sudo route change default -interface $INTF
>>> sudo route change 10.3.0.0/16 -interface $INTF

>>> route get example.net
   route to: 93.184.216.34
destination: default
.
    gateway: 192.168.43.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
...

(manually) find out the service you're using

>>> networksetup -listnetworkserviceorder
...
(5) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
...

>>> networksetup -getdnsservers 'Wi-Fi'
223.6.6.6
...
2001:4860:4860::8844

Update DNS setting ::

 Usage: networksetup -setdnsservers <networkservice> <dns1> [dns2] [...]

>>> networksetup -setdnsservers 'Wi-Fi' 223.6.6.6 223.5.5.5 1.0.0.1 1.1.1.1 240c::6666 240c::6644 2606:4700:4700::1111 2606:4700:4700::1001 2001:4860:4860::8888 2001:4860:4860::8844

get web proxy status of the ``Wi-Fi`` service, notice this setting has no effect for applications run in a terminal

>>> networksetup -getwebproxy 'Wi-Fi'
Enabled: Yes
Server: ::1
Port: 8080
Authenticated Proxy Enabled: 0

Update web proxy setting ::

 Usage: networksetup -setwebproxy <networkservice> <domain> <port number> <authenticated> <username> <password>

Test setting web proxy with authentication. Seems I can skip the ``<password>`` option and type the password in interactively, and a ``keychain`` pop-up window will appear and for saving the credential the credential in the ``keychain`` application. I didn't provide the password to unlock the ``keychain`` application in the following example.

>>> networksetup -setwebproxy 'Wi-Fi' localhost 8080 on 'Meow'
Password:
2023-03-29 16:24:19.958 networksetup[67308:3086436] error -128 attempting to create account and password for proxy: localhost:8080

>>> networksetup -setwebproxystate 'Wi-Fi' off

For socks proxy, use ``-getsocksfirewallproxy`` and ``-setsocksfirewallproxy`` to query and update the state

``Windows``
Windows 系统遇到 IP 冲突时的系统事件日志示例 ::

 日志名称:       System
 来源:           Tcpip
 日期:           2023/12/26 15:19:24
 事件 ID:        4199
 任务类别:       无
 级别:           错误
 关键字:         经典
 用户:           暂缺
 计算机:         Meow-DESKTOP
 描述:           系统检测到 IP 地址 10.x.y.z 和网络硬件地址 aa-bb-cc-33-99-66 发生地址冲突。 此系统的网络操作可能会突然中断。

事件 Xml ::

 <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
   <System>
     <Provider Name="Tcpip" />
     <EventID Qualifiers="49152">4199</EventID>
     <Version>0</Version>
     <Level>2</Level>
     <Task>0</Task>
     <Opcode>0</Opcode>
     <Keywords>0x80000000000000</Keywords>
     <TimeCreated SystemTime="2023-12-26T08:07:40.3056028Z" />
     <EventRecordID>2487</EventRecordID>
     <Correlation />
     <Execution ProcessID="4" ThreadID="360" />
     <Channel>System</Channel>
     <Computer>Meow-DESKTOP</Computer>
     <Security />
   </System>
   <EventData>
     <Data>
     </Data>
     <Data>10.x.y.z</Data>
     <Data>aa-bb-cc-33-99-66</Data>
     <Binary>...030...</Binary>
   </EventData>
 </Event>

Windows 系统日志里的 IP 冲突日志条目的部分信息，出现 IP 冲突的时间段里，在出现冲突的机器上，在命令行用 arp 命令查询地址解析协议 (ARP) 显示的 IP 地址和 MAC 地址的映射关系，可以找到使用了同样 IP 地址的另一个计算机的 MAC 地址：

>>> arp.exe -a
接口: 10.5.6.3 --- 0x6
  Internet 地址 物理地址                类型
  10.5.6.4      aa-bb-cc-33-99-66       动态

Miscellaneous
----------------

Log network traffic data with ``vnstat``

>>> sudo apt-get --yes install --no-install-recommends vnstat
>>> vnstat --iface br0  # show summary of an interface
>>> vnstat --iface br0 --days   # show daily traffic
>>> vnstat --iface br0 --live   # show live traffic
>>> vnstat --add --iface enX0   # add an interface to monitor
Adding interface "enX0" to database for monitoring.
vnStat daemon will automatically start monitoring "enX0" within 5 minutes if the daemon process is currently running.

You will also need to enable the specific interface in ``/etc/vnstat.conf`` ::

 Interface "enX0"

Then ``restart`` the ``vnstat.service``, ``reload`` aren't enough: ``sudo systemctl restart vnstat.service``

>>> vnstat
                      rx      /      tx      /     total    /   estimated
 enX0: Not enough data available yet.
 eth0 [disabled]:
       2022-01    339.53 GiB  /  352.96 GiB  /  692.49 GiB

``squid``

>>> squidclient [-h 127.0.0.1 -p 3128] mgr:info
>>> squidclient -h 127.0.0.1 -p 3142 mgr:utilization

``SSH``

>>> ssh-keyscan -t rsa,ecdsa,ed25519 github.com >> ~/.ssh/known_hosts
...
# github.com:22 SSH-2.0-babeld-62777e2e

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

``Linux``

Enable persistent journal with systemd

>>> sudo mkdir -p /var/log/journal
>>> sudo systemd-tmpfiles --create --prefix /var/log/journal
>>> sudo systemctl restart systemd-journald

Cleanup old ``systemd-journald`` log

>>> sudo journalctl --vacuum-time=3m
.
Vacuuming done, freed 1.8G of archived journals from /var/log/journal/...

``macOS``

show log in the last X minutes ( 4 in this case )

>>> log show --last 4m

View realtime log

>>> log stream --info

``--level``: {``off`` | ``default`` | ``info`` | ``debug``} The level is a hierarchy, e.g. debug implies debug, info, and default

>>> log stream --level default

Find out process id of running DNS query service

>>> sudo lsof -i -nP | rg -e '53' -e 'pid'
COMMAND     PID           USER   FD   TYPE             DEVICE SIZE/OFF   NODE NAME
.
mDNSRespo   181 _mdnsresponder    6u  IPv4 0x4cd7f48a2d576b0f      0t0    UDP *:5353
mDNSRespo   181 _mdnsresponder    7u  IPv6 0x4cd7f48a2d576dff      0t0    UDP *:5353
.

>>> log stream --process 181

or just use the ``--predicate`` filter to get only live ``mDNSResponder`` log

>>> log stream --predicate 'process == "mDNSResponder"'

>>> log show --last 3h --debug --predicate 'eventMessage contains "duplicate IP address"'
Timestamp                       Thread     Type      Activity   PID   TTL
.
2024-01-17 15:12:58.867066+0800 0x36ad28   Default   0x0        0     0    kernel: en4 duplicate IP address 10.x.y.z sent from address aa:bb:cc:33:99:66

``Windows``

List log name

>>> wevtutil enum-logs

Display the three most recent events from the Application log in textual format

>>> wevtutil query-events Application /c:3 /rd:true /f:text

Export log to file

>>> wevtutil epl c:\mylog1.txt

Reference
----------
https://phoenixnap.com/kb/linux-cpu-temp

.. _TCPView: https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview
.. _sysinternals: https://docs.microsoft.com/en-us/sysinternals
.. _stress-ng: https://wiki.ubuntu.com/Kernel/Reference/stress-ng
.. _temperature: https://askubuntu.com/questions/15832/how-do-i-get-the-cpu-temperature

https://stackoverflow.com/questions/48198/how-can-you-find-out-which-process-is-listening-on-a-tcp-or-udp-port-on-windows

Differences between Windows PowerShell 5.1 and PowerShell 7.x
https://docs.microsoft.com/en-us/powershell/scripting/whats-new/differences-from-windows-powershell

PowerShell 7 module compatibility
https://docs.microsoft.com/en-us/powershell/scripting/whats-new/module-compatibility
