Windows server core system requirement:

1.4 GHz, 64-bit CPU and 512 MiB of RAM

The installation process is pretty easy, just boot from a Windows Server 2022 installation media and provide the following required data for the OS:

Option Default

Time and currency format    English (United States)
Keyboard or input method    US

Hard drive to install to;
Data decided by the installation media:

Language to install: English (United States)

Optional data (can be provided after installation): product key

Time and currency format    Chinese (Simplified, China)
Keyboard or input method    Microsoft Pinyin or US

After reboot and login for the first time, you should

Enable ``Remote Desktop`` ``Remote Desktop Protocol`` (RDP) with the following command

>>> SConfig

::

 WARNING: To stop SConfig from launching at sign-in, type "Set-SConfig -AutoLaunch $false"

  ================================================================================
                      Welcome to Windows Server 2022 Datacenter
  ================================================================================

    1)  Domain/workgroup:                   Workgroup: WORKGROUP
    2)  Computer name:                      WIN-6K2V9EVD61R
    3)  Add local administrator
    4)  Remote management:                  Enabled

    5)  Update setting:                     Download only
    6)  Install updates
    7)  Remote desktop:                     Enabled (more secure clients)

    8)  Network settings
    9)  Date and time
    10) Telemetry setting:                  Required
    11) Windows activation

    12) Log off user
    13) Restart server
    14) Shut down server
    15) Exit to command line (PowerShell)

  Enter number to select an option:

and then choose ``7 -> E -> 1``

Change or set the product key of your server

>>> slmgr.vbs –ipk<productkey>

Active the server licence

>>> slmgr.vbs -ato

Power management
----------------

>>> Restart-Computer -ComputerName Server01, Server02, localhost
>>> Stop-Computer -ComputerName "Server01", "Server02", "localhost"

Local user management
------------------------

Change password interactively. Like Linux, nothing will be shown when you (re-)type the new password

>>> net user administrator *
Type a password for the user:
Retype the password to confirm:
The command completed successfully.

Networking
----------

List network interface

>>> Get-NetIPInterface
>>> netsh interface show interface

Set static IP, mask, gateway

>>> New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.3.3.11 -PrefixLength 24 -DefaultGateway 10.3.3.1
>>> netsh interface ipv4 set address "Local Area Connection" source=static 10.3.3.11 255.255.255.0 10.3.3.1

>>> Get-NetAdapter
Name      InterfaceDescription       ifIndex Status   MacAddress          LinkSpeed
----      --------------------       ------- ------   ----------          ---------
Ethernet  Intel(R) 82574L Gigabit...       6 Up       52-54-00-B3-8F-D6      1 Gbps

>>> Get-DnsClientServerAddress -InterfaceIndex 6
InterfaceAlias  Interface Address ServerAddresses
                Index     Family
--------------  --------- ------- ---------------
Ethernet                6 IPv4    {192.168.122.1}
Ethernet                6 IPv6    {}

>>> Set-DnsClientServerAddress -InterfaceIndex 6 -ServerAddresses ("10.10.10.10")

Set primary DNS server

>>> netsh interface ipv4 add dnsserver "Local Area Connection" address=10.3.3.3 index=1

Set secondary DNS server

>>> netsh interface ipv4 add dnsserver "Local Area Connection" address=10.3.3.4 index=2

Remove DNS server from interface

>>> netsh interface ipv4 delete dnsservers "Local Area Connection" 10.3.3.4 (or all)

Set interface to DHCP

>>> netsh interface ipv4 set address "Local Area Connection" source=dhcp

Disable interface

>>> netsh interface set interface "Local Area Connection" disabled (or enabled to re-enable)

Get route table

>>> Get-NetRoute

Firewall
========

>>> New-NetFirewallRule -DisplayName "Allow inbound ICMPv4" -Direction Inbound -Protocol ICMPv4 -IcmpType Any -RemoteAddress LocalSubnet -Action Allow
>>> New-NetFirewallRule -DisplayName "Allow inbound ICMPv6" -Direction Inbound -Protocol ICMPv6 -IcmpType Any -RemoteAddress LocalSubnet -Action Allow

Service management
---------------------

List running service

>>> sc query

Start / stop a service

>>> sc start (service name)
>>> sc stop (service name)

Disable a service

>>> sc config (service name) start=disabled

Security
--------

>>> $User = "Domain01\User01"
>>> $PWord = ConvertTo-SecureString -String "P@sSwOrd" -AsPlainText -Force
>>> $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord

Interactively ask for a credential, and use the credential by using the variable

>>> $Cred = Get-Credential

Hardware (driver) management
-----------------------------

Query active drivers

>>> sc query type=driver

Install a driver

>>> pnputil -i -a oemdriver.inf

Storage management
---------------------

Find out available space on a drive

>>> Get-PSDrive C
>>> Get-CimInstance -ClassName Win32_LogicalDisk | Select-Object DeviceID, FreeSpace, Size
>>> fsutil volume diskFree C:

List PowerShell cmdlets in the `Storage`_ module (used for disk management)

>>> Get-Command -Module Storage | Measure-Object

>>> Get-Command -Module Storage

List Local Disks and Partitions

>>> Get-Disk -Number 6
Number Friendly Name Serial Number HealthStatus OperationalStatus Total Size Partition Style
------ ------------- ------------- ------------ ----------------- ---------- ---------------
0      QEMU HARDDISK QM00001       Healthy      Online                 16 GB MBR

>>> Get-Disk | Where-Object IsSystem -eq $True | ft -AutoSize
Number Friendly Name Serial Number HealthStatus OperationalStatus Total Size Partition Style
------ ------------- ------------- ------------ ----------------- ---------- ---------------
0      QEMU HARDDISK QM00001       Healthy      Online                 16 GB MBR

List physical disk

>>> Get-PhysicalDisk
Number FriendlyName  SerialNumber MediaType   CanPool OperationalStatus HealthStatus Usage        Size
------ ------------  ------------ ---------   ------- ----------------- ------------ -----        ----
0      QEMU HARDDISK QM00001      Unspecified False   OK                Healthy      Auto-Select 16 GB

>>> Get-Partition
   DiskPath: \\?\scsi#disk&ven_qemu&prod_harddisk#4&2749002f&0&000000#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
. 
PartitionNumber  DriveLetter Offset                                        Size Type
---------------  ----------- ------                                        ---- ----
1                           1048576                                     100 MB IFS
2                C           105906176                                 15.39 GB IFS
3                           16629366784                                 523 MB Unknown

List paritions of specified disk

>>> Get-Partition -DiskNumber 1,2

Get all ``USB`` or ``iSCSI`` disks

>>> Get-Disk | Where-Object -FilterScript {$_.Bustype -Eq "USB"}
>>> Get-Disk | Where-Object -FilterScript {$_.Bustype -Eq "iSCSI"}

List all Windows volume

>>> Get-Volume
DriveLetter FriendlyName         FileSystemType DriveType HealthStatus OperationalStatus SizeRemaining     Size
----------- ------------         -------------- --------- ------------ ----------------- -------------     ----
D           SSS_X64FRE_EN-US_DV9 Unknown        CD-ROM    Healthy      OK                          0 B  5.17 GB
            System Reserved      NTFS           Fixed     Healthy      OK                     68.18 MB   100 MB
                                 NTFS           Fixed     Healthy      OK                     83.41 MB   523 MB
C                                NTFS           Fixed     Healthy      OK                      8.18 GB 15.39 GB

List offline disk (no output when none presents)

>>> Get-Disk | Where-Object IsOffline -eq $True | ft -AutoSize

Bring offline disk online and make it ready to be used

>>> Get-Disk | Where-Object IsOffline -eq $True | Set-Disk -IsOffline $False

Initialize the unused disk

>>> Initialize-Disk -Number <index.of.disk>
>>> Initialize-Disk -Number <index.of.disk> -PartitionStyle MBR

``mbr2gpt.exe`` can be used to convert a MBR disk to a GPT one without moving the data on it

Create a new partition and assign specified driver letter

>>> New-Partition -DiskNumber <index.of.disk> -Size 10gb -DriveLetter L

Create a new partition taken all available space and assign a drive letter automatically

>>> New-Partition -DiskNumber <index.of.disk> -AssignDriveLetter –UseMaximumSize

>>> Get-PartitionSupportedSize -DriveLetter <drive.letter> | Format-List

>>> $MaxSize = (Get-PartitionSupportedSize -DriveLetter <drive.letter>).SizeMax

>>> Resize-Partition -DriveLetter <drive.letter> -Size $MaxSize

>>> Set-Partition -DriveLetter <drive.letter> -IsActive $true

>>> Format-Volume -DriveLetter <drive.letter> -FileSystem NTFS -NewFileSystemLabel Data -Confirm:$false

You can specify multiple disk by comma separated index like ``1,3``

>>> Get-Partition -DiskNumber <index.of.disk> | Remove-Partition -Confirm:$false

Dangerous command: delete all partition and clear the data on a disk

>>> Clear-Disk -Number <index.of.disk> -RemoveData -Confirm:$false
>>> Clear-Disk -Number 1 -RemoveData -RemoveOEM

Preparing a new empty drive

>>> Get-Disk | Where-Object PartitionStyle -eq 'RAW' | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -Confirm:$false

.. _Storage: https://docs.microsoft.com/en-us/powershell/module/storage/

Different license level feature comparison: https://docs.microsoft.com/en-us/windows-server/get-started/editions-comparison-windows-server-2019

https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule

https://www.kimiushida.com/bitsandpieces/articles/windows_server_core_command_cheat_sheet/index.html

https://docs.microsoft.com/en-my/powershell/module/Microsoft.PowerShell.Security/Get-Credential