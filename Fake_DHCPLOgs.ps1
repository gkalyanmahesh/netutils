# Script that generates DHCP log with fake data.
# Nxlog agent will take log as input and send it to collector.
# changes in nxlog config are
# Write-Output "File 'C:\\dmp\\dhcp\\DhcpSrvLog-*.log'"
# Replace codewith above line in "dhcp_log_path_include.cmd" file in c:\program files\nxlog\scripts\
#  
# 


mkdir c:\dmp\dhcp -Force

$dstlog = "c:\dmp\dhcp\temp.log"  

#Stopping Nxlog service
stop-service nxlog
$Mainlog="c:\dmp\dhcp\DhcpSrvLog-$((get-date).DayOfWeek.ToString().Substring(0,3)).log"

if (Test-Path $dstlog) {echo "File exists.. Deleting." ; Remove-Item $dstlog -Force}
Else {echo "file does not exist. Creating new one!"}


Function todlog ($val ) {Add-Content -Value $val -path $dstlog}
function txid { @(365895647,258965256,2658587,456321568,459358,124578,65969,3212156,454698,5465498) | Get-Random}
function dtstmp {Get-Date -Format 'MM/dd/yy,HH:mm:ss'}

function wentry ($eid,$evt,$ip,$hname,$mac,$txid ) {
$wval = "$eid,$(dtstmp),$evt,$ip,$hname,$mac,,$txid,0,,,,0x4D53465420352E30,MSFT 5.0,,,,0"
return $wval
}

function nack { 

$nval = "15,$(dtstmp),NACK,192.168.50.192,,000C291AA6AF,,0,6,,,,,,,,,0`n"
$nval += "24,$(dtstmp),Databse Cleanup Begin,,,,,0,6,,,,,,,,,0`n"
$nval += "25,$(dtstmp),0 leases expired and 0 leases deleted,,,,,0,6,,,,,,,,,0"

return $nval
}


$pfix= @"

		Microsoft DHCP Service Activity Log


Event ID  Meaning
00	The log was started.
01	The log was stopped.
02	The log was temporarily paused due to low disk space.
10	A new IP address was leased to a client.
11	A lease was renewed by a client.
12	A lease was released by a client.
13	An IP address was found to be in use on the network.
14	A lease request could not be satisfied because the scope's address pool was exhausted.
15	A lease was denied.
16	A lease was deleted.
17	A lease was expired and DNS records for an expired leases have not been deleted.
18	A lease was expired and DNS records were deleted.
20	A BOOTP address was leased to a client.
21	A dynamic BOOTP address was leased to a client.
22	A BOOTP request could not be satisfied because the scope's address pool for BOOTP was exhausted.
23	A BOOTP IP address was deleted after checking to see it was not in use.
24	IP address cleanup operation has began.
25	IP address cleanup statistics.
30	DNS update request to the named DNS server.
31	DNS update failed.
32	DNS update successful.
33	Packet dropped due to NAP policy.
34	DNS update request failed.as the DNS update request queue limit exceeded.
35	DNS update request failed.
36	Packet dropped because the server is in failover standby role or the hash of the client ID does not match.
50+	Codes above 50 are used for Rogue Server Detection information.

QResult: 0: NoQuarantine, 1:Quarantine, 2:Drop Packet, 3:Probation,6:No Quarantine Information ProbationTime:Year-Month-Day Hour:Minute:Second:MilliSecond.

ID,Date,Time,Description,IP Address,Host Name,MAC Address,User Name, TransactionID, QResult,Probationtime, CorrelationID,Dhcid,VendorClass(Hex),VendorClass(ASCII),UserClass(Hex),UserClass(ASCII),RelayAgentInformation,DnsRegError.

"@

todlog -val $pfix

$pccoll = @()
1..90 | ForEach-Object{

    # Hostname
    $hostname = "PC{0:00}" -f $_
    
    # Mac Address
    $Macaddr = (('{0:X12}' -f $_) -split '(..)' | Where-Object { $_ })  -join ''
    
    # IP Address
    $IPaddr = "10.9.9.{0:0}" -f $_

    # Output
    $obj = "" | select Hname,MAC,IPaddr
    $obj.hname = $hostname; $obj.mac = $Macaddr; $obj.ipaddr = $IPaddr

    # $obj

    $pccoll += $obj
}

echo "Done! `nAssigning new ip addresses !`n "
# Assigning new ip leases:
foreach ($pc in $pccoll)
{
    $dval =  wentry -eid 10 -evt "Assign" -ip $pc.ipadr -hname $pc.hname -mac $pc.mac -txid $(txid)
     sleep -mi 500
    todlog -val $dval
}


echo "Renewing ip leases....untill stopped!!"
#while($true) {
# renewing ip leases
$n=0
foreach ($pc in $pccoll)
{ rm dval -ea SilentlyContinue -Force
 sleep -mi 200
    if (($n/10).tostring().length -eq 1) {$nval= nack ;todlog -val $nval ;$n++;}
    
    $dval = wentry -eid 11 -evt "Renew" -ip $pc.ipadr -hname $pc.hname -mac $pc.mac -txid $(txid)
    sleep -mi 200
    todlog -val $dval
    $n++
}
# sleep -s 10

#}

Copy-Item $dstlog -Destination $Mainlog -Force -Confirm:$false

# Starting Service

 Start-Service nxlog



