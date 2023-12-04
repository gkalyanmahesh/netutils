#
# sshpass package to be installed on prior
# Add US as prohibited countries to site 
disp() { echo $1 ; echo $1 >> /home/cyglass/plog
}
pout() { echo "$1 \t - \t $2" >> /home/cyglass/pout
}
echo "" > /home/cyglass/pout

# Azure Kali VM Public IP : 20.223.181.26
ekvmip="20.223.181.26"

#Internal kali vm ip(self ip ) # Critical Device # Development # Active Directory
ikvmip="10.100.3.49"

# Internal critical device running linux # Critical # Production
ilvmip="10.100.3.35" 

disp "============================== $(date)\nAzure kvm ip : $ekvmip \nInternal kvm ip : $ikvmip \nInternal lvm ip : $ilvmip \n"


# 1-ipaddress , 2-port , 3-pfile

trigger() { sshpass -f $3 ssh -o StrictHostKeychecking=no cyglass@$1 "python3 -m http.server $2 --directory /home/cyglass" &
if (($?>0));
then 	disp "Error connecting $i"
else
	disp "Hosting file on port $2 on $1"
fi
sleep 10
curl "http://$1:$2/pst.zip" -o "/tmp/pst_$1_$2.zip"
if (($?>0));
	then disp "Failed to download from $1 on port $2"
else
	disp "Downloaded from $1 on port $2"
fi
sleep 5
}

#= = = = = = = = = = = = = = =  = = = = = = = = = = = = = = = = = =


#------------------------------------------------------------------------------------
# 1
 # Policy : Block Exfiltration through Common Ports
 # Src: Critical Devices
 # Dst: All External Domains
 # Desc: Detects when a critical devcie is communicating externally through common ports
 # Ports: 80 , 443,  25,53,2525,587,465
 # Volume: ge 1Mb
 disp "Policy 1: Block Exfiltration through Common Ports"
 
 trigger $ekvmip 80 epfile
 
 disp "============================="

 #------------------------------------------------

# 2
 # Policy : Block Exfiltration through Remote Service Layer Ports
 # Src: Critical Devices
 # Dst: All External Domains
 # Desc: Detects when a critical devcie is communicating externally through Service layer ports
 # Ports: 21,22,23
 # Volume: ge 1Mb

disp "Policy 2: Block Exfiltration through Remote Service Layer Ports"

trigger $ekvmip 23 epfile

disp "============================="

 #------------------------------------------------
 
# 3
 # Policy : Internal Telnet Traffic to Critical Devices
 # Src: All Internal Devices
 # Dst: Critical Devices
 # Desc: Detects when unencrypted telnet traffic is detected to your critical systems
 # Ports: 23
 # Conv: UDP Two Way, TCP Normal
 # Volume: ge 1kb
 
#trigger $ilvmip 23 ipfile
disp "Policy 3 : Internal Telnet Traffic to Critical Devices"

sshpass -f ipfile scp -o StrictHostKeychecking=no cyglass@$ilvmip:/home/cyglass/pst.zip /tmp/pst_$ilvmip_23.zip

if (($?>0))
then
disp "Error in executing scp from $ilvmip"
else
disp "Successful SCP from $ilvmip"
fi

disp "============================="
 #------------------------------------------------

# 4
 # Policy : Activity between Development and Production
 # Src: Development Devices
 # Dst: Production
 # Desc: Detect when unauthorized development systems are communicating with Production systems
 # Ports: any
 # Volume: any

disp "Policy 4: Activity between Development and Production"

sshpass -f ipfile scp -o StrictHostKeychecking=no cyglass@$ilvmip:/home/cyglass/pst.zip /tmp/pst_$ilvmip_23.zip

if (($?>0))
then
disp "Error in executing scp from $ilvmip"
else
disp "Successful SCP from $ilvmip"
fi

disp "============================="

 #------------------------------------------------
 
# 5
 # Policy : Unusually High Activity from Critical Devices to External
 # Src: Critical Devices
 # Dst: All External Domains
 # Desc: An unusual volume of activity has been detected between a critical device and an external domain.
 # Ports: any
 # Volume: any
 # Anomaly: Large Volume from asset

disp "Policy 5: Unusually High Activity from Critical Devices to External"

sshpass -f epfile scp -o StrictHostKeychecking=no /home/cyglass/pst.zip cyglass@$ekvmip:/tmp/pst_$ikvmip_23.zip
if (($?>0))
then
disp "Error in executing scp from $ikvmip"
else
disp "Successful SCP from $ikvmip to $ekvmip"
fi

disp "============================="

 #------------------------------------------------
 
# 6
 # Policy : Active Directory to External
 # Src: Active Directory
 # Dst: All External Domains
 # Desc: Detect when Active Directory Servers are communicating improperly with the outside world on ports other than 53, 80, 123 or 443
 # Ports: other than 53,443,80,123
 # Volume: ge 1Kb
 # Conv: UDP One way , UDP two way, TCP Normal

disp "Policy 6: Active Directory to External"

trigger $ekvmip 88 $epfile

disp "============================="

 #------------------------------------------------
 
# 7
 # Policy : AA21-356A - Detecting unusual volume of DNS, LDAP or RMI activity due to potential Log4Shell Attacks
 # Src: All Internal Devices
 # Dst: All External Domains
 # Desc: As recommended in CISA Alert AA21-356A, this policy identifies LDAP and RMI activity that is anomalous.
 # Ports: 389,636,3268,1099,3269,1389,1636
 # Volume: ge 100Kb
 

disp "Policy 7: AA21-356A - Detecting unusual volume of DNS, LDAP or RMI activity due to potential Log4Shell Attacks"

trigger $ekvmip 1099 $epfile

disp "============================="

 #------------------------------------------------
 # 8
 # Policy : AA21-356A - Detect potential Log4Shell Attacks via LDAP or RMI
 # Src: All Internal Devices
 # Dst: All External Domains
 # Desc: As recommended in CISA Alert AA21-356A, this policy identifies LDAP and RMI activity to known malicious IPs.
 # Ports: 389,636,3268,1099,3269,1389,1636
 # Anomaly : Blacklisted IP's
 # Volume: ge 100Kb
 

disp "Policy 8: AA21-356A - Detect potential Log4Shell Attacks via LDAP or RMI"

trigger $ekvmip 1389 epfile

disp "============================="

 #------------------------------------------------
 # 9
 # Policy : AA21-356A - Detect potential Log4Shell Attacks to New Organizations via LDAP or RMI
 # Src: All Internal Devices
 # Dst: All External Domains
 # Desc: As recommended in CISA Alert AA21-356A, this policy identifies LDAP and RMI activity to sites never before communicated with.
 # Ports: 389,636,3268,1099,3269,1389,1636
 # Anomaly : Connection to New Organization
 # Volume: ge 100Kb
 # new site, never before communicated with.

disp "Policy 9: AA21-356A - Detect potential Log4Shell Attacks to New Organizations via LDAP or RMI"

# to be set accordingly

disp "============================="

 #------------------------------------------------
 # 10
 # Policy : Connection From New External Domain to Internal
 # Src: All External Devices
 # Dst: All Internal Domains
 # Desc: A remote Domain has connected to a device in your network for the first time. It may be unusual for connections to be initiated from external domain, especially those that have not connected in the past.
 # Ports: any
 # Anomaly : Connection from New Domain
 # Volume: ge 100Kb
 

disp "Policy 10: Connection From New External Domain to Internal"



disp "============================="

 #------------------------------------------------
 # 11
 # Policy : Connection To New Domain from Critical Device
 # Src: All Critical Devices
 # Dst: All External Domains
 # Desc: A remote Domain has connected to a device in your network for the first time. It may be unusual for connections to be initiated from external domain, especially those that have not connected in the past.
 # Ports: any
 # Anomaly : Connection to New Domain
 # Volume: ge 100Kb
 

disp "Policy 11: Connection To New Domain from Critical Device"

curl -kv disney.com
sleep 1
curl -kv marvel.com
sleep 1
curl -kv https://releases.hashicorp.com/terraform/1.6.5/terraform_1.6.5_darwin_amd64.zip- -0 /tmp/tform.zip

disp "============================="

 #------------------------------------------------
 # 12
 # Policy : Activity from Blocked Countries
 # Src: Prohibited Countries
 # Dst: All internal Devices
 # Desc: Detect traffic from countries blocked by your firewall
 # Ports: any
 # Conv: TCP NOrmal , UDP Two Way
 # Volume: ge 1Kb
 

disp "Policy 12: Activity from Blocked Countries"

curl -kv https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6/npp.8.6.Installer.x64.exe -o /tmp/npp.exe

disp "============================="

 #------------------------------------------------
 # 13
 # Policy : Anomalous Activity to Blocked Countries
 # Src: All Internal Devices
 # Dst: Prohibited Countries
 # Desc: Detect when any anomalous events are detected communicating to Blocked Countries
 # Ports: any
 # Conv: any
 # Volume: any
 

disp "Policy 13: Anomalous Activity to Blocked Countries"

curl -kv https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6/npp.8.6.Installer.x64.exe -o /tmp/npp.exe

disp "============================="

 #------------------------------------------------
 # 14
 # Policy : Anomalous Activity from Blocked Countries
 # Src: All Internal Devices
 # Dst: Prohibited Countries
 # Desc: Detect when any anomalous events are detected due to communication from Blocked Countries
 # Ports: any
 # Conv: any
 # Volume: any
 

disp "Policy 14:  # Policy : Anomalous Activity from Blocked Countries"

curl -kv https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6/npp.8.6.Installer.x64.exe -o /tmp/npp.exe
sleep 1
curl -kv https://download.sysinternals.com/files/PSTools.zip -o /tmp/pdpst.zip

disp "============================="

 #------------------------------------------------
  # 15
 # Policy : Activity to Blocked Countries
 # Src: All Internal Devices
 # Dst: Prohibited Countries
 # Desc: Detect traffic to countries blocked by your firewall
 # Ports: any
 # Conv: TCP Normal, UDP One and TWo Way
 # Volume: ge 1kb
 

disp "Policy 15:  # Policy : Anomalous Activity from Blocked Countries"

curl -kv https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6/npp.8.6.Installer.x64.exe -o /tmp/npp.exe
sleep 1
curl -kv https://download.sysinternals.com/files/PSTools.zip -o /tmp/pdpst.zip

disp "============================="

 #------------------------------------------------
  # 16
 # Policy : Critical Device to or from Facebook
 # Src: Critical Device
 # Dst: Facebook Domain
 # Desc: Detect when a critical device is communicating with Facebook
 # Ports: any
 # Conv: TCP Normal, UDP TWo Way
 # Volume: ge 1kb
 

disp "Policy 16:  # Policy : Critical Device to or from Facebook"

curl -kv facebook.com
sleep 1
wget -r facebook.com 
disp "============================="

 #------------------------------------------------
  # 17
 # Policy : Detect Internal traffic to or from Facebook
 # Src: internal  Device
 # Dst: Facebook Domain
 # Desc: Detect when anyone is communicating with Facebook
 # Ports: any
 # Conv: TCP Normal, UDP TWo Way
 # Volume: ge 1kb
 

disp "Policy 17:  # Detect Internal traffic to or from Facebook"

curl -kv facebook.com
sleep 1
wget -r facebook.com 
disp "============================="

 #------------------------------------------------
  # 18
 # Policy : Activity to Social Media Sites
 # Src: internal  Device
 # Dst: Social Media Sites
 # Desc: Detect when anyone communicates with a prohibited social media site
 # Ports: any
 # Conv: TCP Normal, UDP TWo Way
 # Volume: ge 1kb
 

disp "Policy 18:  # Activity to Social Media Sites"

wget -r netflix.com
sleep 1
wget -r youtube.com

disp "============================="

 #------------------------------------------------
  # 19
 # Policy : Internal WUDO Traffic
 # Src: internal  Device
 # Dst: Internal Devices
 # Desc: Detects Windows Update Delivery Optimization (WUDO) traffic between devices within your network.
 # Ports: 7680, 3544
 # Conv: TCP Normal, UDP TWo Way, UDP ONe way
 # Volume: ge 1kb
 

disp "Policy 19:  # Internal WUDO Traffic"

trigger $ilvmip 3544 ipfile

disp "============================="

 #------------------------------------------------
  # 20
 # Policy : Unsecured Internal IRC Traffic
 # Src: internal  Device
 # Dst: Internal Devices
 # Desc: IRC Traffic is detected between internal endpoints. This Activity on Unsecure Ports indicates vulnerabilities against ransomware attacks.
 # Ports: 194, 6667, 6668, 6669, 7000
 # Conv: TCP Normal, UDP TWo Way
 # Volume: ge 1kb
 

disp "Policy 20:  # Unsecured Internal IRC Traffic"

trigger $ilvmip 6667 ipfile

disp "============================="

 #------------------------------------------------
  # 21
 # Policy : Unsecured Outbound Telnet Traffic
 # Src: internal  Device
 # Dst: External Devices
 # Desc: Telnet Traffic - port 23 TCP - is detected from internal to external endpoints. This Activity on Unsecure Ports indicates vulnerabilities against ransomware attacks.
 # Ports: 23
 # Conv: TCP Normal, UDP TWo Way
 # Volume: ge 1kb
 

disp "Policy 21:  # Unsecured Outbound Telnet Traffic"

trigger $ilvmip 6667 ipfile

disp "============================="

 #------------------------------------------------
  # 22
 # Policy : WUDO Traffic Crossing Network Boundary
 # Src: Internal  Device
 # Dst: External Devices
 # Desc: Detects Windows Update Delivery Optimization (WUDO) traffic between devices within your network and the public internet.
 # Ports: 7680, 3544
 # Conv: TCP Normal, UDP TWo Way
 # Volume: ge 1kb
 

disp "Policy 22:  # WUDO Traffic Crossing Network Boundary"

trigger $ekvmip 3544 epfile

disp "============================="

 #------------------------------------------------
  # 23
 # Policy : Unauthorized Outbound SSH
 # Src: Internal  Device
 # Dst: External domains
 # Desc: An unauthorized SSH connection has been detected from an internal device to an external domain.
 # Ports: 22
 # Conv: TCP Normal, UDP TWo Way
 # Volume: ge 1kb
 

disp "Policy 23:  # Unauthorized Outbound SSHk"

trigger $ekvmip 3389 epfile

disp "============================="

 #------------------------------------------------
  # 24
 # Policy : Unusual connection count from Critical Devices to External
 # Src: Critical  Device
 # Dst: External domains
 # Desc: The connection count from a Critical Device to an external domain is unusual. This could indicate unauthorized activity to an unusual destination.
 # Ports: any
 # Conv: TCP Normal, UDP TWo Way
 # Volume: ge 1kb
 # Anom: High count of outgoing flows
 

disp "Policy 24:  # Unusual connection count from Critical Devices to External"

nmap google.com/24
sleep 1
nmap facebook.com/24

disp "============================="

 #------------------------------------------------
   # 25
 # Policy : SSH Attempts from Internal to Internal
 # Src: Internal  Device
 # Dst: Internal Devicse
 # Desc: Detect when failed SSH sessions are attempted to be established within your network between two Internal IPs
 # Ports: 22
 # Conv: TCP Normal
 # Volume: ge 1kb
 # Anom: SSH failed authentication
 

disp "Policy 25:  # SSH Attempts from Internal to Internal"

for i in {11..30}; do ip="10.100.11.$i"; sshpass -p "notpassword" ssh -o StrictHostKeychecking=no cyglass@$ip ; done &

disp "============================="

 #------------------------------------------------
  # 26
 # Policy : Outbound SMB Traffic
 # Src: Internal Device
 # Dst: External Org
 # Desc: Server Message Block (SMB) traffic - port 445 TCP - from internal endpoints to public IPs is detected. This is an indicator of possible SMB Leakage, and blocking such activity is part of preventing ransomware attacks.
 # Ports: 445
 # Conv: TCP Normal, UDP Two Way
 # Volume: ge 1kb
 # Anom: 
 
disp "Policy 26:  # Outbound SMB Traffic"

trigger $ekvmip 445 epfile

disp "============================="

 #------------------------------------------------
 
 
#==========================================================================
