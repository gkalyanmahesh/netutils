#
# sshpass package to be installed on prior
# 
disp()
{ echo $1 ; echo $1 >> /home/cyglass/plog
}
pout()
{ echo "$1 \t - \t $2" >> /home/cyglass/pout
}
echo "" > /home/cyglass/pout

# Azure Kali VM Public IP : 20.223.181.26
ekvmip="20.223.181.26"

#Internal kali vm ip(self ip )
ikvmip="10.100.3.49"

# Internal critical device running linux
ilvmip="10.100.3.35"

disp "============================== $(date)\nAzure kvm ip : $ekvmip \nInternal kvm ip : $ikvmip \nInternal lvm ip : $ilvmip \n"


# 1-ipaddress , 2-port , 3-pfile

trigger() { 
sshpass -f $3 ssh -o StrictHostKeychecking=no cyglass@$1 "python3 -m http.server $2 --directory /home/cyglass" &
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
#==========================================================================