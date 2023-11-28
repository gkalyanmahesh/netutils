
curl https://download.sysinternals.com/files/PSTools.zip -o /tmp/spst.zip

sleep -s 30

#fast internet horizontal port scan
echo "Internal Horizontal Scan - $(date)" >> /home/cyglass/scanlog.log
nmap 192.168.50.175-240 -p1111 -T4 -A -Pn  

sleep 120

#fast internet vertical port scan
echo "Internal Vertical Scan - $(date)" >> /home/cyglass/scanlog.log
nmap 192.168.50.111 -p100-3390 -T4 -A -Pn  

sleep 120

# external vertical scan
echo "External Vertical Scan - $(date)" >> /home/cyglass/scanlog.log
nmap scanme.nmap.org -T4 -A -p111-1111

sleep 120

# external horizontal scan
echo "External Horizontal Scan - $(date)" >> /home/cyglass/scanlog.log
nmap microsoft.com/24 -T4 -Pn -p443


#External lengthy scan
nmap google.com/24 





