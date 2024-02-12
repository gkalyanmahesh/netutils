# create while loop to continuously send udp packets

# Define port and target IP address 

[int] $Port = 2055 
$IP = "10.100.3.42" 
$Address = [system.net.IPAddress]::Parse($IP) 
$proto = "UDP"

# Create IP Endpoint 
$End = New-Object System.Net.IPEndPoint $address, $port 

# Create Socket 
$Saddrf   = [System.Net.Sockets.AddressFamily]::InterNetwork 
$Stype    = [System.Net.Sockets.SocketType]::Dgram 
$Ptype    = [System.Net.Sockets.ProtocolType]::$proto 
$Sock     = New-Object System.Net.Sockets.Socket $saddrf, $stype, $ptype 
$Sock.TTL = 26 

# Connect to socket 
$sock.Connect($end) 

# Create encoded buffer 
$Enc     = [System.Text.Encoding]::ASCII 
$Message = "From `t`t`t $(hostname) `nTo Server `t`t $ip `nOver Port `t`t $port `nProtocol `t`t $proto `nAt  Time `t`t $(get-date)`n$('*'*30)`n" 
$Buffer  = $Enc.GetBytes($Message) 

# Send the buffer 
$Sent   = $Sock.Send($Buffer) 
"{0} characters sent to: {1} " -f $Sent,$IP 
"Message is:" 
$Message 
