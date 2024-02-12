

# ######################################## 
# #######     Server Side to Receive   # # 
# ########################################

cls

$port = 5656 ; $Rname = "$port UDPin"
New-NetFirewallRule -Name $Rname -Enabled True -LocalPort $port -Action Allow -DisplayName $Rname -Direction Inbound -Protocol UDP 

Set-NetFirewallRule -Name $Rname -Enabled False

Set-NetFirewallRule -Name $Rname -Enabled True

Remove-NetFirewallRule -Name $rname 

$port = 5656

$host.UI.RawUI.WindowTitle = "$port UDP Listner!"

  $endpoint = New-Object System.Net.IPEndPoint ([IPAddress]::Any, $port)
  Try {
      while($true) {
          $socket = New-Object System.Net.Sockets.UdpClient $port
          $content = $socket.Receive([ref]$endpoint)
          $socket.Close()
          [Text.Encoding]::ASCII.GetString($content)
          sleep -s 20
      }
  } Catch {
      "$($Error[0])"
  }
