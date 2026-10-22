Get-ChildItem | Sort-Object Length
$client = New-Object System.Net.Sockets.TcpClient
$client.Connect('db.example.test', 5432)
Write-Host ('open: ' + $client.Connected)
$client.Close()
$Password = Read-Host -AsSecureString
$token = $env:GITHUB_TOKEN
$secure = ConvertTo-SecureString $env:DEPLOY_PW -AsPlainText -Force
$tokenEndpoint = 'https://login.example.test/oauth2/token'
