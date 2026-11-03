$url = "https://dl.google.com/chrome/install/googlechromestandaloneenterprise64.msi"
$wc = New-Object net.webclient
$msiInstaller = "$env:temp\google-chrome.msi"
$wc.Downloadfile($url, $msiInstaller)
$arguments = "/i `"$msiInstaller`" /quiet"
Start-Process msiexec.exe -ArgumentList $arguments -Wait
Remove-Item $msiInstaller
