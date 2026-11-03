$blob = "aGVsbG8gd29ybGQ="
$code = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob))
Invoke-Expression $code
