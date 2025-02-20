$url = "https://openpolicyagent.org/downloads/v0.57.1/opa_windows_amd64.exe"
$output = "opa.exe"
Invoke-WebRequest -Uri $url -OutFile $output
