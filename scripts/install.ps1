param(
  [Parameter(Mandatory=$true)][string]$Version,
  [string]$InstallDir = "$HOME\AppData\Local\Caphe\bin",
  [string]$ReleaseBaseUrl = "https://github.com/andrew-ships-stuff/caphe/releases/download"
)
$ErrorActionPreference = "Stop"
$arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
  "X64" { "amd64" }
  "Arm64" { "arm64" }
  default { throw "Unsupported architecture" }
}
$archive = "caphe_${Version}_windows_${arch}.zip"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("caphe-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tempDir | Out-Null
try {
  Invoke-WebRequest "$ReleaseBaseUrl/$Version/$archive" -OutFile "$tempDir\$archive"
  Invoke-WebRequest "$ReleaseBaseUrl/$Version/checksums.txt" -OutFile "$tempDir\checksums.txt"
  $line = Select-String -Path "$tempDir\checksums.txt" -Pattern "  $([regex]::Escape($archive))$"
  if (-not $line) { throw "Checksum entry missing" }
  $expected = ($line.Line -split '\s+')[0].ToLowerInvariant()
  $actual = (Get-FileHash "$tempDir\$archive" -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw "Checksum mismatch" }
  Expand-Archive "$tempDir\$archive" -DestinationPath $tempDir
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item "$tempDir\caphe.exe" "$InstallDir\caphe.exe" -Force
  & "$InstallDir\caphe.exe" version
  Write-Host "Installed Caphe to $InstallDir\caphe.exe"
  Write-Host "CPU inference is not installed automatically."
} finally {
  Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
}
