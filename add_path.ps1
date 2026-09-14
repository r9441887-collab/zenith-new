param(
    [string]$Dir
)
# Add $Dir to the current user's PATH (HKCU\Environment), without duplicates.
# Uses HKCU registry (no admin rights needed). New terminals will resolve `zenith`.
if (-not $Dir) { Write-Error "no dir"; exit 1 }
$Dir = [string]$Dir.TrimEnd('\')

$keyPath = 'HKCU:\Environment'
if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }

$cur = ''
try { $cur = [string](Get-ItemPropertyValue -Path $keyPath -Name 'Path') } catch { $cur = '' }
if ($null -eq $cur) { $cur = '' }

$parts = @()
foreach ($e in ($cur -split ';')) { if ($e -ne '') { $parts += $e } }

$exists = $false
$low = $Dir.ToLower()
foreach ($e in $parts) {
    if ($e.ToLower() -eq $low) { $exists = $true }
}

if (-not $exists) {
    $parts += $Dir
    $new = $parts -join ';'
    try {
        Set-ItemProperty -Path $keyPath -Name 'Path' -Value $new
        Write-Output "PATH updated (added $Dir). entries=$($parts.Count)"
    } catch {
        Write-Error "failed to set Path: $_"; exit 1
    }
} else {
    Write-Output "already in PATH. entries=$($parts.Count)"
}
exit 0