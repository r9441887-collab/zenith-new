param(
    [string]$Root,
    [string]$Release
)
$src = Get-ChildItem -LiteralPath $Root -Directory |
    Where-Object { $_.Name -notin @('build','src','libs','release','disasm_console') } |
    Select-Object -First 1
if (-not $src) {
    Write-Error "documentation folder not found under $Root"
    exit 1
}
Copy-Item -LiteralPath $src.FullName -Destination (Join-Path $Release $src.Name) -Recurse -Force
Write-Output "copied documentation: $($src.Name)"
