Write-Host "🔍 Starting DLL scan..." -ForegroundColor Cyan

# Define folders to scan
$folders = @(
    "$env:USERPROFILE\AppData\Local",
    "$env:USERPROFILE\AppData\Roaming",
    "$env:USERPROFILE\AppData\Temp",
    "C:\Windows\Temp",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Windows\System32",
    "C:\Windows\SysWOW64"
)

# Create an empty array to store results
$dllReport = @()

foreach ($folder in $folders) {
    if (Test-Path $folder) {
        Write-Host "📁 Scanning: $folder" -ForegroundColor Yellow
        Get-ChildItem -Path $folder -Recurse -Filter *.dll -ErrorAction SilentlyContinue | ForEach-Object {
            $sig = Get-AuthenticodeSignature $_.FullName
            $dllReport += [PSCustomObject]@{
                FilePath = $_.FullName
                Status   = $sig.Status
                Signer   = $sig.SignerCertificate.Subject
            }
        }
    } else {
        Write-Host "⚠️ Folder not found: $folder" -ForegroundColor Red
    }
}

# Filter suspicious entries
$suspicious = $dllReport | Where-Object {
    $_.Status -ne 'Valid' -or (
        $_.Signer -notmatch 'Microsoft' -and
        $_.Signer -notmatch 'NVIDIA'
    )
}

Write-Host "`n✅ Scan complete. Found $($suspicious.Count) suspicious DLL(s)." -ForegroundColor Green
Write-Host "🔎 Total DLLs scanned: $($dllReport.Count)"

$saveFolder = Read-Host "Please input the folder path to save your results"
if (-not (Test-Path $saveFolder)) {
    Write-Host "❌ Invalid path. Please make sure the folder exists." -ForegroundColor Red
    return
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = Join-Path $saveFolder "DLLSniffer_Report_$timestamp.csv"

$suspicious | Format-Table -AutoSize
$suspicious | Export-Csv $reportPath -NoTypeInformation

Write-Host "📄 Report saved to: $reportPath" -ForegroundColor Cyan
