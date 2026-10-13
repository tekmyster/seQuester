$ErrorActionPreference = 'Stop'
$rfRoot = Split-Path -Parent $PSScriptRoot
$rfOutput = Join-Path $rfRoot 'test-results\formats'
New-Item -ItemType Directory -Force -Path $rfOutput | Out-Null
$rfWord = $null
$rfDocument = $null
try {
    $rfWord = New-Object -ComObject Word.Application
    $rfWord.Visible = $false
    $rfWord.DisplayAlerts = 0
    $rfWord.AutomationSecurity = 3
    $rfDocument = $rfWord.Documents.Open((Join-Path $rfRoot 'Assets\canary.docx'), $false, $true)
    $rfDocument.ExportAsFixedFormat((Join-Path $rfOutput 'docx-word.pdf'), 17)
    Write-Output 'PASS: Word opened the DOCX read-only and exported a PDF preview.'
} finally {
    if ($null -ne $rfDocument) { $rfDocument.Close(0); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($rfDocument) }
    if ($null -ne $rfWord) { $rfWord.Quit(0); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($rfWord) }
}
$rfExcel = $null
$rfWorkbook = $null
try {
    $rfExcel = New-Object -ComObject Excel.Application
    $rfExcel.Visible = $false
    $rfExcel.DisplayAlerts = $false
    $rfExcel.AutomationSecurity = 3
    $rfWorkbook = $rfExcel.Workbooks.Open((Join-Path $rfRoot 'Assets\canary.xlsx'), 0, $true)
    if ($rfWorkbook.Worksheets.Item(1).Range('D5').Value2 -ne 2) { throw 'XLSX numeric value did not round-trip.' }
    Write-Output 'PASS: Excel opened the XLSX read-only and verified its numeric data.'
} finally {
    if ($null -ne $rfWorkbook) { $rfWorkbook.Close($false); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($rfWorkbook) }
    if ($null -ne $rfExcel) { $rfExcel.Quit(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($rfExcel) }
}
