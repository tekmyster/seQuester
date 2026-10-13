[CmdletBinding()]
param([Parameter(Mandatory)][string]$AssetRoot)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=(Resolve-Path -LiteralPath $AssetRoot).Path
if((Get-FileHash -LiteralPath (Join-Path $root 'brand-assets.json') -Algorithm SHA256).Hash -cne 'B39B0D1F4C48DC33BAB4EF4042FF5ABE9B45D5ED9314AB32EEF2F948EB004CFE'){throw 'Brand manifest differs from the frozen canonical-derived asset set.'}
$manifest=Get-Content -LiteralPath (Join-Path $root 'brand-assets.json') -Raw|ConvertFrom-Json
if($manifest.SourceSha256 -cne 'B517358EA89EF70EA196F0D682573A5512C966721084711966CA7F312FD84C9E'){throw 'Canonical logo source identity differs.'}
$names=@{}
foreach($asset in $manifest.Files){
    if($asset.Path -notmatch '^sequester(?:-original\.jpg|-\d+\.png|\.ico|\.icns)$' -or $names.ContainsKey($asset.Path)){throw 'Unsafe or duplicate brand manifest path.'}
    $names[$asset.Path]=$true;$file=Get-Item -LiteralPath (Join-Path $root $asset.Path)
    if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -ne $asset.Bytes -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne $asset.Sha256){throw 'Branded asset integrity mismatch.'}
}
foreach($required in @('sequester-original.jpg','sequester.ico','sequester.icns','sequester-16.png','sequester-32.png','sequester-128.png','sequester-180.png','sequester-192.png','sequester-256.png','sequester-512.png','sequester-1024.png')){if(!$names.ContainsKey($required)){throw 'Required icon rendition missing.'}}
if((Get-FileHash -LiteralPath (Join-Path $root 'sequester.ico') -Algorithm SHA256).Hash -cne '26627790C3D1748B756751C1EEA6E3FF958A0D4F64B5A309AF3ED94BC2DFB7A1'){throw 'Unreviewed Windows icon.'}
if((Get-FileHash -LiteralPath (Join-Path $root 'sequester.icns') -Algorithm SHA256).Hash -cne 'C79D10FC312CBE22989CECABC126F8560E7C6C6EBB0DC4F8935B6958B80EB2B6'){throw 'Unreviewed macOS icon.'}
[pscustomobject]@{AssetRoot=$root;Files=$names.Count;Integrity='PASS';NativeAppearance='PENDING'}
