# TEST-ONLY CI INTEGRATION SOURCE. No dispatch, draft creation, publication or cleanup.
# The outer runtime must first bind fresh drafts/privacy, exact commit/run and explicit root GO.
param([Parameter(Mandatory)][string]$BindingBase64,[Parameter(Mandatory)][string]$BindingSha256)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$VerbosePreference='SilentlyContinue';$DebugPreference='SilentlyContinue';$WarningPreference='SilentlyContinue'
Set-StrictMode -Version Latest
function Require($ok){if(-not $ok){throw [InvalidOperationException]::new('FIXED_WINDOWS_WORKFLOW_ADMISSION_REFUSED')}}
function Digest([byte[]]$b){return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($b)).ToLowerInvariant()}
function ExactKeys($v,[string[]]$keys){Require ($v -is [Collections.IDictionary] -and $v.Count -eq $keys.Count);foreach($k in $keys){Require ($v.Keys -ccontains $k)}}
function Integer($n){Require (($n -is [int] -or $n -is [long]) -and $n -gt 0);return [long]$n}
function StrictJson([byte[]]$bytes){
 $d=[Text.Json.JsonDocument]::Parse([ReadOnlyMemory[byte]]::new($bytes),[Text.Json.JsonDocumentOptions]@{MaxDepth=8})
 function Unique($e){if($e.ValueKind -eq 'Object'){$s=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);foreach($p in $e.EnumerateObject()){Require ($s.Add($p.Name));Unique $p.Value}}elseif($e.ValueKind -eq 'Array'){foreach($v in $e.EnumerateArray()){Unique $v}}}
 try{Unique $d.RootElement;return ([Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json -AsHashtable -NoEnumerate)}finally{$d.Dispose()}
}
function Utc($s){Require ($s -is [string] -and $s -cmatch '^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$');return [DateTimeOffset]::ParseExact($s,"yyyy-MM-dd'T'HH:mm:ss'Z'",[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)}
try{
 Require ($IsWindows -and [Environment]::Is64BitProcess -and $PSVersionTable.PSVersion.Major -ge 7)
 Require ($env:GITHUB_REPOSITORY -ceq 'rgin-ds/friends-pk-downloads' -and $env:GITHUB_REPOSITORY_ID -ceq '1433690543' -and $env:GITHUB_EVENT_NAME -ceq 'workflow_dispatch' -and $env:GITHUB_RUN_ATTEMPT -ceq '1' -and $env:GITHUB_RUN_ID -cmatch '^[1-9][0-9]{0,18}$')
 Require ($BindingBase64.Length -le 16384 -and $BindingSha256 -cmatch '^[a-f0-9]{64}$');$raw=[Convert]::FromBase64String($BindingBase64)
 Require ($raw.Length -le 8192 -and (Digest $raw) -ceq $BindingSha256);$b=StrictJson $raw
 ExactKeys $b @('schemaVersion','nonce','repositoryId','workflowCommit','workflowRef','admissionNotBeforeUTC','dispatchNotAfterUTC','jobNotAfterUTC','rootGoSHA256','inputReleaseId','inputAssetId','inputZipBytes','inputZipSHA256','outputReleaseId','codeSHA256','inputPinsSHA256','baselineSourceFreezeSHA256','compiledClasses')
 Require ($b.schemaVersion -eq 1 -and $b.nonce -ceq '6e8f70b7fa18b0979d88e19260f9fbe5' -and $b.repositoryId -eq 1433690543 -and $b.workflowCommit -cmatch '^[a-f0-9]{40}$' -and $b.workflowCommit -ceq $env:GITHUB_SHA -and $b.workflowRef -ceq $env:GITHUB_WORKFLOW_REF -and $b.workflowRef.StartsWith('rgin-ds/friends-pk-downloads/.github/workflows/private-font-constructor-20261028-01.yml@refs/heads/'))
 Require ($b.rootGoSHA256 -cmatch '^[a-f0-9]{64}$' -and $b.rootGoSHA256 -cne ('0'*64))
 foreach($k in @('inputReleaseId','inputAssetId','outputReleaseId')){$null=Integer $b[$k]};Require ($b.inputReleaseId -ne $b.outputReleaseId)
 $null=Integer $b.inputZipBytes;Require ($b.inputZipBytes -le 196608 -and $b.inputZipSHA256 -cmatch '^[a-f0-9]{64}$' -and $b.inputZipSHA256 -cne ('0'*64))
 Require ($b.inputPinsSHA256 -is [string] -and $b.inputPinsSHA256 -cmatch '^[a-f0-9]{64}$' -and $b.inputPinsSHA256 -cne ('0'*64) -and $b.baselineSourceFreezeSHA256 -ceq '494303507d083eff6ba68d69512bfab4c9c83ef560864edb05c9803ffe1eb399')
 ExactKeys $b.compiledClasses @('com/osroyale/ChatGlyphs.class','com/osroyale/Client$Provider.class','com/osroyale/Client.class','com/osroyale/PortableFontConstructorProbe$Input.class','com/osroyale/PortableFontConstructorProbe.class','com/osroyale/Rasterizer2D.class','com/osroyale/UiGlyphs.class')
 foreach($c in $b.compiledClasses.Keys){$f=$b.compiledClasses[$c];ExactKeys $f @('bytes','sha256');$n=Integer $f.bytes;Require ($n -le 32768 -and $n -ge 8 -and $f.sha256 -is [string] -and $f.sha256 -cmatch '^[a-f0-9]{64}$' -and $f.sha256 -cne ('0'*64))}
 $start=Utc $b.admissionNotBeforeUTC;$end=Utc $b.dispatchNotAfterUTC;$close=Utc $b.jobNotAfterUTC;$now=[DateTimeOffset]::UtcNow
 Require ($now -ge $start -and $now -le $end -and ($end-$start).TotalSeconds -le 900 -and ($close-$now).TotalSeconds -ge 510 -and ($close-$now).TotalSeconds -le 1200)
 $pins=@{'Worker.ps1'='859d3d0d1ab0c4d47694d25044f8eb7284baf4d39a7d252cc15fcf00735945cf';'WinGuard.cs'='1ad5090fd4098dc358c1bb9e2d78b4c1d8d1c4df90d0df2695e7f165a435bbcb';'Signal.ps1'='27e0d1a78624675e0be4e56a79b51e668d42535a36f5a8e2cb2fc338281daf11'}
 ExactKeys $b.codeSHA256 @('Worker.ps1','WinGuard.cs','Signal.ps1');foreach($n in $pins.Keys){Require ($b.codeSHA256[$n] -ceq $pins[$n] -and (Digest ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $n)))) -ceq $pins[$n])}
 Require ((Digest ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'OriginalWorker.ps1')))) -ceq '47336dc39a0175aa0be6493db816ab066237ca872a1fcc071fd165abd067aa44')
 Require ((Digest ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'NamespaceShapeControls.ps1')))) -ceq 'eb09f3cdb16701fa69c69e30f6ce491b36c0b00e3b20bb0319823b36b7616e65')
 $result=@(& (Join-Path $PSScriptRoot 'NamespaceShapeControls.ps1') -OriginalWorker (Join-Path $PSScriptRoot 'OriginalWorker.ps1') -CorrectedWorker (Join-Path $PSScriptRoot 'Worker.ps1'))
 Require ($result.Count -eq 1 -and $result[0] -ceq 'PASS_WINDOWS_NAMESPACE_SHAPE checks=13')
 Require (($close-[DateTimeOffset]::UtcNow).TotalSeconds -ge 510)
 # No code/credentials/private payload are inserted in this binding. Worker owns protection/audits.
 $workerBinding=[ordered]@{schemaVersion=1;nonce=$b.nonce;repositoryId=1433690543;runId=[long]$env:GITHUB_RUN_ID;runAttempt=1;workflowCommit=$env:GITHUB_SHA;inputReleaseId=$b.inputReleaseId;inputAssetId=$b.inputAssetId;inputZipBytes=$b.inputZipBytes;inputZipSHA256=$b.inputZipSHA256;outputReleaseId=$b.outputReleaseId;codeSHA256=$pins;inputPinsSHA256=$b.inputPinsSHA256;baselineSourceFreezeSHA256=$b.baselineSourceFreezeSHA256;compiledClasses=$b.compiledClasses}
 $data=[Text.Encoding]::UTF8.GetBytes(($workerBinding|ConvertTo-Json -Depth 4 -Compress));$path=Join-Path $PSScriptRoot 'run-binding.json'
 $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$file.Write($data,0,$data.Length)}finally{$file.Dispose()}
 Write-Host 'WINDOWS_SOURCE_SHAPE_CONTROLS_PASS checks=13'
 # Exactly one worker call. Its mandatory PureControls()==24 precedes private transfer/JVM.
 # Its private receipt, exact process/Job closure, preservation and draft-only output remain authoritative.
 $global:LASTEXITCODE=0
 & (Join-Path $PSScriptRoot 'Worker.ps1') -BindingPath $path -BindingSha256 (Digest $data)
 if($LASTEXITCODE -ne 0){exit 1}
 exit 0
} catch {Write-Host 'WINDOWS_FONT_WORKFLOW_ADMISSION_REFUSED';exit 1}
