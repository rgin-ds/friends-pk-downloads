# TEST ONLY / LOCAL SOURCE. Runtime must bind and review exact workflow + fresh private draft IDs.
param([Parameter(Mandatory)][string]$BindingPath,[Parameter(Mandatory)][string]$BindingSha256)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$VerbosePreference='SilentlyContinue'
$DebugPreference='SilentlyContinue';$InformationPreference='SilentlyContinue';$WarningPreference='SilentlyContinue'
Set-StrictMode -Version Latest
$clock=[Diagnostics.Stopwatch]::StartNew();$stage='ADMISSION';$root=$null;$probe=$null;$before=$null;$after=$null;$token=$null;$dirsBefore=@{};$codePins=@{};$expected=@{};$jrePins=@{};$pins=$null;$runtime=$null;$validated=$null
$receipt=[ordered]@{schemaVersion=1;status='FAIL';productionEligible=$false;probeScope='CONSTRUCTOR_ONLY_NOT_GAME_DPI';closed=$false;inputPreserved=$false;outputsComplete=$false;providerAdministratorBoundary=$true}
function Need($ok,[string]$code){if(-not $ok){throw [InvalidOperationException]::new($code)}}
function Remain([int]$phase){$left=480000-$clock.ElapsedMilliseconds;Need ($left -gt 30000) 'CONTROLLER_RESERVE';return [int][Math]::Min($phase*1000,$left-30000)}
function Hash([byte[]]$b){return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($b)).ToLowerInvariant()}
function ReadBound([string]$p,[int]$cap){$s=$null;$b=[FontWinGuard]::Read($p,$cap,[ref]$s);return ,$b}
function JSON([byte[]]$bytes){
 $doc=[Text.Json.JsonDocument]::Parse([ReadOnlyMemory[byte]]::new($bytes),[Text.Json.JsonDocumentOptions]@{MaxDepth=32})
 function Walk($e,[int]$depth){Need ($depth -le 32) 'JSON_DEPTH';if($e.ValueKind -eq 'Object'){$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);foreach($p in $e.EnumerateObject()){Need ($seen.Add($p.Name)) 'JSON_DUPLICATE';Walk $p.Value ($depth+1)}}elseif($e.ValueKind -eq 'Array'){foreach($v in $e.EnumerateArray()){Walk $v ($depth+1)}}}
 try{Walk $doc.RootElement 0;return ([Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json -AsHashtable -NoEnumerate)}finally{$doc.Dispose()}
}
function Keys($v,[string[]]$names){Need ($v -is [Collections.IDictionary] -and $v.Count -eq $names.Count) 'EXACT_KEYS';foreach($n in $names){Need ($v.Keys -ccontains $n) 'MISSING_KEY'}}
function Number($v,[long]$lo,[long]$hi){Need (($v -is [int] -or $v -is [long] -or $v -is [bigint]) -and $v -ge $lo -and $v -le $hi) 'TYPED_INTEGER';return [long]$v}
function Api([string]$path){return JSON (Fetch ('https://api.github.com/repos/rgin-ds/friends-pk-downloads'+$path) 131072 30 $true 'application/vnd.github+json' $null 0)}
function Fetch([string]$url,[int]$cap,[int]$seconds,[bool]$auth,[string]$accept,[byte[]]$body,[int]$redirects){
 $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.AutomaticDecompression=[Net.DecompressionMethods]::None
 $http=[Net.Http.HttpClient]::new($handler);$http.Timeout=[Threading.Timeout]::InfiniteTimeSpan;$cts=[Threading.CancellationTokenSource]::new((Remain $seconds));$response=$null
 try{
  $u=[Uri]$url;Need ($u.Scheme -eq 'https' -and $u.Port -eq 443 -and -not $u.UserInfo -and -not $u.Fragment) 'HTTPS_ROUTE'
  $hostName=$u.DnsSafeHost.ToLowerInvariant();Need ($hostName -in @('api.github.com','uploads.github.com','github.com','release-assets.githubusercontent.com','objects.githubusercontent.com')) 'HTTP_HOST'
  Need (-not $auth -or $hostName -in @('api.github.com','uploads.github.com')) 'AUTH_AUDIENCE'
  $request=[Net.Http.HttpRequestMessage]::new($(if($null -eq $body){[Net.Http.HttpMethod]::Get}else{[Net.Http.HttpMethod]::Post}),$u)
  try{
   $request.Headers.UserAgent.ParseAdd('private-font-constructor/1');$request.Headers.Accept.ParseAdd($accept);$request.Headers.AcceptEncoding.ParseAdd('identity')
   if($auth){$request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$token);$request.Headers.Add('X-GitHub-Api-Version','2022-11-28')}
   if($null -ne $body){$request.Content=[Net.Http.ByteArrayContent]::new($body);$request.Content.Headers.ContentType=[Net.Http.Headers.MediaTypeHeaderValue]::new('application/zip')}
   $response=$http.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cts.Token).GetAwaiter().GetResult()
   $code=[int]$response.StatusCode
   if($code -in @(301,302,303,307,308)){
    Need ($null -eq $body -and $redirects -eq 1 -and $response.Headers.Location.IsAbsoluteUri) 'ONE_GET_REDIRECT'
    $next=$response.Headers.Location;Need ($next.Scheme -eq 'https' -and $next.DnsSafeHost -in @('release-assets.githubusercontent.com','objects.githubusercontent.com') -and $next.Port -eq 443 -and -not $next.UserInfo -and -not $next.Fragment) 'SIGNED_ASSET_HOST'
    # Keep the same absolute phase CTS over both requests; no recursive timeout renewal.
    $response.Dispose();$response=$null;$request.Dispose();$request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get,$next)
    $request.Headers.UserAgent.ParseAdd('private-font-constructor/1');$request.Headers.AcceptEncoding.ParseAdd('identity')
    $response=$http.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cts.Token).GetAwaiter().GetResult();$code=[int]$response.StatusCode
   }
   Need ($code -eq $(if($null -eq $body){200}else{201})) 'HTTP_STATUS'
   $encoding=[string]::Join(',',@($response.Content.Headers.ContentEncoding));Need (-not $encoding -or $encoding -ceq 'identity') 'IDENTITY_ENCODING'
   if($null -ne $response.Content.Headers.ContentLength){Need ($response.Content.Headers.ContentLength -le $cap) 'HEADER_CAP'}
   $stream=$response.Content.ReadAsStreamAsync($cts.Token).GetAwaiter().GetResult();$data=[IO.MemoryStream]::new()
   try{$b=[byte[]]::new(65536);while(($n=$stream.ReadAsync($b,0,$b.Length,$cts.Token).GetAwaiter().GetResult()) -gt 0){Need ($data.Length+$n -le $cap) 'BODY_CAP';$data.Write($b,0,$n)};return ,$data.ToArray()}finally{$stream.Dispose();$data.Dispose()}
  }finally{$request.Dispose()}
 }finally{if($null -ne $response){$response.Dispose()};$cts.Dispose();$http.Dispose();$handler.Dispose()}
}
function Draft([long]$id,[string]$tag,[long]$assetId,[long]$assetBytes,[string]$assetSHA){
 $r=Api ('/releases/'+$id);Need ($r.id -eq $id -and $r.tag_name -ceq $tag -and $r.draft -is [bool] -and $r.draft -and -not $r.prerelease) 'EXACT_PRIVATE_DRAFT'
 if($assetId -eq 0){Need ($r.assets.Count -eq 0) 'FRESH_OUTPUT_DRAFT'}else{
  Need ($r.assets.Count -eq 1) 'EXACT_INPUT_ASSET_COUNT';$a=$r.assets[0]
  Need ($a.id -eq $assetId -and $a.name -ceq 'font-probe-input.zip' -and $a.size -eq $assetBytes -and $a.digest -ceq ('sha256:'+$assetSHA)) 'EXACT_INPUT_ASSET'
 };return $r
}
function NewDir([string]$p){[FontWinGuard]::Mkdir($p)}
function MakeParents([string]$rootPath,[string]$relative){
 $parts=$relative.Split('/');$p=$rootPath;for($i=0;$i -lt $parts.Length-1;$i++){[FontWinGuard]::Leaf($parts[$i]);$p=Join-Path $p $parts[$i];if(-not [IO.Directory]::Exists($p)){NewDir $p}else{$null=[FontWinGuard]::AuditDirectory($p)}}
}
function Extract([byte[]]$zip,[string]$dest,$expected,[string]$prefix,[long]$maxBytes){
 $allNames=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$allowedDirs=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);if($prefix){$null=$allowedDirs.Add($prefix);foreach($path in $expected.Keys){$bits=$path.Split('/');$rel=$prefix;for($i=0;$i -lt $bits.Length-1;$i++){$rel+=$bits[$i]+'/';$null=$allowedDirs.Add($rel)}}}
 $mem=[IO.MemoryStream]::new($zip,$false);$z=[IO.Compression.ZipArchive]::new($mem,[IO.Compression.ZipArchiveMode]::Read,$false);$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$sum=0L
 try{foreach($entry in $z.Entries){
  Need ($allNames.Add($entry.FullName)) 'ZIP_DUPLICATE_OR_CASE_ALIAS'
  $attrs=[uint32]([long]$entry.ExternalAttributes -band 0xffffffffL);$type=($attrs -shr 16) -band 0xf000;Need (($attrs -band 0x400) -eq 0) 'ZIP_NO_REPARSE'
  if($entry.FullName.EndsWith('/')){Need ($type -in @(0,0x4000)) 'ZIP_DIRECTORY_TYPE';Need ($prefix -and $entry.Length -eq 0 -and $allowedDirs.Contains($entry.FullName)) 'ZIP_DIRECTORY';continue}
  Need ($entry.FullName.StartsWith($prefix,[StringComparison]::Ordinal)) 'ZIP_PREFIX';$name=$entry.FullName.Substring($prefix.Length)
  Need (($expected.Keys -ccontains $name) -and $seen.Add($name)) 'ZIP_EXACT_MEMBER';foreach($part in $name.Split('/')){[FontWinGuard]::Leaf($part)}
  $attrs=[uint32]([long]$entry.ExternalAttributes -band 0xffffffffL);$type=($attrs -shr 16) -band 0xf000
  Need ($type -in @(0,0x8000) -and ($attrs -band 0x400) -eq 0) 'ZIP_NO_SPECIAL'
  $pin=$expected[$name];Need ($entry.Length -eq $pin.bytes) 'ZIP_MEMBER_SIZE';$sum+=$entry.Length;Need ($sum -le $maxBytes) 'ZIP_SUM'
  $stream=$entry.Open();$data=[IO.MemoryStream]::new();try{$buffer=[byte[]]::new(65536);while(($n=$stream.Read($buffer,0,$buffer.Length)) -gt 0){Need ($data.Length+$n -le $pin.bytes) 'ZIP_INFLATE_CAP';$data.Write($buffer,0,$n)};$bytes=$data.ToArray()}finally{$stream.Dispose();$data.Dispose()}
  Need ($bytes.Length -eq $pin.bytes -and (Hash $bytes) -ceq $pin.sha256) 'ZIP_MEMBER_HASH';MakeParents $dest $name;[FontWinGuard]::WriteNew((Join-Path $dest $name.Replace('/','\')),$bytes)
 };Need ($seen.Count -eq $expected.Count) 'ZIP_ALL_MEMBERS'}finally{$z.Dispose();$mem.Dispose()}
}
function AuditSet([string]$base,$pins,[int]$cap){
 $seen=[Collections.Generic.HashSet[string]]::new();$facts=[ordered]@{};$allowedDirs=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($name in $pins.Keys){$parts=$name.Split('/');$rel='';for($i=0;$i -lt $parts.Length-1;$i++){$rel=if($rel){$rel+'/'+$parts[$i]}else{$parts[$i]};$null=$allowedDirs.Add($rel)}}
 $queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue('');$count=0
 while($queue.Count -gt 0){$rel=$queue.Dequeue();$parent=if($rel){Join-Path $base $rel.Replace('/','\')}else{$base}
  $d=[FontWinGuard]::AuditDirectory($parent);Need ($seen.Add($d.id)) 'DIRECTORY_ALIAS';$facts['D:'+$rel]=$d
  foreach($path in [IO.Directory]::EnumerateFileSystemEntries($parent)){
   $count++;Need ($count -le 1000) 'EXACT_TREE_CAP';$name=if($rel){$rel+'/'+[IO.Path]::GetFileName($path)}else{[IO.Path]::GetFileName($path)}
   $attr=[IO.File]::GetAttributes($path);Need (($attr -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'TREE_NO_REPARSE'
   if(($attr -band [IO.FileAttributes]::Directory) -ne 0){Need ($allowedDirs.Contains($name)) 'NO_EXTRA_DIRECTORY';$queue.Enqueue($name)}else{
    Need ($pins.Keys -ccontains $name) 'NO_EXTRA_FILE';$stamp=$null;$null=[FontWinGuard]::Read($path,$cap,[ref]$stamp);$pin=$pins[$name]
    Need ($stamp.bytes -eq $pin.bytes -and $stamp.sha256 -ceq $pin.sha256 -and $seen.Add($stamp.id)) 'PINNED_IDENTITY_HASH';$facts['F:'+$name]=$stamp
   }
  }
 };Need ($facts.Count -eq $pins.Count+$allowedDirs.Count+1) 'EXACT_TREE_COUNT';return $facts
}
function ValidateInputs([string]$dir){
 $meta=JSON (ReadBound (Join-Path $dir 'font-inputs.json') 8192);Keys $meta @('schemaVersion','kind','sourceCommit','titleArchiveSha256','fonts')
 Need ($meta.schemaVersion -eq 1 -and $meta.kind -ceq 'native-font-creation-inputs' -and $meta.sourceCommit -ceq $pins.sourceCommit -and $meta.titleArchiveSha256 -ceq $pins.titleSHA256 -and $meta.fonts.Count -eq 3) 'FONT_INPUT_SCHEMA'
 $i=0;foreach($name in @('p11_full','p12_full','b12_full')){
  $font=$meta.fonts[$i++];Keys $font @('name','metricsFile','metricsBytes','metricsSha256','masksFile','masksBytes','masksSha256','nativeBaseline','capInkFeet','baselineOffset','rowTop','rowBottom')
  Need ($font.name -ceq $name -and $font.metricsFile -ceq ($name+'-metrics.csv') -and $font.masksFile -ceq ($name+'-native-masks.bin') -and $font.capInkFeet.Count -eq 4) 'EXACT_FONT_NAMES'
  $csv=ReadBound (Join-Path $dir $font.metricsFile) 8192;$masks=ReadBound (Join-Path $dir $font.masksFile) 32768
  Need ($csv.Length -eq (Number $font.metricsBytes 1 8192) -and (Hash $csv) -ceq $font.metricsSha256 -and $masks.Length -eq (Number $font.masksBytes 1 32768) -and (Hash $masks) -ceq $font.masksSha256) 'FONT_INPUT_HASH'
  $lines=(Text $csv).Split("`n");Need ($lines.Count -eq 258 -and $lines[0] -ceq 'code,width,height,xOffset,yOffset,advance,baseline' -and $lines[257] -ceq '') 'INPUT_CSV_ROWS'
  $base=Number $font.nativeBaseline 1 64;$at=0;$top=0;$bottom=0;$feet=@()
  for($c=0;$c -lt 256;$c++){$v=$lines[$c+1].Split(',');Need ($v.Count -eq 7 -and $v[0] -ceq [string]$c) 'INPUT_CSV_CODE';$values=@()
   foreach($j in 1..6){Need ($v[$j] -cmatch '^(0|[1-9][0-9]{0,2})$') 'INPUT_CSV_INTEGER';$n=[int]$v[$j];Need ($n -le $(if($j -le 2){32}else{64})) 'INPUT_METRIC_RANGE';$values+=$n}
   Need ($values[5] -eq $base) 'INPUT_REPEAT_BASELINE';$w=$values[0];$h=$values[1];$y=$values[3];$size=$w*$h;Need ($at+$size -le $masks.Length) 'INPUT_SLICE'
   if($c -in @(72,73,77,88)){$foot=-1;for($py=0;$py -lt $h;$py++){for($px=0;$px -lt $w;$px++){if($masks[$at+$py*$w+$px] -ne 0){$foot=$py}}};$feet+=($foot+$y-$base+1)}
   if($c -ge 32 -and $c -lt 128){$top=[Math]::Min($top,$y-$base);$bottom=[Math]::Max($bottom,$y+$h-$base)};$at+=$size
  }
  Need ($at -eq $masks.Length -and $font.capInkFeet.Count -eq 4) 'INPUT_SLICE_SUM';for($k=0;$k -lt 4;$k++){Need ((Number $font.capInkFeet[$k] -64 64) -eq $feet[$k]) 'INPUT_REAL_HIMX'}
  Need ((Number $font.baselineOffset -64 64) -eq $feet[0] -and @($feet|Select-Object -Unique).Count -eq 1 -and (Number $font.rowTop -64 64) -eq $top -and (Number $font.rowBottom -64 64) -eq $bottom) 'INPUT_COMMON_BASELINE_ROWS'
 }
}
function Preserved($a,$b){Need ($a.Count -eq $b.Count) 'PRESERVE_COUNT';foreach($k in $a.Keys){Need ($b.Contains($k) -and $a[$k].Same($b[$k])) 'PRESERVE_EXACT'} }
function Tree([string]$p,[int]$depth,[ref]$nodes){
 Need ($depth -le 8) 'NAMESPACE_DEPTH';$facts=@();foreach($child in [IO.Directory]::EnumerateFileSystemEntries($p)){
  $nodes.Value++;Need ($nodes.Value -le 128) 'NAMESPACE_NODES';$attr=[IO.File]::GetAttributes($child);Need (($attr -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'NAMESPACE_REPARSE';$dir=($attr -band [IO.FileAttributes]::Directory) -ne 0
  [FontWinGuard]::ProtectOutput($child,$dir)
  if($dir){$s=[FontWinGuard]::AuditDirectory($child);$facts+=@{name=[IO.Path]::GetFileName($child);directory=$true;id=$s.id;children=@(Tree $child ($depth+1) $nodes)}}else{$s=$null;$null=[FontWinGuard]::Read($child,32768,[ref]$s);$facts+=@{name=[IO.Path]::GetFileName($child);directory=$false;id=$s.id;bytes=$s.bytes;sha256=$s.sha256}}
 };return ,$facts
}
function Text([byte[]]$b){return [Text.UTF8Encoding]::new($false,$true).GetString($b)}
function ValidateOutputs([string]$dir){
 $names=@('constructor-evidence.json');foreach($f in @('p11_full','p12_full','b12_full')){$names+=($f+'-constructor-1.0x.png'),($f+'-fallbacks.csv')}
 $got=@([IO.Directory]::EnumerateFileSystemEntries($dir));Need ($got.Count -eq 7) 'OUTPUT_SEVEN';[FontWinGuard]::ProtectOutput($dir,$true);$total=0;$facts=[ordered]@{};$contents=@{}
 foreach($p in $got){$name=[IO.Path]::GetFileName($p);Need ($name -cin $names) 'FIXED_OUTPUT_NAME';[FontWinGuard]::ProtectOutput($p,$false);$s=$null;$b=[FontWinGuard]::Read($p,262144,[ref]$s);$total+=$b.Length;Need ($total -le 1048576) 'OUTPUT_SUM';$facts[$name]=$s;$contents[$name]=$b}
 $e=JSON $contents['constructor-evidence.json'];Keys $e @('diagnosticFontSource','productionEligible','status','sourceCommit','titleSHA256','inputManifestSHA256','java','javaVendor','os','fonts','qualification')
 Need ($e.productionEligible -is [bool] -and -not $e.productionEligible -and $e.diagnosticFontSource -ceq 'bd8a1a378cecc6fff1ca4dbcc35281ed2529d7f1' -and $e.sourceCommit -ceq $pins.sourceCommit -and $e.titleSHA256 -ceq $pins.titleSHA256 -and $e.inputManifestSHA256 -ceq $pins.inputManifestSHA256 -and $e.java -ceq '11.0.32.1' -and $e.os.StartsWith('Windows') -and $e.fonts.Count -eq 3) 'OUTPUT_PROVENANCE'
 $i=0;foreach($name in @('p11_full','p12_full','b12_full')){
  $png=$contents[$name+'-constructor-1.0x.png'];Need ($png.Length -le 262144 -and $png.Length -ge 33 -and [Convert]::ToHexString([byte[]]$png[0..7]) -ceq '89504E470D0A1A0A' -and [BitConverter]::ToUInt32([byte[]]@($png[19],$png[18],$png[17],$png[16]),0) -eq 720 -and [BitConverter]::ToUInt32([byte[]]@($png[23],$png[22],$png[21],$png[20]),0) -eq 240) 'PNG_DIMENSIONS'
  $csv=$contents[$name+'-fallbacks.csv'];Need ($csv.Length -le 32768) 'CSV_CAP';$lines=(Text $csv).Split("`n");Need ($lines.Count -eq 258 -and $lines[0] -ceq 'code,natural,width,height,bearingX,bearingY,reason' -and $lines[257] -ceq '') 'CSV_SCHEMA'
  $natural=0;$fallback=0;$common=0;for($c=0;$c -lt 256;$c++){$v=$lines[$c+1].Split(',');Need ($v.Count -eq 7 -and $v[0] -ceq [string]$c -and $v[1] -cin @('true','false')) 'CSV_CODE'
   foreach($j in 2..5){Need ($v[$j] -cmatch '^-?(0|[1-9][0-9]{0,2})$' -and ([int]$v[$j]).ToString([Globalization.CultureInfo]::InvariantCulture) -ceq $v[$j] -and [int]$v[$j] -ge $(if($j -eq 5){-64}else{0}) -and [int]$v[$j] -le 64) 'CSV_BOUNDS'}
   Need ($v[6] -cin @('natural','native blank','native control artwork','font unsupported','font blank for native ink','natural width plus shadow exceeds native advance','natural glyph exceeds common native row')) 'CSV_REASON'
   if($v[1] -ceq 'true'){Need ($v[6] -ceq 'natural') 'NATURAL_REASON';$natural++}else{$fallback++;if(($c -ge 48 -and $c -le 57) -or ($c -ge 65 -and $c -le 90) -or ($c -ge 97 -and $c -le 122)){$common++}}
  }
  $f=$e.fonts[$i++];foreach($key in @('commonFallback','commonTotal','naturalGlyphs','fallbackGlyphs')){$null=Number $f[$key] 0 256};Keys $f @('name','commonFallback','commonTotal','naturalGlyphs','fallbackGlyphs','logicalAwtIdentity');Need ($f.name -ceq $name -and $f.commonTotal -eq 62 -and $f.commonFallback -eq $common -and $f.naturalGlyphs -eq $natural -and $f.fallbackGlyphs -eq $fallback -and $f.logicalAwtIdentity.Length -le 1024 -and $f.logicalAwtIdentity.Contains('width=0.75 (standard WIDTH_CONDENSED)')) 'FONT_COUNTS_IDENTITY'
 };Need ($contents['constructor-evidence.json'].Length -le 8192) 'JSON_CAP';return @{facts=$facts;evidence=$e;contents=$contents}
}
try {
 Need ($IsWindows -and [Environment]::Is64BitProcess -and $PSVersionTable.PSVersion.Major -ge 7) 'WINDOWS_X64_PWSH7'
 $bb=[IO.File]::ReadAllBytes($BindingPath);Need ($bb.Length -le 32768 -and (Hash $bb) -ceq $BindingSha256) 'BINDING_PIN';$binding=JSON $bb
 Keys $binding @('schemaVersion','nonce','repositoryId','runId','runAttempt','workflowCommit','inputReleaseId','inputAssetId','inputZipBytes','inputZipSHA256','outputReleaseId','codeSHA256')
 Need ($binding.schemaVersion -eq 1 -and $binding.nonce -ceq '6e8f70b7fa18b0979d88e19260f9fbe5' -and $binding.repositoryId -eq 1433690543 -and $binding.runAttempt -eq 1 -and [string]$binding.runId -ceq $env:GITHUB_RUN_ID -and $env:GITHUB_RUN_ATTEMPT -ceq '1' -and $binding.workflowCommit -ceq $env:GITHUB_SHA -and $env:GITHUB_REPOSITORY -ceq 'rgin-ds/friends-pk-downloads') 'FRESH_RUN_BINDING'
 $null=Number $binding.runId 1 ([long]::MaxValue);foreach($n in @('inputReleaseId','inputAssetId','outputReleaseId')){$null=Number $binding[$n] 1 ([long]::MaxValue)};Need ($binding.inputReleaseId -ne $binding.outputReleaseId) 'DISTINCT_DRAFTS'
 $null=Number $binding.inputZipBytes 1 196608;Need ($binding.inputZipSHA256 -cmatch '^[a-f0-9]{64}$') 'ZIP_PIN'
 Keys $binding.codeSHA256 @('Worker.ps1','WinGuard.cs','Signal.ps1');foreach($name in $binding.codeSHA256.Keys){Need ((Hash ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name)))) -ceq $binding.codeSHA256[$name]) 'SOURCE_PIN'}
 Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'WinGuard.cs'))) -ErrorAction Stop
 Need ([FontWinGuard]::Sid -cne 'S-1-5-18' -and [FontWinGuard]::PureControls() -eq 24) 'PURE_PREDICATES'
 $root=Join-Path $env:RUNNER_TEMP ('font-probe-'+$binding.nonce);NewDir $root
 foreach($d in @('payload','jre','home','tmp','cwd','private','code')){NewDir (Join-Path $root $d)}
 foreach($name in @('Worker.ps1','WinGuard.cs','Signal.ps1')){[FontWinGuard]::WriteNew((Join-Path $root ('code\'+$name)),[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name)))}
 $token=$env:GH_TOKEN;if(-not $token){$token=$env:GITHUB_TOKEN};Need ($token -and $token.Length -le 4096) 'JOB_TOKEN_REQUIRED';Remove-Item Env:GH_TOKEN,Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
 $stage='PRIVATE_INPUT';$repo=Api '';Need ($repo.id -eq 1433690543 -and $repo.full_name -ceq 'rgin-ds/friends-pk-downloads') 'EXACT_REPOSITORY';$null=Draft $binding.inputReleaseId 'private-font-probe-input-20261028-01' $binding.inputAssetId $binding.inputZipBytes $binding.inputZipSHA256
 $null=Draft $binding.outputReleaseId 'private-font-probe-output-20261028-01' 0 0 ''
 $zip=Fetch ('https://api.github.com/repos/rgin-ds/friends-pk-downloads/releases/assets/'+$binding.inputAssetId) 196608 30 $true 'application/octet-stream' $null 1
 Need ($zip.Length -eq $binding.inputZipBytes -and (Hash $zip) -ceq $binding.inputZipSHA256) 'INPUT_ZIP_HASH'
 # Context must be found exactly once before extracting any private member.
 $zs=[IO.MemoryStream]::new($zip,$false);$za=[IO.Compression.ZipArchive]::new($zs,[IO.Compression.ZipArchiveMode]::Read,$false)
 try{$contexts=@($za.Entries|Where-Object FullName -CEQ 'context.json');Need ($contexts.Count -eq 1 -and $contexts[0].Length -le 131072) 'CONTEXT_MEMBER';$cs=$contexts[0].Open();$cm=[IO.MemoryStream]::new();try{$buffer=[byte[]]::new(4096);while(($n=$cs.Read($buffer,0,$buffer.Length)) -gt 0){Need ($cm.Length+$n -le 131072) 'CONTEXT_INFLATE_CAP';$cm.Write($buffer,0,$n)};$contextBytes=$cm.ToArray()}finally{$cs.Dispose();$cm.Dispose()}}finally{$za.Dispose();$zs.Dispose()}
 $context=JSON $contextBytes;Keys $context @('schemaVersion','inputPinsBase64','runtimeMapBase64');Need ($context.schemaVersion -eq 1) 'CONTEXT_SCHEMA'
 $pinBytes=[Convert]::FromBase64String($context.inputPinsBase64);$mapBytes=[Convert]::FromBase64String($context.runtimeMapBase64)
 Need ((Hash $pinBytes) -ceq '009b82876ee6b7d0f249c89d3fe02f1981e6e3427e48ddc09277665a7d53d9b5' -and (Hash $mapBytes) -ceq '059c6b46a8dcafee15a47fb3c31053e32c2047ec43d5a3b456432eb1fc8fd741') 'EXACT_CONTEXT_MAPS'
 [FontWinGuard]::WriteNew((Join-Path $root 'private\input-pins.json'),$pinBytes);[FontWinGuard]::WriteNew((Join-Path $root 'private\runtime-map.json'),$mapBytes)
 $pins=JSON $pinBytes;$runtime=JSON $mapBytes;Need ($pins.fontInputs.Count -eq 7 -and $pins.compiledClasses.Count -eq 7 -and $runtime.files.Count -eq 337) 'PIN_COUNTS'
 $expected=@{'context.json'=@{bytes=$contextBytes.Length;sha256=(Hash $contextBytes)}}
 foreach($f in $pins.fontInputs){$expected['inputs/'+$f.name]=$f};foreach($f in $pins.compiledClasses){$expected['classes/'+$f.classPath]=$f}
 Extract $zip (Join-Path $root 'payload') $expected '' 262144
 foreach($f in $pins.compiledClasses){$b=ReadBound (Join-Path $root ('payload\classes\'+$f.classPath.Replace('/','\'))) 32768;Need ([Convert]::ToHexString([byte[]]$b[0..3]) -ceq 'CAFEBABE' -and $b[4] -eq 0 -and $b[5] -eq 0 -and $b[6] -eq 0 -and $b[7] -eq 55) 'SEVEN_JAVA11_CLASSES'}
 ValidateInputs (Join-Path $root 'payload\inputs')
 $stage='EXACT026_JRE';$jreZip=Fetch 'https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.32.1%2B1/OpenJDK11U-jre_x64_windows_hotspot_11.0.32.1_1.zip' 43578373 120 $false 'application/octet-stream' $null 1
 Need ($jreZip.Length -eq 43578373 -and (Hash $jreZip) -ceq 'f8c7da672f5dba36b6f870608820b6b598cfae91296929f1b8f21ef2f1e8a0dd') 'EXACT026_RUNTIME_ARCHIVE'
 $jrePins=@{};foreach($f in $runtime.files){$jrePins[$f.name]=$f}
 $jm=[IO.MemoryStream]::new($jreZip,$false);$jz=[IO.Compression.ZipArchive]::new($jm,[IO.Compression.ZipArchiveMode]::Read,$false)
 try{$files=@($jz.Entries|Where-Object {-not $_.FullName.EndsWith('/')});Need ($files.Count -eq 337) 'JRE_EXACT_FILE_COUNT';$bits=$files[0].FullName.Split('/');Need ($bits.Count -ge 2) 'JRE_SINGLE_ROOT';[FontWinGuard]::Leaf($bits[0]);$jrePrefix=$bits[0]+'/'}finally{$jz.Dispose();$jm.Dispose()}
 Extract $jreZip (Join-Path $root 'jre') $jrePins $jrePrefix 200000000
 $codePins=@{};foreach($name in $binding.codeSHA256.Keys){$codePins[$name]=@{bytes=([IO.FileInfo](Join-Path $root ('code\'+$name))).Length;sha256=$binding.codeSHA256[$name]}}
 $stage='BEFORE_AUDIT';$null=Remain 80;[FontWinGuard]::DeadlineUtc=[DateTime]::UtcNow.AddMilliseconds((Remain 80));$before=@{payload=(AuditSet (Join-Path $root 'payload') $expected 131072);jre=(AuditSet (Join-Path $root 'jre') $jrePins 100000000);code=(AuditSet (Join-Path $root 'code') $codePins 131072)}
 $dirsBefore=@{};foreach($d in @('payload','payload\inputs','payload\classes','payload\classes\com','payload\classes\com\osroyale','jre','home','tmp','cwd','private','code')){$dirsBefore[$d]=[FontWinGuard]::AuditDirectory((Join-Path $root $d))}
 $ids=[Collections.Generic.HashSet[string]]::new();foreach($set in @($before.payload,$before.jre,$before.code)){foreach($v in $set.Values){Need ($ids.Add($v.id)) 'CROSS_SET_ALIAS'}}
 $stage='ONE_CONSTRUCTOR';$null=Remain 60;[FontWinGuard]::DeadlineUtc=[DateTime]::UtcNow.AddMilliseconds((Remain 60));$java=Join-Path $root 'jre\bin\java.exe';$output=Join-Path $root 'constructor-output';$home=Join-Path $root 'home';$tmp=Join-Path $root 'tmp';$cwd=Join-Path $root 'cwd'
 $environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
 foreach($pair in @{SystemRoot=$env:SystemRoot;WINDIR=$env:SystemRoot;PATH=((Join-Path $root 'jre\bin')+';'+(Join-Path $env:SystemRoot 'System32'));HOME=$home;USERPROFILE=$home;TEMP=$tmp;TMP=$tmp;APPDATA=(Join-Path $home 'AppData\Roaming');LOCALAPPDATA=(Join-Path $home 'AppData\Local')}.GetEnumerator()){$environment.Add($pair.Key,$pair.Value)}
 $arguments=@('-Xmx128m','-XX:MaxMetaspaceSize=128m','-XX:ActiveProcessorCount=1','-Djava.awt.headless=true',('-Duser.home='+$home),('-Djava.io.tmpdir='+$tmp),'-cp',(Join-Path $root 'payload\classes'),'com.osroyale.PortableFontConstructorProbe',(Join-Path $root 'payload\inputs'),$output,$pins.sourceCommit,$pins.titleSHA256,$pins.inputManifestSHA256)
 $signal=[Func[FontWinGuard+Identity,bool]]{
  param($owned)
  $start=[Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh.exe'));$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.Environment.Clear()
  foreach($p in $environment.GetEnumerator()){$start.Environment[$p.Key]=$p.Value}
  foreach($a in @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $root 'code\Signal.ps1'),'-TargetPid',[string]$owned.pid,'-Creation',[string]$owned.creation,'-Image',$owned.image,'-JobName',$owned.job,'-GuardPath',(Join-Path $root 'code\WinGuard.cs'),'-GuardSha256',$binding.codeSHA256['WinGuard.cs'])){$start.ArgumentList.Add($a)}
  $helper=[Diagnostics.Process]::Start($start);try{if(-not $helper.WaitForExit(5000)){return $false};return $helper.ExitCode -eq 0}finally{$helper.Dispose()}
 }
 $probe=[FontWinGuard]::Run($java,$arguments,$cwd,$environment,$binding.nonce,$signal);$receipt.process=$probe
 Need ($probe.status -ceq 'CLOSED_OWNED_PROBE' -and $probe.closed -and $probe.jobEmpty -and $probe.captureClosed -and $probe.helperClosed) 'POSITIVE_OWNED_CLOSURE';$receipt.closed=$true
 [FontWinGuard]::WriteNew((Join-Path $root 'private\stdout.bin'),$probe.stdout);[FontWinGuard]::WriteNew((Join-Path $root 'private\stderr.bin'),$probe.stderr);Need (-not $probe.captureExceeded) 'PRIVATE_CAPTURE_CAP'
 $stage='OUTPUT_VALIDATION';$validated=ValidateOutputs $output;$receipt.outputsComplete=$true;$receipt.outputFacts=$validated.facts
 $stdout=(Text $probe.stdout).Replace("`r`n","`n");$stderr=(Text $probe.stderr).Replace("`r`n","`n")
 $rejected=$validated.evidence.status -ceq 'FONT_CONSTRUCTOR_NUMERIC_REJECTED'
 if($rejected){Need ($probe.exitCode -eq 1 -and $stdout -ceq '' -and $stderr -ceq "Exception in thread `"main`" java.lang.AssertionError: Candidate ineligible: common fallback exceeds unchanged2/62 gate; outputs retained`n`t at com.osroyale.PortableFontConstructorProbe.main(PortableFontConstructorProbe.java:169)`n".Replace("`t at","`tat")) 'EXACT_NUMERIC_REFUSAL';$receipt.status='COMPLETED_DIAGNOSTIC_NUMERIC_REJECTION'}else{Need ($validated.evidence.status -ceq 'PASS_FONT_CONSTRUCTOR_NUMERIC' -and $probe.exitCode -eq 0 -and $stderr -ceq '' -and $stdout -ceq "PASS_PORTABLE_FONT_CONSTRUCTOR fonts=3 commonFallbackAtMost=2 native1x=true`n") 'EXACT_DIAGNOSTIC_PASS';$receipt.status='COMPLETED_CONSTRUCTOR_DIAGNOSTIC'}
} catch {
 $receipt.status='FAIL';$receipt.failureStage=$stage;$receipt.errorClass=$_.Exception.GetType().Name
} finally {
 if($null -ne $root){
  try{
   $null=Remain 80;[FontWinGuard]::DeadlineUtc=[DateTime]::UtcNow.AddMilliseconds((Remain 80))
   if($null -ne $before){$after=@{payload=(AuditSet (Join-Path $root 'payload') $expected 131072);jre=(AuditSet (Join-Path $root 'jre') $jrePins 100000000);code=(AuditSet (Join-Path $root 'code') $codePins 131072)};Preserved $before.payload $after.payload;Preserved $before.jre $after.jre;Preserved $before.code $after.code;$receipt.inputPreserved=$true;$receipt.auditMapSHA256=Hash ([Text.Encoding]::UTF8.GetBytes(($before|ConvertTo-Json -Depth 8 -Compress)));$receipt.auditFiles=352;$receipt.codeFiles=3}
   $ns=[ordered]@{};foreach($d in @('home','tmp','cwd')){$nodes=0;$ns[$d]=@(Tree (Join-Path $root $d) 0 ([ref]$nodes))};$receipt.namespaces=$ns;Need (([Text.Encoding]::UTF8.GetByteCount(($ns|ConvertTo-Json -Depth 12 -Compress))) -le 32768) 'NAMESPACE_METADATA_CAP'
   foreach($d in $dirsBefore.Keys){$s=[FontWinGuard]::AuditDirectory((Join-Path $root $d));Need ($s.id -ceq $dirsBefore[$d].id) 'DIRECTORY_PRESERVATION'}
   if($ns.home.Count -ne 0 -or $ns.tmp.Count -ne 0 -or $ns.cwd.Count -ne 0){$receipt.status='FAIL_UNEXPECTED_OWNED_NAMESPACE'}
  }catch{$receipt.status='FAIL_FINAL_PRESERVATION';$receipt.finalErrorClass=$_.Exception.GetType().Name}
  # No unknown/live process cleanup, root removal, retries or additional Java runs.
  try{
   if($receipt.closed -and $receipt.inputPreserved){
    $stage='PRIVATE_RESULT';[FontWinGuard]::DeadlineUtc=[DateTime]::UtcNow.AddMilliseconds((Remain 60));$receipt.elapsedMilliseconds=$clock.ElapsedMilliseconds;$receipt.imageOS=$env:ImageOS;$receipt.imageVersion=$env:ImageVersion;$receipt.osBuild=[Environment]::OSVersion.Version.ToString();$receipt.osArchitecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();$receipt.processArchitecture=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    $receipt.process.stdout=$null;$receipt.process.stderr=$null
    $archiveData=[ordered]@{};$available=[ordered]@{}
    foreach($name in @('stdout.bin','stderr.bin')){$archiveData[$name]=ReadBound (Join-Path $root ('private\'+$name)) 32768}
    if([IO.Directory]::Exists((Join-Path $root 'constructor-output'))){
     if($null -eq $validated){[FontWinGuard]::ProtectOutput((Join-Path $root 'constructor-output'),$true)}
     foreach($name in @('constructor-evidence.json','p11_full-constructor-1.0x.png','p11_full-fallbacks.csv','p12_full-constructor-1.0x.png','p12_full-fallbacks.csv','b12_full-constructor-1.0x.png','b12_full-fallbacks.csv')){
      $p=Join-Path $root ('constructor-output\'+$name);if([IO.File]::Exists($p)){
       if($null -eq $validated){[FontWinGuard]::ProtectOutput($p,$false)}
       $stamp=$null;$b=[FontWinGuard]::Read($p,$(if($name.EndsWith('.png')){262144}elseif($name.EndsWith('.csv')){32768}else{8192}),[ref]$stamp)
       if($null -ne $validated){Need ($validated.facts[$name].Same($stamp)) 'OUTPUT_FINAL_PRESERVATION'}
       $available[$name]=$stamp;$archiveData[$name]=$b
      }
     }
    }
    $receipt.availableOutputFacts=$available
    $resultBytes=[Text.Encoding]::UTF8.GetBytes(($receipt|ConvertTo-Json -Depth 14 -Compress));Need ($resultBytes.Length -le 262144) 'RECEIPT_CAP';[FontWinGuard]::WriteNew((Join-Path $root 'private\controller-receipt.json'),$resultBytes)
    $archiveData['controller-receipt.json']=$resultBytes;$archive=[IO.MemoryStream]::new();$za=[IO.Compression.ZipArchive]::new($archive,[IO.Compression.ZipArchiveMode]::Create,$true)
    try{foreach($name in $archiveData.Keys){$b=$archiveData[$name];$entry=$za.CreateEntry($name,[IO.Compression.CompressionLevel]::Optimal);$stream=$entry.Open();try{$stream.Write($b,0,$b.Length)}finally{$stream.Dispose()}}}finally{$za.Dispose()}
    $result=$archive.ToArray();$archive.Dispose();Need ($result.Length -le 2097152) 'RESULT_ARCHIVE_CAP'
    $null=Draft $binding.outputReleaseId 'private-font-probe-output-20261028-01' 0 0 ''
    $response=JSON (Fetch ('https://uploads.github.com/repos/rgin-ds/friends-pk-downloads/releases/'+$binding.outputReleaseId+'/assets?name=font-probe-result.zip') 131072 60 $true 'application/vnd.github+json' $result 0)
    Need ($response.name -ceq 'font-probe-result.zip' -and $response.size -eq $result.Length -and $response.digest -ceq ('sha256:'+(Hash $result))) 'PRIVATE_UPLOAD_DIGEST'
    $published=Api ('/releases/'+$binding.outputReleaseId);Need ($published.draft -and $published.tag_name -ceq 'private-font-probe-output-20261028-01' -and $published.assets.Count -eq 1 -and $published.assets[0].id -eq $response.id) 'OUTPUT_STILL_DRAFT'
    $null=Draft $binding.inputReleaseId 'private-font-probe-input-20261028-01' $binding.inputAssetId $binding.inputZipBytes $binding.inputZipSHA256
    Write-Host ('PRIVATE_FONT_DIAGNOSTIC_CLOSED status='+$receipt.status+' assetId='+$response.id+' sha256='+(Hash $result)+' bytes='+$result.Length)
   }else{Write-Host 'PRIVATE_FONT_DIAGNOSTIC_UNKNOWN_OR_UNPRESERVED_NO_UPLOAD'}
  }catch{$receipt.status='FAIL_PRIVATE_RESULT';Write-Host 'PRIVATE_FONT_DIAGNOSTIC_RESULT_REFUSED'}
 }
 $token=$null
}
if($receipt.status -notin @('COMPLETED_DIAGNOSTIC_NUMERIC_REJECTION','COMPLETED_CONSTRUCTOR_DIAGNOSTIC')){exit 1}
