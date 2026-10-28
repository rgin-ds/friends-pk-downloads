# TEST ONLY. Sole timeout signal helper. No API/network, termination, raw error or secret output.
param([Parameter(Mandatory)][uint32]$TargetPid,[Parameter(Mandatory)][long]$Creation,
 [Parameter(Mandatory)][string]$Image,[Parameter(Mandatory)][string]$JobName,
 [Parameter(Mandatory)][string]$GuardPath,[Parameter(Mandatory)][string]$GuardSha256)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue';$InformationPreference='SilentlyContinue';$VerbosePreference='SilentlyContinue';$DebugPreference='SilentlyContinue';Set-StrictMode -Version Latest
try {
 if((Get-FileHash -LiteralPath $GuardPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $GuardSha256){exit 3}
 Add-Type -TypeDefinition ([IO.File]::ReadAllText($GuardPath)) -ErrorAction Stop
 if([FontWinGuard]::Signal($TargetPid,$Creation,$Image,$JobName)){exit 0}
 exit 3
} catch {exit 3}
