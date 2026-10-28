# TEST ONLY / UNRUN. Parse pinned source as DATA; execute only Tree's terminal return expression.
# No worker top-level, directory enumeration, Win32, Add-Type, JVM, process or HTTP is invoked.
param([Parameter(Mandatory)][string]$OriginalWorker,[Parameter(Mandatory)][string]$CorrectedWorker)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$checks=0
function Check($ok,[string]$why){if(-not $ok){throw [InvalidOperationException]::new($why)};$script:checks++}
function Producer([string]$path,[string]$sha,[string]$expected){
 $bytes=[IO.File]::ReadAllBytes($path)
 Check ($bytes.Length -le 65536 -and [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() -ceq $sha) 'SOURCE_PIN'
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
 Check ($errors.Count -eq 0) 'SOURCE_SYNTAX'
 $trees=@($ast.FindAll({param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -ceq 'Tree'},$true))
 Check ($trees.Count -eq 1) 'EXACT_TREE'
 $returns=@($trees[0].Body.FindAll({param($a) $a -is [Management.Automation.Language.ReturnStatementAst]},$true))
 Check ($returns.Count -eq 1 -and $returns[0].Extent.Text -ceq $expected) 'EXACT_RETURN'
 # This actual extracted return is the producer used by the unchanged @(Tree ...) consumers.
 return [ScriptBlock]::Create('param([object[]]$facts) '+$returns[0].Extent.Text)
}
$old=Producer $OriginalWorker '47336dc39a0175aa0be6493db816ab066237ca872a1fcc071fd165abd067aa44' 'return ,$facts'
$new=Producer $CorrectedWorker '859d3d0d1ab0c4d47694d25044f8eb7284baf4d39a7d252cc15fcf00735945cf' 'return $facts'
$oldEmpty=@(& $old -facts @())
Check ($oldEmpty.Count -eq 1 -and $oldEmpty[0] -is [array] -and $oldEmpty[0].Count -eq 0) 'ORIGINAL_FALSE_NONEMPTY_REPRODUCED'
$empty=@(& $new -facts @())
Check ($empty.Count -eq 0) 'CORRECTED_EMPTY'
$one=@(& $new -facts @(@{name='one';directory=$false;bytes=1}))
Check ($one.Count -eq 1 -and $one[0] -is [Collections.IDictionary] -and $one[0].name -ceq 'one' -and -not $one[0].directory) 'ONE_CHILD_NOT_ARRAY_WRAPPED'
$nested=@(& $new -facts @(@{name='nested';directory=$true;children=@(& $new -facts @())}))
Check ($nested.Count -eq 1 -and $nested[0].directory -and $nested[0].children.Count -eq 0) 'NESTED_EMPTY_CHILDREN'
$pair=@(& $new -facts @($one[0],$nested[0]))
Check ($pair.Count -eq 2 -and $pair[0].name -ceq 'one' -and $pair[1].name -ceq 'nested' -and $pair[1].children.Count -eq 0) 'NONEMPTY_ORDER_PRESERVED'
if($checks -ne 13){throw [InvalidOperationException]::new('EXPECTED_CONTROL_COUNT')}
Write-Output ('PASS_WINDOWS_NAMESPACE_SHAPE checks='+$checks)
