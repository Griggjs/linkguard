# 护链统一启动器：自动找一个能用的 Python，然后调 `python -m linkguard <参数>`
#
#   .\scripts\run.ps1 check http://x.top/a
#   .\scripts\run.ps1 serve --port 8088
#   .\scripts\run.ps1 feeds --update
#
# 想固定用某个解释器，设环境变量 LINKGUARD_PYTHON 指向 python.exe 即可。

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Rest
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUTF8 = '1'

function Resolve-Python {
    $candidate = $env:LINKGUARD_PYTHON
    if ($candidate -and (Test-Path $candidate)) {
        return @{ Exe = $candidate; Pre = @() }
    }
    foreach ($name in @('py', 'python3', 'python')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        $pre = if ($name -eq 'py') { @('-3') } else { @() }
        try {
            & $cmd.Source @pre -c "import sys" 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { return @{ Exe = $cmd.Source; Pre = $pre } }
        } catch {
            continue
        }
    }
    # 最后兜底：本机自带的运行时
    $bundled = Join-Path $env:USERPROFILE '.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe'
    if (Test-Path $bundled) {
        return @{ Exe = $bundled; Pre = @() }
    }
    return $null
}

$py = Resolve-Python
if (-not $py) {
    Write-Host ''
    Write-Host '没有找到 Python 3。' -ForegroundColor Red
    Write-Host '请先安装 Python 3.9 或更高版本：https://www.python.org/downloads/'
    Write-Host '安装时务必勾选 "Add python.exe to PATH"。'
    Write-Host ''
    exit 1
}

if ($Rest.Count -eq 0) {
    & $py.Exe @($py.Pre) -m linkguard --help
} else {
    & $py.Exe @($py.Pre) -m linkguard @Rest
}
exit $LASTEXITCODE
