# 一键安装 Android 命令行工具链（不需要 Android Studio）
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\setup-android-sdk.ps1
#
# 装什么：cmdline-tools + platform-tools(adb) + platforms;android-35 + build-tools;35.0.0
# 装到哪：$SdkRoot，默认 %USERPROFILE%\android-sdk，也认 ANDROID_HOME；可用 -SdkRoot 指定
# 前提：机器上已有 JDK 17（脚本在 JAVA_HOME、Android Studio、JetBrains 及常见位置查找）

[CmdletBinding()]
param(
    [string] $SdkRoot = '',
    [string] $ApiLevel = '35',
    [string] $BuildTools = '35.0.0'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not $SdkRoot) {
    if ($env:ANDROID_HOME) { $SdkRoot = $env:ANDROID_HOME }
    elseif ($env:ANDROID_SDK_ROOT) { $SdkRoot = $env:ANDROID_SDK_ROOT }
    else { $SdkRoot = Join-Path $env:USERPROFILE 'android-sdk' }
}

function Write-Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

# ---------------------------------------------------------------- 1. 找 JDK
Write-Step "查找 JDK 17"

$javaHome = $null
$candidates = @()
if ($env:JAVA_HOME) { $candidates += $env:JAVA_HOME }
$candidates += @(
    (Join-Path $env:ProgramFiles 'Android\Android Studio\jbr'),
    (Join-Path $env:ProgramFiles 'Java\jdk-17'),
    (Join-Path $env:ProgramFiles 'Java\jdk-21'),
    (Join-Path $env:ProgramFiles 'Eclipse Adoptium\jdk-17')
)
foreach ($glob in @('Java\jdk-*', 'JetBrains\*\jbr', 'Eclipse Adoptium\jdk-*', 'ADS*')) {
    $candidates += Get-ChildItem (Join-Path $env:ProgramFiles $glob) -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { $_.FullName }
}

foreach ($c in $candidates) {
    if (-not $c) { continue }
    $javac = Join-Path $c 'bin\javac.exe'
    if (Test-Path $javac) {
        $v = (& $javac -version 2>&1) -join ' '
        if ($v -match '1[7-9]|2[0-9]') { $javaHome = $c; Write-Host "  找到 $c  ($v)" -ForegroundColor Green; break }
    }
}

if (-not $javaHome) {
    Write-Host "  没有找到 JDK 17。请先安装：https://adoptium.net/temurin/releases/?version=17" -ForegroundColor Red
    exit 1
}
$env:JAVA_HOME = $javaHome
$env:PATH = "$javaHome\bin;$env:PATH"

# ---------------------------------------------------------------- 2. 下载 cmdline-tools
Write-Step "下载 Android command-line tools"

New-Item -ItemType Directory -Force -Path $SdkRoot | Out-Null
$zip = Join-Path $env:TEMP 'android-cmdline-tools.zip'

if (-not (Test-Path $zip)) {
    # 从官方 repository 索引里解析当前版本的文件名，避免硬编码失效
    $url = $null
    try {
        $index = (Invoke-WebRequest -Uri 'https://dl.google.com/android/repository/repository2-3.xml' -TimeoutSec 60).Content
        $m = [regex]::Match($index, 'commandlinetools-win-\d+_latest\.zip')
        if ($m.Success) { $url = "https://dl.google.com/android/repository/$($m.Value)" }
    } catch {
        Write-Host "  索引获取失败，用已知版本兜底" -ForegroundColor Yellow
    }
    if (-not $url) { $url = 'https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip' }

    Write-Host "  下载 $url"
    Invoke-WebRequest -Uri $url -OutFile $zip -TimeoutSec 600
}
Write-Host "  压缩包 $([math]::Round((Get-Item $zip).Length/1MB,1)) MB"

# ---------------------------------------------------------------- 3. 解压
Write-Step "解压到 $SdkRoot\cmdline-tools\latest"

$tmp = Join-Path $env:TEMP ('android-clt-' + [guid]::NewGuid().ToString('N').Substring(0,8))
Expand-Archive -Path $zip -DestinationPath $tmp -Force
$inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
$dest = Join-Path $SdkRoot 'cmdline-tools\latest'
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
Move-Item $inner.FullName $dest
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue

$sdkmanager = Join-Path $dest 'bin\sdkmanager.bat'
if (-not (Test-Path $sdkmanager)) { Write-Host "  sdkmanager 没找到，解压结构异常" -ForegroundColor Red; exit 1 }
Write-Host "  sdkmanager: $sdkmanager" -ForegroundColor Green

# ---------------------------------------------------------------- 4. 接受许可
Write-Step "接受 SDK 许可"
$yes = (1..40 | ForEach-Object { 'y' })
$yes | & $sdkmanager --sdk_root=$SdkRoot --licenses 2>&1 | Select-Object -Last 5

# ---------------------------------------------------------------- 5. 安装组件
Write-Step "安装 platform-tools / platforms;android-$ApiLevel / build-tools;$BuildTools"

& $sdkmanager --sdk_root=$SdkRoot `
    'platform-tools' `
    "platforms;android-$ApiLevel" `
    "build-tools;$BuildTools" 2>&1 | Select-Object -Last 12

# ---------------------------------------------------------------- 6. 验证
Write-Step "验证"
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
if (Test-Path $adb) { Write-Host "  adb: $(& $adb version | Select-Object -First 1)" -ForegroundColor Green }
else { Write-Host "  adb 没装上" -ForegroundColor Red }

foreach ($p in @("platforms\android-$ApiLevel\android.jar", "build-tools\$BuildTools\aapt2.exe")) {
    $full = Join-Path $SdkRoot $p
    if (Test-Path $full) { Write-Host "  OK  $p" -ForegroundColor Green }
    else { Write-Host "  缺失 $p" -ForegroundColor Red }
}

Write-Host "`n完成。SDK 根目录: $SdkRoot" -ForegroundColor Cyan
Write-Host "后续编译前设置：`$env:ANDROID_HOME = '$SdkRoot'" -ForegroundColor Cyan
