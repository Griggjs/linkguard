# 打包 APK。用法：.\build.ps1
#
# 需要：
#   - JDK 17 或以上
#   - Android SDK（platforms;android-35 + build-tools;35.0.0）
#
# 工具链自动查找顺序：
#   JDK  ：$env:JAVA_HOME → Android Studio / JetBrains / JDK 常见安装位置
#   SDK  ：$env:ANDROID_HOME → $env:ANDROID_SDK_ROOT → local.properties → %LOCALAPPDATA%\Android\Sdk
#   Gradle：仓库自带的 gradlew.bat（首次运行会自动下载 8.9）
#
# 可选覆盖：$env:JAVA_HOME、$env:ANDROID_HOME、$env:GRADLE_BIN

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-Location $PSScriptRoot

function Find-Jdk {
    $candidates = @()
    if ($env:JAVA_HOME) { $candidates += $env:JAVA_HOME }
    $candidates += @(
        (Join-Path $env:ProgramFiles 'Android\Android Studio\jbr')
    )
    foreach ($glob in @('JetBrains\*\jbr', 'Java\jdk-*', 'Eclipse Adoptium\jdk-*', 'ADS*')) {
        $candidates += Get-ChildItem (Join-Path $env:ProgramFiles $glob) -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName }
    }
    $candidates += Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Programs\*\jbr') -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { $_.FullName }

    foreach ($c in $candidates) {
        if (-not $c) { continue }
        $javac = Join-Path $c 'bin\javac.exe'
        if (-not (Test-Path $javac)) { continue }
        $v = (& $javac -version 2>&1) -join ' '
        if ($v -match '1[7-9]|2[0-9]') { return $c }
    }
    return $null
}

function Find-Sdk {
    foreach ($c in @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT)) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    $lp = Join-Path $PSScriptRoot 'local.properties'
    if (Test-Path $lp) {
        $line = Get-Content $lp -Encoding UTF8 | Where-Object { $_ -match '^\s*sdk\.dir=' } | Select-Object -First 1
        if ($line) {
            # local.properties 是 Java properties 格式，冒号和反斜杠会被转义
            $sdk = ($line -replace '^\s*sdk\.dir=', '') -replace '\\(.)', '$1'
            if (Test-Path $sdk) { return $sdk }
        }
    }
    $default = Join-Path $env:LOCALAPPDATA 'Android\Sdk'
    if (Test-Path $default) { return $default }
    return $null
}

$Jdk = Find-Jdk
if (-not $Jdk) {
    throw "找不到 JDK 17 或以上版本。请安装 JDK（如 https://adoptium.net）并设置环境变量 JAVA_HOME。"
}

$Sdk = Find-Sdk
if (-not $Sdk) {
    throw "找不到 Android SDK。请设置环境变量 ANDROID_HOME，或在 android\local.properties 写入 sdk.dir=你的SDK路径。"
}

if (-not (Test-Path (Join-Path $Sdk 'platforms\android-35'))) {
    throw "SDK 里缺少 platform-35：$Sdk。可运行 tools\setup-android-sdk.ps1 安装，或用 Android Studio 的 SDK Manager 勾选。"
}

$Gradle = $env:GRADLE_BIN
if (-not $Gradle) {
    $wrapper = Join-Path $PSScriptRoot 'gradlew.bat'
    if (Test-Path $wrapper) { $Gradle = $wrapper }
}
if (-not $Gradle -or -not (Test-Path $Gradle)) {
    throw "找不到 Gradle。仓库本应自带 gradlew.bat；若已删除，请安装 Gradle 8.9 并用环境变量 GRADLE_BIN 指向它。"
}

$env:JAVA_HOME = $Jdk
$env:ANDROID_HOME = $Sdk
$env:ANDROID_SDK_ROOT = $Sdk
$env:PATH = "$Jdk\bin;$env:PATH"

Write-Host "JDK    : $Jdk"
Write-Host "SDK    : $Sdk"
Write-Host "Gradle : $Gradle"

Write-Host "`n=== 1/2 跑单元测试 ===" -ForegroundColor Cyan
& $Gradle test --console=plain --no-daemon
if ($LASTEXITCODE -ne 0) { throw "单元测试失败，不打包" }

Write-Host "`n=== 2/2 打包 APK ===" -ForegroundColor Cyan
& $Gradle assembleDebug --console=plain --no-daemon
if ($LASTEXITCODE -ne 0) { throw "打包失败" }

$apk = Join-Path $PSScriptRoot 'app\build\outputs\apk\debug\app-debug.apk'
if (Test-Path $apk) {
    $mb = [math]::Round((Get-Item $apk).Length / 1MB, 2)
    Write-Host "`n完成：$apk（$mb MB）" -ForegroundColor Green
} else {
    throw "没有找到产物：$apk"
}
