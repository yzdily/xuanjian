# ============================================================
# start.ps1 — XuanJian 一键启动 (Windows PowerShell 5.1+)
# 行为与 start.sh / launch.bat 一致:
#   1) cd 到脚本所在目录 (仓库根)
#   2) 选择 Python 解释器 (venv > py > python)
#   3) 转发所有参数到 python start.py
# 用法:
#   .\start.ps1                       # 等价 python start.py
#   .\start.ps1 -Production           # 生产模式
#   $env:PROXY_PORT=18081; .\start.ps1
# ============================================================

$ErrorActionPreference = "Stop"

# 切到项目根
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# 选 Python：优先 .\.venv\Scripts\python.exe，其次 py launcher，最后 python
$py = $null
$candidates = @(
    Join-Path $ScriptDir ".venv\Scripts\python.exe",
    Join-Path $ScriptDir "venv\Scripts\python.exe"
)
foreach ($c in $candidates) {
    if (Test-Path $c) { $py = $c; break }
}
if (-not $py) {
    # 优先 py launcher (Windows 官方推荐)
    if (Get-Command py -ErrorAction SilentlyContinue) { $py = "py" }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { $py = "python" }
    else {
        Write-Host "[x] 未找到 Python (>=3.10)。请先安装 Python 3.10+ 并加入 PATH" -ForegroundColor Red
        Write-Host "    下载: https://www.python.org/downloads/" -ForegroundColor Yellow
        Read-Host "按 Enter 退出"
        exit 1
    }
}

# 强制 UTF-8 输出 + 无缓冲
$env:PYTHONIOENCODING = if ($env:PYTHONIOENCODING) { $env:PYTHONIOENCODING } else { "utf-8" }
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONUNBUFFERED = "1"

Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] start.ps1  平台=Windows  Python=$((& $py --version) 2>&1)"

# 转发所有原始参数
& $py start.py @args
if ($LASTEXITCODE -ne 0) {
    Write-Host "[x] 启动失败 (退出码 $LASTEXITCODE)，按 Enter 退出..." -ForegroundColor Red
    Read-Host
    exit $LASTEXITCODE
}
