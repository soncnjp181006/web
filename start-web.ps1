param(
    [switch]$SkipInstall,
    [switch]$NoBackend,
    [switch]$NoFrontend
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $repoRoot "backend"
$frontendDir = Join-Path $repoRoot "frontend"
$logsDir = Join-Path $repoRoot "logs"

if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir | Out-Null
}

if (-not (Test-Path (Join-Path $repoRoot ".env"))) {
    $envExample = Join-Path $repoRoot ".env.example"
    Copy-Item $envExample (Join-Path $repoRoot ".env")
    Write-Host "Created .env from .env.example. Update it if needed before running the app." -ForegroundColor Yellow
}

function Ensure-Dependencies($projectDir) {
    if ($SkipInstall) {
        return
    }

    $nodeModules = Join-Path $projectDir "node_modules"
    if (-not (Test-Path $nodeModules)) {
        Write-Host "Installing dependencies in $projectDir..." -ForegroundColor Cyan
        Push-Location $projectDir
        try {
            npm install
        }
        finally {
            Pop-Location
        }
    }
}

function Start-Service($name, $workingDir, $command, $logPath) {
    $psArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        "Set-Location '$workingDir'; $command 2>&1 | Tee-Object -FilePath '$logPath'"
    )

    Start-Process powershell -ArgumentList $psArgs -WorkingDirectory $workingDir -WindowStyle Normal | Out-Null
    Write-Host "Started $name. Log: $logPath" -ForegroundColor Green
}

if (-not $NoBackend) {
    Ensure-Dependencies $backendDir
    Start-Service -name "Backend" -workingDir $backendDir -command "npm start" -logPath (Join-Path $logsDir "backend.log")
}

if (-not $NoFrontend) {
    Ensure-Dependencies $frontendDir
    Start-Service -name "Frontend" -workingDir $frontendDir -command "npm run dev -- --host 0.0.0.0 --port 4173" -logPath (Join-Path $logsDir "frontend.log")
}

Write-Host "" 
Write-Host "App is starting..." -ForegroundColor Cyan
Write-Host "Frontend: http://127.0.0.1:4173" -ForegroundColor Cyan
Write-Host "Backend health: http://127.0.0.1:4000/health" -ForegroundColor Cyan
Write-Host "" 
Write-Host "Use Ctrl+C inside each console window if you want to stop the services." -ForegroundColor Yellow
