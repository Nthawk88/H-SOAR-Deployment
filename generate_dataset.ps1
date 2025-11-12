# H-SOAR HIDS Dataset Generator Script for Windows
# PowerShell script to generate training dataset

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "H-SOAR HIDS Dataset Generator" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Error: Python not found. Please install Python 3.8+" -ForegroundColor Red
    exit 1
}

# Check if required packages are installed
Write-Host "Checking required packages..." -ForegroundColor Yellow
try {
    python -c "import pandas, numpy" 2>&1 | Out-Null
    Write-Host "Required packages found" -ForegroundColor Green
} catch {
    Write-Host "Error: Required packages not found. Installing..." -ForegroundColor Yellow
    pip install pandas numpy
}

# Create data directory if it doesn't exist
if (-not (Test-Path "data")) {
    New-Item -ItemType Directory -Path "data" | Out-Null
    Write-Host "Created data directory" -ForegroundColor Green
}

# Generate dataset
Write-Host ""
Write-Host "Generating training dataset..." -ForegroundColor Yellow
Write-Host "This may take a few minutes..." -ForegroundColor Yellow
Write-Host ""

# Generate dataset with default parameters (10,000 samples)
python generate_dataset.py --samples 10000 --benign-ratio 0.80 --suspicious-ratio 0.12 --malicious-ratio 0.08 --output data/training_dataset.csv

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "Dataset generated successfully!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Dataset location: data/training_dataset.csv" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Review dataset: data/training_dataset.csv" -ForegroundColor White
    Write-Host "2. Train ML model: python run_system.py --mode train --dataset data/training_dataset.csv" -ForegroundColor White
    Write-Host "3. Test system: python run_system.py --mode test" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "Error: Dataset generation failed!" -ForegroundColor Red
    exit 1
}


