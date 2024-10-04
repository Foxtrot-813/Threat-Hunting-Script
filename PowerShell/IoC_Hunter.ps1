# Define essential variables
$hostname = hostname
$userProfileDirectory = $env:USERPROFILE
$currentTimestamp = Get-Date -Format "yyyy-MM-dd-HH:mm"
$workingDirectoryPath = "$userProfileDirectory\Downloads\IoC_Working_Path\opt\security\working\"
$errorDirectoryPath = "$userProfileDirectory\Downloads\IoC_Working_Path\opt\security\errors\"
# $datestamp = Get-currentTimestamp -Format "yyyyMMdd"
$datestamp = "20231122"
$serverUrl = $args[0]
$uploadServerUrl = $args[1]
$userIdentity = $args[2]
$workingDirectoryCreatedFlag = "0"
$errorDirectoryCreatedFlag = "0"

# Log files
$iocFile = "IOC-$datestamp.ioc"
$iocGPGFile = "IOC-${datestamp}.gpg"
$iocLogFile = "IOC-${datestamp}.log"
$errorLogFile = "error-${datestamp}.log"

Write-Host "CND-Hunter by 8$([char]0x039B)$([char]0x042F)24$([char]0x0418)1"
Write-Host "TTH IoC Check for $hostname $currentTimestamp STARTED"
Write-Host "======================= IOC Hunter ======================="

# Check parameters
Function ValidateParameters {
    if (-Not $serverUrl) {
        Write-Host "No URL provided."
    }
    elseif ($serverUrl -Match "^http://") {
        Write-Host "WARNING: The URL uses HTTP. Only HTTPS is supported for secure communication."
    }
    elseif ($serverUrl -Match "^https://") {
        Write-Host "URL validation successful: HTTPS protocol detected."
    }
    elseif ($serverUrl -NotMatch "^http[s]?://") {
        Write-Host "WARNING: The URL provided does not include a valid HTTP or HTTPS scheme."
        exit 1
    }
    else {
        Write-Host "WARNING: An unexpected error occurred while validating the URL."
        exit 1
    }

    if (-Not (Test-Path -Path $workingDirectoryPath -PathType Container)) {
        Write-Host "Directory not found. Creating new directory at: $workingDirectoryPath"
        New-Item -Path $workingDirectoryPath -ItemType Directory -Force > $null
        Write-Host "Directory created successfully at: $workingDirectoryPath"
        $script:workingDirectoryCreatedFlag = "1"  # UpcurrentTimestamp the script-scoped variable, not just the local function scope.
    }
    else {
        Write-Host "Directory already exists at: $workingDirectoryPath. No action needed."
    }

    if (-Not (Test-Path -Path $errorDirectoryPath -PathType Container)) {
        Write-Host "Directory not found. Creating new directory at: $errorDirectoryPath"
        New-Item -Path $errorDirectoryPath -ItemType Directory -Force > $null
        Write-Host "Directory created successfully at: $errorDirectoryPath"
        $script:errorDirectoryCreatedFlag = "1"  # UpcurrentTimestamp the script-scoped variable, not just the local function scope.
    }
    else {
        Write-Host "Directory already exists at: $errorDirectoryPath. No action needed."
    }
    Set-Location $workingDirectoryPath
    "Current working directory is: " + (Get-Location).Path
}

# Restore system environment
Function Restore-SystemEnv {
    Write-Host "Restoring the previous system environment...."
    Set-Location "$userProfileDirectory"
    if ($workingDirectoryCreatedFlag -eq "0") {
        if (Test-Path "$workingDirectoryPath$iocFile") {
            Remove-Item "$workingDirectoryPath$iocFile" -Force
            Write-Host "File $iocFile in $workingDirectoryPath deleted successfully."
        }
        
        if (Test-Path "$workingDirectoryPath$iocGPGFile") {
            Remove-Item "$workingDirectoryPath$iocGPGFile" -Force
            Write-Host "File $iocGPGFile in $workingDirectoryPath deleted successfully."
        }
    
        if (Test-Path "$workingDirectoryPath$iocLogFile") {
            Remove-Item "$workingDirectoryPath$iocLogFile" -Force
            Write-Host "File $iocLogFile in $workingDirectoryPath deleted successfully."
        }
    
        if (Test-Path "$workingDirectoryPath\binfailure") {
            Remove-Item "$workingDirectoryPath\binfailure" -Force
            Write-Host "File binfailure in $workingDirectoryPath deleted successfully."
        }
    
        if (Test-Path "$workingDirectoryPath\listeningports") {
            Remove-Item "$workingDirectoryPath\listeningports" -Force
            Write-Host "File listeningports in $workingDirectoryPath deleted successfully."
        }
    
        if (Test-Path "$workingDirectoryPath\firewall") {
            Remove-Item "$workingDirectoryPath\firewall" -Force
            Write-Host "File firewall in $workingDirectoryPath deleted successfully."
        }
    
        if (Test-Path "$workingDirectoryPath\$hostname-tth-$datestamp.tgz") {
            Remove-Item "$workingDirectoryPath\$hostname-tth-$datestamp.tgz" -Force
            Write-Host "File $hostname-tth-$datestamp.tgz in $workingDirectoryPath deleted successfully."
        }
    
        if (Test-Path "$workingDirectoryPath\$hostname-tth-$datestamp.tgz.sig") {
            Remove-Item "$workingDirectoryPath\$hostname-tth-$datestamp.tgz.sig" -Force
            Write-Host "File $hostname-tth-$datestamp.tgz.sig in $workingDirectoryPath deleted successfully."
        }
    
        if (Test-Path "$workingDirectoryPath\iocreport-$datestamp.txt") {
            Remove-Item "$workingDirectoryPath\iocreport-$datestamp.txt" -Force
            Write-Host "File iocreport-$datestamp.txt in $workingDirectoryPath deleted successfully."
        }
    
        if (Test-Path "$workingDirectoryPath\msg") {
            Remove-Item "$workingDirectoryPath\msg" -Force
            Write-Host "File msg in $workingDirectoryPath deleted successfully."
        }
    }
    elseif ($workingDirectoryCreatedFlag -eq "1") {
        Write-Host "Pausing execution for 2 seconds at line 105"
        Start-Sleep -Seconds 2
        Remove-Item "$workingDirectoryPath" -Recurse -Force
        Write-Host "$workingDirectoryPath directory deleted successfully."
    }
    # Check and delete error log file in /opt/security/errors directory
    if ($errorDirectoryCreatedFlag -eq "0") {
        Start-Sleep -Seconds 2
        Remove-Item $errorDirectoryPath$errorLogFile -Force
        Write-Host "File $errorLogFile in $errorDirectoryPath deleted successfully."
    }
    elseif ($errorDirectoryCreatedFlag -eq "1") {
        Start-Sleep -Seconds 2
        Remove-Item "$errorDirectoryPath" -Recurse -Force
    }
    Write-Host "System Restored."

}

# Error handeling
Function ErrorHandling {
    param (
        [string]$error_msg,
        [string]$severity
    )
    Write-Host "$error_msg"
    if (-Not (Test-Path -Path $errorDirectoryPath)) {
        New-Item -Path $errorDirectoryPath -ItemType Directory -Force > $null
    }
    Write-Output "Hostname: $hostname Timestamp: $currentTimestamp $error_msg" >> $errorDirectoryPath$errorLogFile

    if ($severity -eq "CRITICAL") {
        Write-Host "Abort..."
        Restore-SystemEnv
        exit 1
    }
}

Function FailedStage () {
    param (
        [string]$stage
    )
    Write-Host "FAILED $stage - Hostname: $hostname Timestamp: $currentTimestamp"
}

# Download the daily IoC file
Function DownloadFiles () {
    try {
        if ($serverUrl[-1] -eq "/") {
            Invoke-WebRequest -Uri "$serverUrl$iocFile" -OutFile "$workingDirectoryPath$iocFile" -ErrorAction SilentlyContinue
            Invoke-WebRequest -Uri "$serverUrl$iocGPGFile" -OutFile "$workingDirectoryPath$iocGPGFile" -ErrorAction SilentlyContinue
        } elseif ($serverUrl[-1] -ne "/") {
            Invoke-WebRequest -Uri "$serverUrl/$iocFile" -OutFile "$workingDirectoryPath$iocFile" -ErrorAction SilentlyContinue
            Invoke-WebRequest -Uri "$serverUrl/$iocGPGFile" -OutFile "$workingDirectoryPath$iocGPGFile" -ErrorAction SilentlyContinue
        } else {
            Invoke-WebRequest -Uri "$serverUrl$iocFile" -OutFile "$workingDirectoryPath$iocFile" -ErrorAction SilentlyContinue
            Invoke-WebRequest -Uri "$serverUrl$iocGPGFile" -OutFile "$workingDirectoryPath$iocGPGFile" -ErrorAction SilentlyContinue
        }
    }
    catch {
        if (-Not $?) {
            FailedStage "to download IOC files"
            exit 1
        }
    }
    
}

Function ValidateIocIntegrity () {
    gpg --verify $iocGPGFile $iocFile
    If ($LASTEXITCODE -ne 0) {
        $ErrorMessage = "WARN: Signature verification failed for $iocFile"
        ErrorHandling $ErrorMessage "CRITICAL"
    }
}











ValidateParameters
ErrorHandling
DownloadFiles
ValidateIocIntegrity


#Restore-SystemEnv







