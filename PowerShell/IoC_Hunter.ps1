$hostname = hostname
$userProfilePath = $env:USERPROFILE
$date = Get-Date -Format "yyyy-MM-dd-HH:mm"
$working_path = "$userProfilePath\Downloads\IoC_Working_Path\opt\security\oporation\"
$errors_path = "$userProfilePath\Downloads\IoC_Working_Path\opt\security\errors"
# $datestamp = Get-Date -Format "yyyyMMdd"
$datestamp ="20231122"
$server_url = $args[0]
$upload_server = $args[1]
$user_identity = $args[2]
$flag_1 = "0"
$flag_2 = "0"

# Log files
$ioc_file = "IOC-$datestamp.ioc"
$ioc_gpg = "IOC-${datestamp}.gpg"
$ioc_log = "IOC-${datestamp}.log"
$error_file = "error-${datestamp}.log"

Write-Host "CND-Hunter by 8$([char]0x039B)$([char]0x042F)24$([char]0x0418)1"
Write-Host "TTH IoC Check for $hostname $date STARTED"
Write-Host "======================= IOC Hunter ======================="

# Check parameters
Function Initiate_Check {
    if (-Not $server_url) {
        Write-Host "No URL provided."
    } elseif ($server_url -Match "^http://") {
        Write-Host "WARNING: The URL uses HTTP. Only HTTPS is supported for secure communication."
    } elseif ($server_url -Match "^https://") {
        Write-Host "URL validation successful: HTTPS protocol detected."
    } elseif ($server_url -NotMatch "^http[s]?://") {
        Write-Host "WARNING: The URL provided does not include a valid HTTP or HTTPS scheme."
    } else {
        Write-Host "WARNING: An unexpected error occurred while validating the URL."
    }

    if (-Not (Test-Path -Path $working_path -PathType Container)) {
        Write-Host "Directory not found. Creating new directory at: $working_path"
        New-Item -Path $working_path -ItemType Directory -Force > $null
        Write-Host "Directory created successfully at: $working_path"
        $script:flag_1 = "1"  # Update the script-scoped variable, not just the local function scope.
    } else {
        Write-Host "Directory already exists at: $working_path. No action needed."
    }
    Set-Location $working_path
    "Current working directory is: " + (Get-Location).Path
}

# Restore system environment
Function restore_system_env {
    Write-Host "Restoring the previous system environment...."
    Set-Location "$userProfilePath"
    if ($flag_1 -eq "0") {
        if (Test-Path "$working_path$ioc_file") {
            Remove-Item "$working_path$ioc_file" -Force
            Write-Host "File $ioc_file in $working_path deleted successfully."
        }
    
        if (Test-Path "$working_path$ioc_gpg") {
            Remove-Item "$working_path$ioc_gpg" -Force
            Write-Host "File $ioc_gpg in $working_path deleted successfully."
        }
    
        if (Test-Path "$working_path$ioc_log") {
            Remove-Item "$working_path$ioc_log" -Force
            Write-Host "File $ioc_log in $working_path deleted successfully."
        }
    
        if (Test-Path "$working_path\binfailure") {
            Remove-Item "$working_path\binfailure" -Force
            Write-Host "File binfailure in $working_path deleted successfully."
        }
    
        if (Test-Path "$working_path\listeningports") {
            Remove-Item "$working_path\listeningports" -Force
            Write-Host "File listeningports in $working_path deleted successfully."
        }
    
        if (Test-Path "$working_path\firewall") {
            Remove-Item "$working_path\firewall" -Force
            Write-Host "File firewall in $working_path deleted successfully."
        }
    
        if (Test-Path "$working_path\$hostname-tth-$datestamp.tgz") {
            Remove-Item "$working_path\$hostname-tth-$datestamp.tgz" -Force
            Write-Host "File $hostname-tth-$datestamp.tgz in $working_path deleted successfully."
        }
    
        if (Test-Path "$working_path\$hostname-tth-$datestamp.tgz.sig") {
            Remove-Item "$working_path\$hostname-tth-$datestamp.tgz.sig" -Force
            Write-Host "File $hostname-tth-$datestamp.tgz.sig in $working_path deleted successfully."
        }
    
        if (Test-Path "$working_path\iocreport-$datestamp.txt") {
            Remove-Item "$working_path\iocreport-$datestamp.txt" -Force
            Write-Host "File iocreport-$datestamp.txt in $working_path deleted successfully."
        }
    
        if (Test-Path "$working_path\msg") {
            Remove-Item "$working_path\msg" -Force
            Write-Host "File msg in $working_path deleted successfully."
        }
    } elseif ($flag_1 -eq "1") {
        Start-Sleep -Seconds 2
        Remove-Item "$userProfilePath\Downloads\IoC_Working_Path\" -Recurse -Force
        Write-Host "$userProfilePath\Downloads\IoC_Working_Path\ directory deleted successfully."
    }
    # Check and delete error log file in /opt/security/errors directory


}


Initiate_Check
restore_system_env
