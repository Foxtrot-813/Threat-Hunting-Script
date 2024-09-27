$hostname = hostname
$date = Get-Date -Format "yyyy-MM-dd-HH:mm"
$working_path = "C:\Users\barjaw\Downloads\IoC_Working_Path\opt\security\oporation"
$errors_path = "C:\Users\barjaw\Downloads\IoC_Working_Path\opt\security\errors"
$datestamp = Get-Date -Format "yyyyMMdd"
$server_url = $args[0]
$upload_server = $args[1]
$user_identity = $args[2]
$flag1 = "0"
$flag2 = "="

# Log files
$ioc_file = "IOC-$datestamp.ioc"
$ioc_gpg = 
$ioc_log = 
$error_file = 

Write-Host "CND-Hunter by 8$([char]0x039B)$([char]0x042F)24$([char]0x0418)1"
Write-Host "TTH IoC Check for $hostname $date STARTED"
Write-Host "======================= IOC Hunter ======================="

# Check parameters
Function Initiate_Check {
    if ($server_url -Match "^http://") {
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
        $flag1 = "1"
        Write-Host $flag1
    } else {
        Write-Host "Directory already exists at: $working_path. No action needed."
    }
    
}




Initiate_Check
