$hostname = hostname
$date = Get-Date -Format "yyyy-MM-dd-HH:mm"
$working_path = "/opt/security/oporation"
$errors_path = "/opt/security/errors"
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
    } elseif ($server_url -NotMatch "^http") {
        Write-Host "WARNING: The URL provided does not include a valid HTTPS scheme."
    } elseif ($server_url -Match "^https://") {
        Write-Host "Validation successful: HTTPS protocol detected."
    } else {
        Write-Host "WARNING: An unexpected error occurred while validating the URL."
    }
}



Initiate_Check
