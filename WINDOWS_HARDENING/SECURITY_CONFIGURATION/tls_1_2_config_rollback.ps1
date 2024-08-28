# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2019 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ************************************************************************
# Name     : tls_1_2_configuration_rollback
# Purpose : Automation for Rollback of TLS 1.2 enforcement on Windows Servers
# Last updated : 18-Sep-2019
#
# *************************************************************************
$logtimestamp=$([datetime]::Now).ToString("yyyy-MM-dd_HH_mm_ss")
$log="C:\SECURITY_CONFIGURATION\tls1_2_config_rollback_log-$logtimestamp.log"
#Function for logging
function log($logmessage) {
   $TimeStamp = Get-Date -format yyyy-MM-dd_HH_mm_ss
   $TimeStamp + " : " + $logmessage | out-file -Filepath $log -append -Force
}
log "TLS 1.2 configuration rollback script started.."
#Checking if the machine is installed with Virtual Delivery Agent
if(Test-Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent")
{
$rollback_success=5
log "The machine has VDA installation"
$option=@("ciphers_config","triple_des_168","hash_config","protocol_config","ssl_2_0","print_status")
}
elseif(Test-Path "HKLM:\SOFTWARE\Citrix\Storefront")
{
$rollback_success=5
log "The machine has CCS installation"
$option=@("ciphers_config","triple_des_168","hash_config","protocol_config","ssl_2_0","print_status")
}
else
{
$rollback_success=6
log "The machine doesn't contain CCS or VDA installation"
$option=@("ciphers_config","triple_des_168","hash_config","protocol_config","tls_1_2","ssl_2_0","tls_default","print_status")
}
Write-Host "*********************************************************"
Write-Host "          TLS 1.2 Configuration Rollback Started                    "
Write-Host "*********************************************************"
function remove-key{
param (
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$path
)
if(Test-Path $Path)
{
try{
Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
log "$path removed"
$global:validation_counter++
}
catch{
$global:validation_counter=0
log "Failed to remove $path"
Write-Host "Failed to remove $path" 
Write-Host "Check the log details in C:\SECURITY_CONFIGURATION\tls1_2_config_rollback_log-$logtimestamp.log"
Exit(1)
}
}
else
{
log "$path is not available"
}
}
switch ($option)
{
ciphers_config{
#script for rollback of cipher configuration
log "Cipher configuration rollback started"
write-host("`n")
Write-Host "Cipher configuration rollback started"
#Storing the list of cipher keys  to be removed
$ciphers_list=@("RC4 128/128","RC4 56/128","RC4 40/128","RC4 64/128")
$ciphers_path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
$global:validation_counter=0
foreach ($cipher in $ciphers_list)
{
remove-key -path "$ciphers_path\$cipher" 
}
if ($global:validation_counter -eq 4)
{
log "Cipher configuration rollback completed"
write-host("`n")
Write-Host "Cipher configuration rollback completed"
}
else
{
log "Cipher configuration rollback failed!!"
Write-Host "Cipher configuration rollback failed!!"
write-host("`n")
Write-Host "Check the log details in C:\SECURITY_CONFIGURATION\tls1_2_config_rollback_log-$logtimestamp.log"
EXIT(1)
}
}
triple_des_168{
log "Triple DES 168 Cipher configuration rollback started"
$ciphers_path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
$global:validation_counter=0
remove-key -path "$ciphers_path\Triple DES 168" 
if($global:validation_counter -eq 1)
{
log "Triple DES 168 Cipher configuration rollback completed"
}
else
{
log "Triple DES 168 cipher configuration rollback failed!!" 
Write-Host "Triple DES 168 cipher configuration rollback failed!!" 
write-host("`n")
Write-Host "Check the log details in C:\SECURITY_CONFIGURATION\tls1_2_config_rollback_log-$logtimestamp.log"
Exit(1)
}
}
hash_config{
#script for Rollback of hash configuration
log "Hashing algorithm configuration rollback started"
write-host("`n")
Write-Host "Hashing algorithm configuration rollback started"
#creating an array with list of hashes configuration to rollback
$hashes_list=@("MD2","MD4","MD5","SHA1")
$hash_path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"
$global:validation_counter=0
foreach ($hash in $hashes_list)
{
remove-key -path $hash_path\$hash 
}
if($global:validation_counter -eq 4)
{
log "Hashing algorithm configuration rollback completed"
write-host("`n")
Write-Host "Hashing algorithm configuration rollback completed"
write-host("`n")
}
else
{
log "Hashing algorithm configuration rollback failed!!"
Write-Host "Hashing algorithm configuration rollback failed!!"
write-host("`n")
Write-Host "Check the log details in C:\SECURITY_CONFIGURATION\tls1_2_config_rollback_log-$logtimestamp.log"
Exit(1)
}
}
protocol_config{
#script for rollback of PCT ,SSL 3.0,TLS 1.0,TLS 1.1 Protocols configuration
log "Protocol configuration rollback started"
Write-Host "Protocol configuration rollback started"
write-host("`n")
$protocols_path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$Protocols_list=@("PCT 1.0","SSL 3.0","TLS 1.0","TLS 1.1")
$global:validation_counter=0
foreach ($global:protocol in $Protocols_list)
{
remove-key -path $protocols_path\$protocol 
}
}
tls_1_2{
log "TLS 1.2 Protocol configuration rollback started"
$protocols_path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
remove-key -path "$protocols_path\TLS 1.2"
if ($global:validation_counter -eq 5)
{
log "TLS 1.2 Protocol configuration rollback completed"
}
else
{
log "TLS 1.2 Protocol configuration rollback Failed!!"
Write-Host "TLS 1.2 configuration rollback failed!!"
Write-Host "Check the log details in C:\SECURITY_CONFIGURATION\tls1_2_config_rollback_log-$logtimestamp.log"
}
}
ssl_2_0{
log "SSL 2.0 server Sub-key removal started"
remove-key -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
if ($global:validation_counter -eq $rollback_success)
{
log "SSL 2.0 server sub-key removal completed"
log "Protocol configuration rollback completed"
Write-Host "Protocol configuration rollback completed"
}
else
{
log "SSL 2.0 server sub-key removal Failed!!"
log "Protocol configuration rollback Failed!!"
Write-Host "Protocol configuration rollback Failed!!"
Write-Host "Check the log details in C:\SECURITY_CONFIGURATION\tls1_2_config_rollback_log-$logtimestamp.log"
Exit(1)
}
}
tls_default{
log "TLS 1.2 Default secure protocols D-word removal started"
if (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp")
{
try{
Remove-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -name "DefaultSecureProtocols" -ErrorAction Stop
log "TLS 1.2 Default secure protocols D-word removal completed"
}
catch{
log "TLS 1.2 Default secure protocols D-word removal failed!!"
Write-Host "TLS 1.2 configuration rollback failed!!"
write-host("`n")
Write-Host "Check the log details in C:\SECURITY_CONFIGURATION\tls1_2_config_rollback_log-$logtimestamp.log"
Exit(1)
}
}
else
{
log "Path for Default secure protocols D-word is not available"
}
}
print_status{
write-host("`n")
Write-Host "Script execution completed,find the log details in C:\SECURITY_CONFIGURATION\tls1_2_config_rollback_log-$logtimestamp.log"
write-host("`n")
Write-Host "Restart the machine for changes to be effective"
write-host("`n")
Write-Host "*********************************************************"
Write-Host "       TLS 1.2 Configuration Rollback Completed                    "
Write-Host "*********************************************************"
}
}



 
