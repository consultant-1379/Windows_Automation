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
# Name     : tls_1_2_Configuration
# Purpose : Automation for Enforcing TLS 1.2 on Windows Servers
# Last updated : 16-Sep-2019
#
# *************************************************************************

$logtimestamp=$([datetime]::Now).ToString("yyyy-MM-dd_HH_mm_ss")
$log="C:\SECURITY_CONFIGURATION\tls1_2_config_log-$logtimestamp.log"
#Function to create logging
function log($logmessage) {
   $TimeStamp = Get-Date -format yyyy-MM-dd_HH_mm_ss
   $TimeStamp + " : " + $logmessage | out-file -Filepath $log -append -Force
}
log "TLS 1.2 configuration script Started.."
$Working_dir=Get-Location
cd HKLM:
#Checking if the machine is installed with Virtual Delivery Agent
if( Test-Path -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Virtual Desktop Agent" ) 
{
log "The machine has VDA installed"
$option=@("cipher_config","triple_des_168","hash_config","protocol_config","tls_1_2_config","print_status")
}
else
{
log "The machine doesn't contain VDA Installation"
$option=@("cipher_config","triple_des_168","hash_config","protocol_config","tls_1_2_config","print_status")
}
Write-Host "*********************************************************"
Write-Host "           TLS 1.2 Configuration Started                    "
Write-Host "*********************************************************"
#Function to test registry d-word entries are present
function Test-RegVal{
param (
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$Path,
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$key_name,
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$value
)
try{
$validation_counter = 0
Get-Item -Path "$Path\$key_name" -ErrorAction Stop | Select-Object -ExpandProperty property | % { if ($_ -match $value) 
{ $validation_counter=1 
  return $true
} }
}
catch{
log "$key_name $value D-word NOT Found "
if ($validation_counter -eq 0) 
{return $false}
}
}
#Function to read the d-word values
function Test-dwordVal{
param (
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$full_Path,
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$key_name,
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$d_name
)
try{
($d_wordval = (Get-ItemProperty -path "$full_path\$key_name" -Name $d_name -ErrorAction Stop).$d_name) 2> $null | Out-Null
log "$d_name D-word value is: $d_wordval"
return $d_wordval
}
catch{
log "Failed to identify $key_name $d_name value"
}
}

#Function to check and create keys 
function create-key{
param (
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$full_Path,
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$key_name,
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$dword_name,
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$dword_value
)
if ( Test-Path -Path "$full_Path\$key_name" )
{
log "$key_name is available"
#calling the Function to check for availability of D-word
$dword_Check=Test-RegVal -Path "$full_path" -key_name "$key_name" -value "$dword_name"
        if ( $dword_Check -eq "True" )
        {
        log "$key_name $dword_name D-word is available"
#Calling the function to Reading the value of the D-word
        $get_dwordval=Test-dwordval -full_Path "$full_Path" -key_name "$key_name" -d_name $dword_name
#Checking if the D-word value is as expected
            if ( "$get_dwordval" -eq "$dword_value" )
            {
            log "$key_name $dword_name D-word value is as expected "
            }
            else
            {
            try{
            log "$key_name $dword_name D-word is not as expected"
            Set-ItemProperty -path "$full_path\$key_name" -Name "$dword_name"  -Value "$dword_value" -ErrorAction Stop | Out-Null
            log "$key_name $dword_name D-word value is updated " 
            }
            catch{
            log "Failed to update $key_name $dword_name"
            Write-Host "Failed to update $key_name $dword_name"
            }
            }
        }
    else
        {
#Creating the  D-words if not available
 try{
        log "$key_name $dword_name D-word is not available"
        New-ItemProperty -path "$full_path\$key_name" -Name "$dword_name" -Value "$dword_value" -PropertyType DWORD -ErrorAction Stop| Out-Null
        log "$key_name $dword_name D-word is created and value is set "
      }
 catch{
      log "Failed to create $key_name $dword_name D-word"
      Write-Host "Failed to create $key_name $dword_name D-word"
      }
    }
    }
    else
    {
#creating the key's and D-words if not available
    log "$key_name is not available" 
    reg add "$full_path\$key_name" /v $dword_name /t REG_DWORD /d $dword_value  | Out-Null
    if ($?){ log "operation to create key and D-word was successful"}else{log "operation to create key and D-word failed!!";Write-Host "operation to create key and D-word failed!!"}
}
}
switch ($option){
cipher_config{
########################Script for checking the availability of ciphers and if not available disable#################################
log "Ciphers configuration started"
Write-Host "Ciphers configuration started"
#storing the ciphers to be disabled in an array
$ciphers_list=@("RC4 128/128","RC4 56/128","RC4 40/128","RC4 64/128")
$cipher_path="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
foreach ($cipher in $ciphers_list)
{
create-key -full_path "$cipher_path" -key_name "$cipher" -dword_name "Enabled" -dword_value "0"
}
log "Ciphers configuration completed"
write-host("`n")
Write-Host "Ciphers configuration completed"
}
triple_des_168{
##########################Script for checking the availability of Triple DES 168 cipher and if not available create/disable######################
log "Triple DES 168 cipher configuration started"
#storing the ciphers to be disabled in an array
$cipher_path="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
#calling the Function to check and create key's, D-word's 
create-key -full_path "$cipher_path" -key_name "Triple DES 168" -dword_name "Enabled" -dword_value "0"
log "Triple DES 168 cipher Configuration completed"
}
hash_config{
########################Script for disabling weak hashing algorithms#######################################
log "Hashing algorithms configuration started"
write-host("`n")
Write-Host "Hashing algorithms configuration started"
#Storing the hashes to be disabled into array
$hashes_list=@("MD2","MD4","MD5","SHA1")
$hash_path="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"
    foreach ($hash in $hashes_list)
    {
#Calling the function to check and create key's , D-words
    create-key -full_path "$hash_path" -key_name "$hash" -dword_name "Enabled" -dword_value "0"
    }
    log "Hashing algorithms configuration completed"
    write-host("`n")
    Write-Host "Hashing algorithms configuration completed"
}
protocol_config{
######################Script to Disable weak Protocols#####################################
log "Protocols configuration started"
write-host("`n")
Write-Host "Protocols configuration started"
$protocols_path="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
#Storing the Protocols to be disabled in an array
$Protocols_list=@("PCT 1.0","SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1")
#storing the sub-key's for each protocol in array
$protocols_subkey=@("Client","Server")
    foreach ($protocol in $Protocols_list)
    {
#Checking for the availability of protocol related Key
        if (Test-Path -Path "$protocols_path\$protocol" )
        {
        log "$protocol key is available"
            foreach ($subkey in $protocols_subkey)
	        {
#calling function to check and created sub-key's and D-words
            	create-key -full_Path "$protocols_path\$protocol" -key_name "$subkey" -dword_name "Enabled" -dword_value "0"
            	create-key -full_Path "$protocols_path\$protocol" -key_name "$subkey" -dword_name "DisabledByDefault" -dword_value "1"
           	}
        }
        else
        {
#Creating key's, sub-keys and D-word's if not available
            foreach ( $subkey in $protocols_subkey )
            {
            reg add "$protocols_path\$protocol\$subkey" /v Enabled /t REG_DWORD /d 0 | Out-Null
            if ($?){ log "operation to create $protocol $subkey Enabled D-word is successful"}
                    else{log "operation to create $protocol $subkey Enabled D-word is failed!!"
                         Write-Host "operation to create $protocol $subkey Enabled D-word is failed!!"}
     	    reg add "$protocols_path\$protocol\$subkey" /v DisabledByDefault /t REG_DWORD /d 1 | Out-Null
            if ($?){ log "operation to create $protocol $subkey DisabledByDefault D-word is successful"}
                    else{log "operation to create key $protocol $subkey DisabledByDefault D-word failed!!"
                         Write-Host "operation to create key $protocol $subkey DisabledByDefault D-word failed!!"}
	    }
        }
    }
     log "Protocols configuration completed"
}
tls_1_2_config{
#######################Script for Enabling and Enforcing TLS 1.2#######################################
log "TLS 1.2 Protocol configuration started"
#Write-Host "TLS 1.2 Protocol configuration script started"
$protocols_path="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
#Storing the Sub-key's of protocol in an array
$protocols_subkey=@("Client","Server")
#Verifying if the TLS 1.2 Protocol Key is available
    if (Test-Path -Path "$protocols_path\TLS 1.2")
    {
    log "TLS 1.2 protocol key is available"
    		foreach ($subkey in $protocols_subkey)
	    	{
#calling function to check and create sub-key's and D-word's
        	create-key -full_Path "$protocols_path\TLS 1.2" -key_name $subkey -dword_name "Enabled" -dword_value "1"
        	create-key -full_Path "$protocols_path\TLS 1.2" -key_name $subkey -dword_name "DisabledByDefault" -dword_value "0"
        	}
#Enforce TLS 1.2 as Default Secure Protocol
        log "Enforcing TLS 1.2 as Default Secure Protocol"
#Storing the Default Secure Protocols Path
        $tls1_2_path="HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings"
#Checking if the path exists
        if (Test-Path -Path "$tls1_2_path\WinHttp")
        {
#calling the Function to check and create key and D-word
        create-key -full_Path "$tls1_2_path" -key_name "WinHttp" -dword_name "DefaultSecureProtocols" -dword_value 0x00000800
        }
        else
        {
#Creating a key and D-word if not available, set the required value to enable TLS 1.2 default
            reg add "$tls1_2_path\WinHttp" /v DefaultSecureProtocols /t REG_DWORD /d 0x00000800 | Out-Null
            if($?) {log "TLS 1.2 is set as Default Secure Protocol"}
              else {log "Failed to set TLS 1.2 as Default secure Protocol"
                    Write-Host "Failed to set TLS 1.2 as Default secure Protocol"}
        }
    }
        
    else
    {
#If TLS 1.2 protocol key is not available, creating the key,sub-key's and D-words as required
    	foreach ( $subkey in $protocols_subkey )
    	{
    	reg add "$protocols_path\TLS 1.2\$subkey" /v Enabled /t REG_DWORD /d 1 | Out-Null
    	if ($?){ log "operation to create $subkey Enabled D-word is successful"}
    	else{log "operation to create $subkey Enabled D-word  failed!!"
    	Write-Host "operation to create $subkey Enabled D-word  failed!!"}
	reg add "$protocols_path\TLS 1.2\$subkey" /v DisabledByDefault /t REG_DWORD /d 0 | Out-Null
    	if ($?){ log "operation to create $subkey DisabledByDefault D-word is successful"}
    	else{log "operation to create $subkey DisabledByDefault D-word failed!!"
    	Write-Host "operation to create $subkey DisabledByDefault D-word failed!!" }
    	}
#Enforcing TLS 1.2 as Default Secure Protocol
        log "Enforcing TLS 1.2 as Default Secure Protocol"
#Storing the Default Secure Protocols Path
        $tls1_2_path="HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings"
#Checking if the path exists       
        if (Test-Path -Path $tls1_2_path)
        {
#calling the Function to check and create key and D-word
        create-key -full_Path "$tls1_2_path" -key_name "WinHttp" -dword_name "DefaultSecureProtocols" -dword_value 0x00000800
        }
        else
        {
        reg add "$tls1_2_path\WinHttp" /v DefaultSecureProtocols /t REG_DWORD /d 0x00000800 | Out-Null
        if ($?){ log "operation to set TLS 1.2 as Default secure Protocol is successful"}
        else{log "operation to set TLS 1.2 as Default secure Protocol failed!!"
        Write-Host "operation to set TLS 1.2 as Default secure Protocol failed!!"}
        }
       }
log "TLS 1.2 Protocol configuration completed"
write-host("`n")
Write-Host "Protocols configuration completed"
}
print_status{
write-host("`n")
Write-Host "Script execution completed,find the log details in C:\SECURITY_CONFIGURATION\tls1_2_config_log-$logtimestamp.log"
write-host("`n")
Write-Host "Restart the machine for changes to be effective"
write-host("`n")
cd $Working_dir
Write-Host "*********************************************************"
Write-Host "           TLS 1.2 Configuration Completed                   "
Write-Host "*********************************************************"
   }
}



