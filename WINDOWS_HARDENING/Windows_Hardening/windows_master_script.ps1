
#------------------------------------------------
# Function to print date and time in log file
#------------------------------------------------
function PrintDateTime()
{    
    "----------------------------------------------- " >>$Log 
    Get-Date -Format "dddd [MM/dd/yyyy] [HH:mm:ss]" >>$Log
    "----------------------------------------------- " >>$Log      
}

#------------------------------------------------
# Function to initiate action and reset variables
#------------------------------------------------

Function PrintActionAndResetVariables()
{
	$script:output_obj = New-Object System.Object	
}

#------------------------------------------------
# Function to verify media is not present or not
#------------------------------------------------

function CheckMedia()
{         
    if(($global:BISServerCheck -eq "True") -OR ($global:VDAServer -eq "True") -OR ($global:OCSwithoutCitrixServer -eq "True"))
    {
        $WindowsMedia = "C:\ebid\ebid_medias\WINDOWS_HARDENING.iso"
    }
    elseif($global:OCSServer -eq "True")
    {
        $WindowsMedia = "C:\Windows_Hardening\WINDOWS_HARDENING.iso"
    }

    if(Test-Path -Path $WindowsMedia)
    {
        if((Get-DiskImage -ImagePath $WindowsMedia).Attached)
        {
 	        "Media: $WindowsMedia already mounted" >>$Log
 	        $global:DriveLetter = (Get-DiskImage -ImagePath $WindowsMedia | Get-Volume).DriveLetter
 	        $global:DriveLetter = $global:DriveLetter + ":\"
        }
        else
        {
 	        "Media: $WindowsMedia Not mounted and mounting..." >>$Log
 	        $global:DriveLetter = (Mount-DiskImage -ImagePath $WindowsMedia -PassThru | Get-Volume).DriveLetter        
 	        $global:DriveLetter = $global:DriveLetter + ":\"        
        }
        "Windows Hardening drive $global:DriveLetter" >>$Log
    }    
    else
    {
        "Windows media not available in $WindowsMedia path. Please place media in correct path and execute script again" >>$Log
        Write-Host "Windows media not available in $WindowsMedia path. Please place media in correct path and execute script again"
        if($global:BISServerCheck -eq "True")
        {
            return $false
        }        
        exit
    }   
}

#------------------------------------------------
# Function to Copy latest folders from media
#------------------------------------------------

function CopyLatestFolders()
{
    PrintDateTime
    if(Test-Path -Path ($global:DriveLetter+"Firewall"))
    {
        $SourceDirectory = $global:DriveLetter+"Firewall"
        $DestinationDirectory = "C:\"
        CopyFolder $SourceDirectory $DestinationDirectory
        if(Test-Path -Path ($DestinationDirectory+"Firewall"))
        {
            "Firewall folder copied successfully" >>$Log
        }
    } 
	if(Test-Path -Path ($global:DriveLetter+"Certificate-expiry"))
    {
        $SourceDirectory = $global:DriveLetter+"Certificate-expiry"
        $DestinationDirectory = "C:\"
        CopyFolder $SourceDirectory $DestinationDirectory
        if(Test-path -Path ($DestinationDirectory+"Certificate-expiry"))
        {
            "Certificate-expiry folder copied successfully" >>$Log
        }
    }
    if(Test-Path -Path ($global:DriveLetter+"group_policy"))
    {
        $SourceDirectory = $global:DriveLetter+"group_policy"
        $DestinationDirectory = "C:\"
        CopyFolder $SourceDirectory $DestinationDirectory
        if(Test-Path -Path ($DestinationDirectory+"group_policy"))
        {
            "group_policy folder copied successfully" >>$Log
        }
    }
    if(Test-Path -Path ($global:DriveLetter+"SECURITY_CONFIGURATION"))
    {
        $SourceDirectory = $global:DriveLetter+"SECURITY_CONFIGURATION"
        $DestinationDirectory = "C:\"
        CopyFolder $SourceDirectory $DestinationDirectory
        if(Test-Path -Path ($DestinationDirectory+"SECURITY_CONFIGURATION"))
        {
            "SECURITY_CONFIGURATION folder copied successfully" >>$Log
        }
    }
}

#------------------------------------------------
# Function to copy folders
#------------------------------------------------

Function CopyFolder($SourceDirectory, $DestinationDirectory)
{
    try
    {
	    copy-item -path $SourceDirectory -destination $DestinationDirectory -Recurse -Force	    
    }
    catch
	{
		$_ >>$Log
		"`nException in CopyFolder function" >>$Log
		Write-Host "`nError!! Check $Log for more details."		
	}
}

#------------------------------------------------
# Function for Disabling weak ciphers script
#------------------------------------------------

function DisableWeakCiphers()
{
    PrintDateTime
    PrintActionAndResetVariables
	"Disable Weak Ciphers, Protocols, and Hashes" >>$Log    
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Disable Weak Ciphers, Protocols, and Hashes"
    #powershell.exe -executionpolicy unrestricted -file C:\SECURITY_CONFIGURATION\tls_1_2_configuration.ps1
	try
	{
		Invoke-Expression "C:\SECURITY_CONFIGURATION\tls_1_2_configuration.ps1"
	}
	catch
	{
		$_ >>$Log
	}    
    #Start-Sleep -Seconds 10
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
    $script:output_table += $script:output_obj
	$Script:TaskValue = $Script:TaskValue + 1
}

#------------------------------------------------
# Function for Rollback of Disable weak ciphers script
#------------------------------------------------

function RollbackDisableWeakCiphers()
{
    PrintDateTime
    PrintActionAndResetVariables
	"Rollback of Disable Weak Ciphers, Protocols, and Hashes" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Rollback Disable Weak Ciphers, Protocols, and Hashes"
    #powershell.exe -executionpolicy unrestricted –file C:\SECURITY_CONFIGURATION\tls_1_2_config_rollback.ps1    
	try
	{
		Invoke-Expression "C:\SECURITY_CONFIGURATION\tls_1_2_config_rollback.ps1"
	}
	catch
	{
		$_ >>$Log
	}
    #Start-Sleep -Seconds 10
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
    $script:output_table += $script:output_obj
	$Script:TaskValue = $Script:TaskValue + 1
}

function rollback_old_disableweakciphers()
{
	PrintDateTime
    PrintActionAndResetVariables
	"checking if weak ciphers are disabled" >>$Log
	try
	{
		if(Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4*")
		{
			"Weak ciphers are disabled as part of previous ii/upgrade, rolling back as it is requied for Remote connection broker installation." >>$Log
			Invoke-Expression "C:\SECURITY_CONFIGURATION\tls_1_2_config_rollback.ps1"
		}
		else
		{
			"Weak Ciphers are not disabled. Proceeding.. ">>$Log
		}	
	}
	catch
	{
		$_ >>$Log
	}
}


#------------------------------------------------
# Function for calling enabling group policy script
#------------------------------------------------

function EnableGroupPolicy()
{    
    PrintDateTime
    PrintActionAndResetVariables
	$GroupPolicyStatus = "Failed"
    "Enabling Group policy" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enable Password Policies"
    $argumentList = "Enable"    
	try
	{
		$GroupPolicyStatus = Invoke-Expression "$GroupPolicy $argumentList"
		"GP STATUS $GroupPolicyStatus" >>$Log
	}
	catch
	{
		$_ >>$Log	
	}
	"`n Group Policy status $GroupPolicyStatus" >>$Log    
    if($GroupPolicyStatus -eq "Failed")
	{
		"`nExecution of $GroupPolicy (Enable GroupPolicy) Failed. Check C:\group_policy\log\Group_Policy_Enable-* for more details" >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}		
	elseif($GroupPolicyStatus -eq "Success")
	{
		"`nExecution of $GroupPolicy is completed and Enable GroupPolicy is successful. Proceeding to next stage.." >>$Log	
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"	
		$Script:TaskValue = $Script:TaskValue + 1
	}
	else
	{
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}
    $script:output_table += $script:output_obj
}

#------------------------------------------------
# Function for calling disabling group policy script
#------------------------------------------------

function DisableGroupPolicy()
{
    PrintDateTime
    PrintActionAndResetVariables
	$GroupPolicyStatus = "Failed"
	"Disabling Group policy" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Disable Password Policies"
    $argumentList = "Disable"    
	try
	{
		$GroupPolicyStatus = Invoke-Expression "$GroupPolicy $argumentList"
		"GP STATUS $GroupPolicyStatus" >>$Log
	}
	catch
	{
		$_ >>$Log
	}
    Write-Host "`n Group Policy status $GroupPolicyStatus"
    if($GroupPolicyStatus -eq "Failed")
	{
		"`nExecution of $GroupPolicy (Disable GroupPolicy) Failed. Check C:\group_policy\log\Group_Policy_Disable-* for more details" >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}		
	elseif($GroupPolicyStatus -eq "Success")
	{
		"`nExecution of $GroupPolicy is completed and Disable GroupPolicy is successful. Proceeding to next stage.." >>$Log		
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
		$Script:TaskValue = $Script:TaskValue + 1
	}
	else
	{
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}
    $script:output_table += $script:output_obj
}

#---------------------------------------------------------
#Function for calling enabling certificate expiry script
#---------------------------------------------------------

function EnableCertificateExpiry()
{
	PrintDateTime
	PrintActionAndResetVariables
	$CertificateExpiryStatus = "Failed"
	"Enabling Certificate-expiry" >>$Log
	$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enable Certificate-expiry"
	try
	{
		$CertificateExpiryStatus = Invoke-Expression "$CertificateExpiryScript"
		"CertificateExpiryStatus STATUS $CertificateExpiryStatus" >>$Log
	}
	catch
	{
		$_ >>$Log
	}
	"`n Enable Certificate-expiry Status $CertificateExpiryStatus">>$Log
	Write-Host "`n Enable Certificate-expiry Status $CertificateExpiryStatus"
	if($CertificateExpiryStatus -eq "Failed")
	{
		"`nExecution of $CertificateExpiryScript (Enable Certificate-expiry) Failed. Check C:\Certificate-expiry\log\Schedule_task_EnableCertificateExpiry-* for more details" >>$Log
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}
	elseif($CertificateExpiryStatus -eq "Success")
	{
		"`nExecution of $CertificateExpiryScript is completed and Enable Certificate-expiry is successful. Proceeding to next stage.." >>$Log	
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"	
		$Script:TaskValue = $Script:TaskValue + 1
	}
	else
	{
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}
	$script:output_table += $script:output_obj
}

#------------------------------------------------
# Function for calling enabling firewall script
#------------------------------------------------

function EnableFirewall()
{    
    PrintDateTime
    PrintActionAndResetVariables
	$FirewallStatus = "Failed"
	"Enabling Firewall" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enable Firewall and Ports"
    $argumentList = "EnableFirewall"    
	try
	{
		$FirewallStatus = Invoke-Expression "$FirewallScript $argumentList"
		"FirewallStatus STATUS $GroupPolicyStatus" >>$Log
	}
	catch
	{
		$_ >>$Log
	}
	"`n Enable Firewall status $FirewallStatus" >>$Log
    Write-Host "`n Enable Firewall status $FirewallStatus"
    if($FirewallStatus -eq "Failed")
	{
		"`nExecution of $FirewallScript (Enable Firewall) Failed. Check C:\Firewall\log\Firewall_Settings_EnableFirewall-* for more details" >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}		
	elseif($FirewallStatus -eq "Success")
	{
		"`nExecution of $FirewallScript is completed and Enable Firewall is successful. Proceeding to next stage.." >>$Log	
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"	
		$Script:TaskValue = $Script:TaskValue + 1
	}
	else
	{
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}
    $script:output_table += $script:output_obj
}

#------------------------------------------------
# Function for calling disabling firewall script
#------------------------------------------------

function DisableFirewall()
{    
    PrintDateTime
    PrintActionAndResetVariables
	$FirewallStatus = "Failed"
	"Disalbing Firewall" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Disable Firewall and Ports"
    $argumentList = "DisableFirewall"    
	try
	{
		$FirewallStatus = Invoke-Expression "$FirewallScript $argumentList"
		"FirewallStatus STATUS $GroupPolicyStatus" >>$Log
	}
	catch
	{
		$_ >>$Log
	}
	"`n Disable Firewall status $FirewallStatus" >>$Log
    Write-Host "`n Disable Firewall status $FirewallStatus"
    if($FirewallStatus -eq "Failed")
	{
		"`nExecution of $FirewallScript (Disable Firewall) Failed. Check C:\Firewall\log\Firewall_Settings_DisableFirewall-* for more details" >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}		
	elseif($FirewallStatus -eq "Success")
	{
		"`nExecution of $FirewallScript is completed and Disable Firewall is successful. Proceeding to next stage.." >>$Log	
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"	
		$Script:TaskValue = $Script:TaskValue + 1
	}
	else
	{
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}
    $script:output_table += $script:output_obj
}

#------------------------------------------------
# Function for calling block ICMP script
#------------------------------------------------

function BlockICMP()
{
    PrintDateTime
    PrintActionAndResetVariables
	$FirewallStatus = "Failed"
	"Block ICMP " >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Block ICMP Vulnerabilities"
    $argumentList = "BlockICMP"
    try
	{
		$FirewallStatus = Invoke-Expression "$FirewallScript $argumentList"
		"FirewallStatus STATUS $GroupPolicyStatus" >>$Log
	}
	catch
	{
		$_ >>$Log
	}
	"`n BlockICMP status $FirewallStatus" >>$Log
    Write-Host "`n BlockICMP status $FirewallStatus"
    if($FirewallStatus -eq "Failed")
	{
		"`nExecution of $FirewallScript (Block ICMP) Failed. Check C:\Firewall\log\Firewall_Settings_BlockICMP-* for more details" >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}		
	elseif($FirewallStatus -eq "Success")
	{
		"`nExecution of $FirewallScript is completed and Block ICMP is successful. Proceeding to next stage.." >>$Log	
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"	
		$Script:TaskValue = $Script:TaskValue + 1
	}
	else
	{
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}
    $script:output_table += $script:output_obj
}

#------------------------------------------------
# Function for calling unblock ICMP script
#------------------------------------------------

function UnblockICMP()
{
    PrintDateTime
    PrintActionAndResetVariables
	$FirewallStatus = "Failed"
	"UnBlock ICMP " >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Unblock ICMP Vulnerabilities"
    $argumentList = "UnblockICMP"
    try
	{
		$FirewallStatus = Invoke-Expression "$FirewallScript $argumentList"
		"FirewallStatus STATUS $GroupPolicyStatus" >>$Log
	}
	catch
	{
		$_ >>$Log
	}
	"`n Unblock ICMP status $FirewallStatus" >>$Log
    Write-Host "`n Unblock ICMP status $FirewallStatus"
    if($FirewallStatus -eq "Failed")
	{
		"`nExecution of $FirewallScript (UNBlock ICMP) Failed. Check C:\Firewall\log\Firewall_Settings_UnblockICMP-* for more details" >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}		
	elseif($FirewallStatus -eq "Success")
	{
		"`nExecution of $FirewallScript is completed and Block ICMP is successful. Proceeding to next stage.." >>$Log	
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"	
		$Script:TaskValue = $Script:TaskValue + 1
	}
	else
	{
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}
    $script:output_table += $script:output_obj
}

#------------------------------------------------
# Function to get Autorun value for BO
#------------------------------------------------

function Get-AutoRunValues()
{
    "Status of Autorun Values" >>$Log
	try
	{
		if([bool](Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutorun -ErrorAction SilentlyContinue))
		{
			try
			{
				$AutorunValue = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutorun -ErrorAction SilentlyContinue).NoDriveTypeAutorun
				if($AutorunValue -eq 255)
				{
					"Autorun value is already configured" >>$Log
					return $true
				}
				else
				{
					"Autorun value is already configured, but with different value" >>$Log
					return $false
				}
			}
			catch
			{
				$_ >>$Log
				return $false
			}			
		}   
		else
		{
			"Autorun value is not configured" >>$Log
			return $false
		}  
	}
	catch
	{
		$_ >>$Log
		return $false
	}      
}

#------------------------------------------------
# Function to set Autorun value for BO
#------------------------------------------------

function EnableAutorunBO()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Enabling Autorun" >>$Log
	try
	{
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enabling Autorun"
		if([bool](Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutorun -ErrorAction SilentlyContinue))
		{
			try
			{
				Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutorun 
				"Enable of Autorun value is successful" >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
				$Script:TaskValue = $Script:TaskValue + 1
			}
			catch
			{
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}        
		}
		else
		{
			"Enable of Autorun value is successful" >>$Log
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
	}
	catch
	{
		$_ >>$Log
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}
    $script:output_table += $script:output_obj
}

#------------------------------------------------
# Function to get Autoplay value for BO
#------------------------------------------------

function Get-AutoPlayValues()
{
    "Status of AutoPlayValues" >>$Log
	try
	{
		if([bool](Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoAutorun -ErrorAction SilentlyContinue))
		{
			$AutoPlayValue = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoAutorun -ErrorAction SilentlyContinue).NoAutorun
			if($AutoPlayValue -eq 255)
			{
				"AutoPlay value is already configured" >>$Log
				return $true
			}
			else
			{
				"AutoPlay value is already configured, but with different value" >>$Log
				return $false
			}
		}   
		else
		{
			"AutoPlay value is not configured" >>$Log
			return $false
		}
	}
	catch
	{
		$_ >>$Log
		return $false
	}
    
    
}

#------------------------------------------------
# Function to set Autoplay value for BO
#------------------------------------------------

function EnableAutoPlayBO()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Enabling AutoPlay" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enabling AutoPlay"
	try
	{
		if([bool](Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoAutorun -ErrorAction SilentlyContinue))
		{
			try
			{
				Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoAutorun 
				"Enabling of AutoPlay is successful" >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
				$Script:TaskValue = $Script:TaskValue + 1
			}
			catch
			{
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}
			
		}
		else
		{
			"Enabling of AutoPlay is successful" >>$Log
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
	}
	catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj
}

#------------------------------------------------
# Function to remove Autoplay value for BO
#------------------------------------------------

function DisableAutoPlayBO()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Disabling AutoPlay" >>$Log
	$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Disabling AutoPlay"
    $AutoPlay = Get-AutoPlayValues 
	try
	{
		if($AutoPlay -eq $true)
		{
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
		else
		{
			try
			{
				Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoAutorun -Type DWord -Value 1
				if([bool](Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoAutorun -ErrorAction SilentlyContinue))
				{
					"Autoplay value configured successfully" >>$Log
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
					$Script:TaskValue = $Script:TaskValue + 1
				}
				else
				{
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                    $Script:ErrorCount = $Script:ErrorCount +1
				}
			}
			catch
			{
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}
		}  
	}
	catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj
}

#------------------------------------------------
# Function to remove Autorun value for BO
#------------------------------------------------

function DisableAutoRunBO()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Disabling Autorun" >>$Log    
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Disabling AutoRun"
	$Autorun = Get-AutoRunValues  
	try
	{	
		if($Autorun -eq $true)
		{
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
		else
		{
			try
			{
				Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutorun -Type DWord -Value 255            
				if([bool](Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutorun -ErrorAction SilentlyContinue))
				{
					"Autorun value configured successfully" >>$Log
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
					$Script:TaskValue = $Script:TaskValue + 1
				}
				else
				{
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                    $Script:ErrorCount = $Script:ErrorCount +1
				}
			}
			catch
			{
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}
		}  
	}
	catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj  
}

#------------------------------------------------
# Function to get max Idle time value for BO
#------------------------------------------------

function Get-MaxIdleTime()
{    
	try
	{
		if([bool](Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxIdleTime -ErrorAction SilentlyContinue))
		{
			try
			{
				$RDmaxIdleTime = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxIdleTime -ErrorAction SilentlyContinue).MaxIdleTime
				if($RDmaxIdleTime -eq 1800000)
				{
					"Remote desktop max idle timeout value is already configured" >>$Log
					return $true
				}
				else
				{
					"Remote desktop max idle timeout value is already configured, but with different value" >>$Log
					return $true
				}
			}
			catch
			{
				$_ >>$Log
				return $false
			}
		}   
		else
		{
			"Remote desktop max idle timeout value is not configured" >>$Log
			return $false
		}    
	}    
	catch
	{
		$_ >>$Log
		return $false
	}
}

#------------------------------------------------
# Function to set max Idle time value for BO
#------------------------------------------------

function SetRDMaxIdleTimeBO()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Setting Max Idle Time" >>$Log       
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enabling Remote Desktop Max Idle Time"
	$MaxIdleTime = Get-MaxIdleTime
	try
	{
		if($MaxIdleTime -eq $true)
		{
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
		else
		{
			try
			{
				Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxIdleTime -Type DWord -Value 1800000
				if([bool](Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxIdleTime -ErrorAction SilentlyContinue))
				{
					"MaxIdleTime value configured successfully" >>$Log
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
					$Script:TaskValue = $Script:TaskValue + 1
				}
				else
				{
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                    $Script:ErrorCount = $Script:ErrorCount +1
				}
			}
			catch
			{
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}
		}  
	}
	catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj  
}

#------------------------------------------------
# Function to get max session timeout value for BO
#------------------------------------------------

function Get-MaxSessionTimeout()
{    
	try
	{
		if([bool](Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxDisconnectionTime -ErrorAction SilentlyContinue))
		{
			$RDmaxIdleTime = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxDisconnectionTime -ErrorAction SilentlyContinue).MaxDisconnectionTime
			if($RDmaxIdleTime -eq 7200000)
			{
				"Remote desktop session timeout value is already configured" >>$Log
				return $true
			}
			else
			{
				"Remote desktop session timeout value is already configured, but with different value" >>$Log
				return $true
			}
		}   
		else
		{
			"Remote desktop session timeout value is not configured" >>$Log
			return $false
		}  
	}
	catch
	{
		$_ >>$Log
		return $false
	}         
}

#---------------------------------------------------------------------------
# Function to set max remote desktop session timeout value for BO
#---------------------------------------------------------------------------

function SetRDSessionTimeoutBO()
{
    PrintDateTime
    PrintActionAndResetVariables
	"`n Setting Remote Desktop Session Timeout" >>$Log    
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enabling Remote Desktop Session Timeout"
	$SessionTimeout = Get-MaxSessionTimeout
	try
	{
		if($SessionTimeout -eq $true)
		{
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
		else
		{
			try
			{
				Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxDisconnectionTime -Type DWord -Value 7200000
				if([bool](Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxDisconnectionTime -ErrorAction SilentlyContinue))
				{
					"MaxSessionTimeout value configured successfully" >>$Log
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
					$Script:TaskValue = $Script:TaskValue + 1
				}
				else
				{
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                    $Script:ErrorCount = $Script:ErrorCount +1
				}
			}
			catch
			{
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}
		}  
	}
	catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1                  
    }
    $script:output_table += $script:output_obj  
}

#----------------------------------------------------------
# Function to rollback max session timeout value for BO
#----------------------------------------------------------

function RollbackSessionTimeoutBO()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Rollback Remote Desktop Session Timeout" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Rollback Remote Desktop Session Timeout"
	try
	{
		if([bool](Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxDisconnectionTime -ErrorAction SilentlyContinue))
		{
			try
			{
				Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxDisconnectionTime
				"MaxSessionTimeout value removed successfully" >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
				$Script:TaskValue = $Script:TaskValue + 1
			}
			catch
			{
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}        
		}
		else
		{
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
	}
	catch
	{
		$_ >>$Log
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}
    
    $script:output_table += $script:output_obj
}

#----------------------------------------------------------
# Function to rollback max idle time value for BO
#----------------------------------------------------------

function RollbackMaxIdleTimeBO()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Rollback Max Idle Time" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Rollback Max Idle Time"
	try
	{
		if([bool](Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxIdleTime -ErrorAction SilentlyContinue))
		{
			try
			{
				Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxIdleTime 
				"MaxIdleTime value removed successfully" >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
				$Script:TaskValue = $Script:TaskValue + 1
			}
			catch
			{
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}
			
		}
		else
		{
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
	}
	catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj
}

#----------------------------------------------------------------------------
# Function to disable SMB protocol enabled at 20.4 level after upgrade
#----------------------------------------------------------------------------
function Disable-OldSMBProtocols()
{
    $CheckSMB1=$True
	$CheckSMB2=$True
    PrintDateTime
    PrintActionAndResetVariables
     "Disabling SMB Protocols if already enabled" >>$log
	try	
	{
		$CheckSMB1 = (Get-SmbServerConfiguration | Select-Object -Property EnableSMB1Protocol).EnableSMB1Protocol
		$CheckSMB2 = (Get-SmbServerConfiguration | Select-Object -Property EnableSMB2Protocol).EnableSMB2Protocol
	}
	catch
	{
	    "$_" >>$Log
		"Error occured in Get-SmbServerConfiguration command" >>$Log
	} 
	if((!$CheckSMB1) -and (!$CheckSMB2))
    { 
            Set-SmbServerConfiguration -EnableSMB1Protocol $True -Force
            Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force
			 "`n Disabled SMB Protocols [Enabled with old node hardening procedure]" >>$Log
    }
	elseif(($CheckSMB1) -and (!$CheckSMB2))
	{
            Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force
            "`n Disabled SMB2 Protocol [Enabled with old node hardening procedure]" >>$Log			
	}
	elseif((!$CheckSMB1) -and ($CheckSMB2))
	{
            Set-SmbServerConfiguration -EnableSMB1Protocol $True -Force 
            "`n Disabled SMB1 Protocol [Enabled with old node hardening procedure]" >>$Log			
	}
	else
	{
	    "`n SMB Protocols are at default state in this server." >>$Log	
    }
}

#----------------------------------------------------------
# Function to enable SMB protocol
#----------------------------------------------------------

function Get-SMBValue()
{
    try
    {        
        if([bool](Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue))
        {            
            try
            {
                $SMBSetValue = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
                if($SMBSetValue -eq 1)
                {
                    "SMB Value is already configured" >>$log
                    return $true
                }
                else
                {
                    "SMB Value is configured with different value" >>$log
                    return $false
                }
            }
            catch
            {
                $_ >>$log
                return $false
            }
        }
        else
        {
            "SMB Value is not configured" >>$log
            return $false
        }
    }
    catch
    {
        $_ >>$log
        return $false
    }

}

function EnableSMBProtocols()
{
    Disable-OldSMBProtocols
    PrintDateTime
    PrintActionAndResetVariables
    "Enabling SMB Protocols" >>$log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enabling SMB Protocols"
    $SMBValue = Get-SMBValue
    try
    {
        if($SMBValue)
        {
            "SMB Value configured successfully" >>$log
            $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
        }
        else
        {            
            try
			{
				Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" -Name "RequireSecuritySignature" -Value 1
				if([bool](Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue))
				{
					"SMB value configured successfully" >>$Log
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
					$Script:TaskValue = $Script:TaskValue + 1
				}
				else
				{
                    "SMB value configuration failed" >>$Log
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                    $Script:ErrorCount = $Script:ErrorCount +1
				}
			}
			catch
			{
                "SMB value configuration failed" >>$Log
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}
        }
    }
    catch
    {
        "SMB value configuration failed" >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj    
}

#----------------------------------------------------------
# Function to Disable SMB protocol
#----------------------------------------------------------
function DisableSMBProtocols()
{
    PrintDateTime
    PrintActionAndResetVariables
    "Disabling SMB Protocols" >>$log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Disabling SMB Protocols"
    try
    {        
        if([bool](Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue))
        {            
            try
            {
                $SMBSetValue = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
                if($SMBSetValue -eq 0)
                {                    
				    "SMB value configured successfully"  >>$log
				    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
				    $Script:TaskValue = $Script:TaskValue + 1                    
                }
                else
                {
                    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" -Name "RequireSecuritySignature" -Value 0
                    if([bool](Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue))
				    {
				    	"SMB value configured successfully" >>$log
				    	$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
				    	$Script:TaskValue = $Script:TaskValue + 1
				    }
				    else
				    {
                        "SMB value configuration failed" >>$log
				    	$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                        $Script:ErrorCount = $Script:ErrorCount +1
				    }
                }
            }
            catch
            {
                "SMB value configuration failed" >>$log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
                
            }
        }
        else
        {
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" -Name "RequireSecuritySignature" -Value 0
            if([bool](Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue))
			{
				"SMB value configured successfully" >>$log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
				$Script:TaskValue = $Script:TaskValue + 1
			}
			else
			{
                "SMB value configuration failed" >>$log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}
        }
    }
    catch
    {
        "SMB value configuration failed" >>$log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj    
}


#------------------------------------------------
# Function to get Autorun value for OCS
#------------------------------------------------

function Get-AutoRunValuesOCS()
{
    "Status of Autorun Values OCS" >>$Log    
    try
    {
        if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutorun" -ErrorAction SilentlyContinue))
        {
			try
			{
				$AutorunValue = (Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutorun" -ErrorAction SilentlyContinue).NoDriveTypeAutorun
				if($AutorunValue -eq 255)
				{
					"Autorun value is already configured" >>$Log
					return $true
				}
				else
				{
					"Autorun value is already configured, but with different value" >>$Log
					return $false
				}
			}
			catch
			{
				$_ >>$Log
				return $false
			}
        }   
        else
        {
            "Autorun value is not configured" >>$Log
            return $false
        }  
    }
    catch
    {
        $_ >>$Log
        return $false
    }  
}

#------------------------------------------------
# Function to set Autorun value for OCS
#------------------------------------------------

function DisableAutoRunOCS()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Disabling Autorun "
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Disabling AutoRun"
    $Autorun = Get-AutoRunValuesOCS  
	try
	{
		if($Autorun -eq $true)
		{
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
		else
		{
			try
			{
				Set-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutorun" -Type DWord -Value 255 >>$Log
				if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutorun" -ErrorAction SilentlyContinue))
				{
					"Autorun value configured successfully" >>$Log
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
					$Script:TaskValue = $Script:TaskValue + 1
				}
				else
				{
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                    $Script:ErrorCount = $Script:ErrorCount +1
				}
			}
			catch
			{
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}
		}
	}	
	catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj  
}

#------------------------------------------------
# Function to remove Autorun value for OCS
#------------------------------------------------

function EnableAutorunOCS()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Enabling Autorun" 
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enabling Autorun"
    try
    {
        if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutorun" -ErrorAction SilentlyContinue))
        {
            try
            {
                Remove-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutorun" >>$Log
				"Autorun value Removed successfully" >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
	    		$Script:TaskValue = $Script:TaskValue + 1
            }
            catch
            {
                $_ >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
            }
            
        }
        else
        {
            $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
	    	$Script:TaskValue = $Script:TaskValue + 1
        }
    }
    catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }    
    $script:output_table += $script:output_obj
}

#------------------------------------------------
# Function to get Autoplay value for OCS
#------------------------------------------------

function Get-AutoPlayValuesOCS()
{
    "Status of AutoPlayValues" >>$Log
    try
    {
        if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoAutorun" -ErrorAction SilentlyContinue))
        {
			try
			{
				$AutoPlayValue = (Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoAutorun" -ErrorAction SilentlyContinue).NoAutorun
				if($AutoPlayValue -eq 255)
				{
					"AutoPlay value is already configured" >>$Log
					return $true
				}
				else
				{
					"AutoPlay value is already configured, but with different value" >>$Log
					return $false
				}
			}
			catch
			{
				$_ >>$Log
				return $false
			}
        }   
        else
        {
            "AutoPlay value is not configured" >>$Log
            return $false
        }
    }
    catch
    {
        $_ >>$Log
        return $false
    }        
}

#------------------------------------------------
# Function to set Autoplay value for OCS
#------------------------------------------------

function DisableAutoPlayOCS()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Disabling AutoPlay "
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Disabling AutoPlay"
    $AutoPlay = Get-AutoPlayValuesOCS  
	try
	{
		if($AutoPlay -eq $true)
		{
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
		else
		{
			try
			{
				Set-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoAutorun" -Type DWord -Value 1 >>$Log
				"Autoplay value configured successfully" >>$Log
				if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoAutorun" -ErrorAction SilentlyContinue))
				{
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
					$Script:TaskValue = $Script:TaskValue + 1
				}
				else
				{
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"	
                    $Script:ErrorCount = $Script:ErrorCount +1			
				}
			}
			catch
			{
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}
		}
	}	
	catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj
}

#------------------------------------------------
# Function to remove Autoplay value for OCS
#------------------------------------------------

function EnableAutoPlayOCS()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Enabling AutoPlay " 
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enabling AutoPlay"
    try
    {
        if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoAutorun" -ErrorAction SilentlyContinue))
        {
            try
            {
                Remove-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoAutorun" >>$Log
				"Autoplay value removed successfully" >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
	    		$Script:TaskValue = $Script:TaskValue + 1
            }
            catch
            {
                $_ >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1                     
            }
            
        }
        else
        {
            $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
	    	$Script:TaskValue = $Script:TaskValue + 1
        }
    }
    catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1            
    }     
    $script:output_table += $script:output_obj
}

function GetNLA()
{
    try
    {
        $NLAValue = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $env:ComputerName -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired
	}
	catch
	{
		$_ >>$Log
		return $False
	}
    if($NLAValue -eq 1)
    {
        "Network Level Authentication Enabled ...." >>$Log
		return $true
	}
    else
    {
        "Network Level Authentication Disabled ...." >>$Log
		return $False
    }               
}
function EnableVDANLA()
{
    PrintDateTime
	PrintActionAndResetVariables
	"`n Enabling NLA for VDA server"  >>$Log  
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enable NLA"
    
    try
    {
        Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' -Name UserAuthentication -Value 1 -force
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
		$Script:TaskValue = $Script:TaskValue + 1
        
    }
    catch
    {
        $_ >>$Log
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj      
}

function DisableVDANLA()
{
    PrintDateTime
	PrintActionAndResetVariables
	"`n Disabling NLA for VDA server"  >>$Log 
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Disable NLA"
    try
    {
        Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' -Name UserAuthentication -Value 0 -force
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
		$Script:TaskValue = $Script:TaskValue + 1
        
    }
    catch
    {
        $_ >>$Log
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj      
    
}

function EnableNLA()
{   
	PrintDateTime
	PrintActionAndResetVariables
	"`n Enabling NLA for server"  >>$Log  
	$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enable NLA"
	$NLACheck = GetNLA	
	try
	{
		if($NLACheck -eq $true)
		{
			"Network Level Authentication Enabled" >>$Log
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
		else
		{
			"Network Level Authentication is Disabled and Enabling it" >>$Log
			try
			{
				(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $env:ComputerName -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1) | Out-Null
				"Network Level Authentication Enabled" >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
				$Script:TaskValue = $Script:TaskValue + 1
			}
			catch
			{
				$_ >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
			}        
		}
	}
	catch
	{
		$_ >>$Log
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
	}
	$script:output_table += $script:output_obj      
}

function DisableNLA()
{
    PrintDateTime
	PrintActionAndResetVariables
	"`n Disabling NLA for server"    
	$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Disable NLA"
	$NLACheck = GetNLA	
    if($NLACheck -eq $true)
    {
        "Network Level Authentication Enabled and Disabling it" >>$Log
		try
		{
			(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $env:ComputerName -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) | Out-Null
			"Network Level Authentication Disabled" >>$Log
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
            $Script:TaskValue = $Script:TaskValue + 1
		}
		catch
		{
			$_ >>$Log
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
            $Script:ErrorCount = $Script:ErrorCount +1
		}		
    }
    else
    {
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful" 
        $Script:TaskValue = $Script:TaskValue + 1  
    }
	$script:output_table += $script:output_obj
}

#------------------------------------------------
# Function to get max Idle time value for OCS
#------------------------------------------------

function Get-MaxIdleTimeOCS()
{   
    try
    {
        if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxIdleTime" -ErrorAction SilentlyContinue))
        {
			try
			{
				$RDmaxIdleTime = (Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxIdleTime" -ErrorAction SilentlyContinue).MaxIdleTime
				if($RDmaxIdleTime -eq 1800000)
				{
					"Remote desktop max idle timeout value is already configured" >>$Log
					return $true
				}
				else
				{
					"Remote desktop max idle timeout value is already configured, but with different value" >>$Log
					return $true
				}
			}
			catch
			{
				$_ >>$Log
				return $false
			}
        }   
        else
        {
            "Remote desktop max idle timeout value is not configured" >>$Log
            return $false
        }
    }
    catch
    {
        $_ >>$Log
        return $false
    }            
}

#------------------------------------------------
# Function to set max Idle time value for OCS
#------------------------------------------------

function SetRDMaxIdleTimeOCS()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Setting Max Idle Time" 
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enabling Remote Desktop Max Idle Time"
    $MaxIdleTime = Get-MaxIdleTimeOCS        
    if($MaxIdleTime -eq $true)
    {
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
        $Script:TaskValue = $Script:TaskValue + 1
    }
    else
    {
        try
        {
            Set-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxIdleTime" -Type DWord -Value 1800000 >>$Log
            if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxIdleTime" -ErrorAction SilentlyContinue))
            {
				"MaxIdleTime value configured successfully" >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
                $Script:TaskValue = $Script:TaskValue + 1
            }
            else
            {
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
            }
        }
        catch
        {
            $_ >>$Log
            $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
            $Script:ErrorCount = $Script:ErrorCount +1
        }
    }  
    $script:output_table += $script:output_obj  
}

#----------------------------------------------------------
# Function to rollback max idle time value for OCS
#----------------------------------------------------------

function RollbackMaxIdleTimeOCS()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Rollback Max Idle Time" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Rollback Max Idle Time"
    try
    {
        if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxIdleTime" -ErrorAction SilentlyContinue))
        {
            try
            {
                Remove-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxIdleTime" >>$Log
				"MaxIdleTime value removed successfully" >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
                $Script:TaskValue = $Script:TaskValue + 1
            }
            catch
            {
                $_ >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
            }
            
        }
        else
        {
            $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
            $Script:TaskValue = $Script:TaskValue + 1
        }
    }
    catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }    
    $script:output_table += $script:output_obj
}

#-----------------------------------------------------
# Function to get max session timeout value for OCS
#-----------------------------------------------------

function Get-MaxSessionTimeoutOCS()
{    
    try
    {
        if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxDisconnectionTime" -ErrorAction SilentlyContinue))
        {
			try
			{
				$RDmaxIdleTime = (Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxDisconnectionTime" -ErrorAction SilentlyContinue).MaxDisconnectionTime
				if($RDmaxIdleTime -eq 7200000)
				{
					"Remote desktop session timeout value is already configured" >>$Log
					return $true
				}
				else
				{
					"Remote desktop session timeout value is already configured, but with different value" >>$Log
					return $true
				}
			}
			catch
			{
				$_ >>$Log
				return $false
			}
        }   
        else
        {
            "Remote desktop session timeout value is not configured" >>$Log
            return $false
        } 
    }
    catch
    {
        $_ >>$Log
        return $false
    }           
}

#--------------------------------------------------------------------
# Function to set max remote desktop session timeout value for OCS
#--------------------------------------------------------------------

function SetRDSessionTimeoutOCS()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Setting Remote Desktop Session Timeout" 
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enabling Remote Desktop Session Timeout"
    $SessionTimeout = Get-MaxSessionTimeoutOCS    
    if($SessionTimeout -eq $true)
    {
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
        $Script:TaskValue = $Script:TaskValue + 1
    }
    else
    {
        try
        {
            Set-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxDisconnectionTime" -Type DWord -Value 7200000 >>$Log
            if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxDisconnectionTime" -ErrorAction SilentlyContinue))
            {
				"MaxSessionTimeout value configured successfully" >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
                $Script:TaskValue = $Script:TaskValue + 1
            }
            else
            {
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
            }
        }
        catch
        {
            $_ >>$Log
            $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
            $Script:ErrorCount = $Script:ErrorCount +1
        }
    }  
    $script:output_table += $script:output_obj  
}

#----------------------------------------------------------
# Function to rollback max session timeout value for OCS
#----------------------------------------------------------
function RollbackSessionTimeoutOCS()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Rollback Remote Desktop Session Timeout" 
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Rollback Remote Desktop Session Timeout"
    try
    {
        if([bool](Get-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxDisconnectionTime" -ErrorAction SilentlyContinue))
        {
            try
            {            
	            Remove-GPRegistryValue -Name "winharauto_gpo" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" -ValueName "MaxDisconnectionTime" >>$Log
				"MaxSessionTimeout value removed successfully" >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
                $Script:TaskValue = $Script:TaskValue + 1
            }
            catch
            {
                $_ >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
            }        
        }
        else
        {
            $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
            $Script:TaskValue = $Script:TaskValue + 1
        }
    }
    catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    
    $script:output_table += $script:output_obj
}

#------------------------------------------------------------------------
#Enable Remote Desktop Feature
#------------------------------------------------------------------------
function EnableRDInstallFeature()
{
    PrintDateTime
    PrintActionAndResetVariables
    "Create the Prototype Security Policy" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Create the Prototype Security Policy"
    try
    {
		try
		{
			Import-Module "Servermanager"
		}
		catch
		{
			$_ >>$Log
		}
        if($global:VDAServer -eq "True")
        {
            "Installing prototypes for VDA server" >>$Log
			try
			{
				$TotalRoles =@("remote-desktop-services","CMAK","RSAT-RDS-Licensing-Diagnosis-UI","RDS-Licensing-UI","RSAT-RemoteAccess-Mgmt","RSAT-RemoteAccess-PowerShell","WAS-Process-Model","WAS-Config-APIs")            
				foreach($Role in $TotalRoles)
				{
					PrintDateTime
					"`n RoleName $Role" >>$Log
					try
					{
						Install-WindowsFeature -Name $Role >>$Log
					}
					catch
					{
						$_ >>$Log
						"Unable to install $Role feature Please perform manually"  >>$Log
					}
				}
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
				$Script:TaskValue = $Script:TaskValue + 1
            }
            catch
            {
                $_ >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
            }
        }
        else
        {
            "Installing prototypes for server" >>$Log
            try
			{
				$TotalRoles =@("remote-desktop-services","CMAK","RSAT-RDS-Licensing-Diagnosis-UI","RDS-Licensing-UI","RSAT-RemoteAccess-Mgmt","RSAT-RemoteAccess-PowerShell","WAS-Process-Model","WAS-Config-APIs")
				foreach($Role in $TotalRoles)
                {
                    PrintDateTime
                    "`n RoleName $Role" >>$Log
                    try
                    {
                        Install-WindowsFeature -Name $Role
                    }
                    catch
                    {
                        $_ >>$Log
                        "Unable to install $Role feature Please perform manually"  >>$Log
                    }
                }
				try
                {      
					Install-WindowsFeature RDS-Connection-Broker -IncludeManagementTools >>$Log
                }
                catch
                {
                    $_ >>$Log
                    "Unable to install RDS-Connection-Broker feature Please perform manually"  >>$Log
                }
				try
                {
				
                    Install-WindowsFeature RDS-RD-Server -IncludeManagementTools >>$Log
                }
                catch
                {
                    $_ >>$Log
                    "Unable to install RDS-RD-Server feature Please perform manually"  >>$Log
                }
                try
                {
                    Install-WindowsFeature RDS-Licensing -IncludeManagementTools >>$Log
                }
                catch
                {
                    $_ >>$Log
                    "Unable to install RDS-Licensing feature Please perform manually"  >>$Log
                }
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
				$Script:TaskValue = $Script:TaskValue + 1	
			}
			catch
            {
                $_ >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
            }				
        }
    }
    catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj	
}

#------------------------------------------------------------------------
#Disable Remote Desktop Feature
#------------------------------------------------------------------------
function DisableRDInstallFeature()
{
    PrintDateTime
    PrintActionAndResetVariables
    "Rollback of Prototype Security Policy" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Rollback of Prototype Security Policy"
    try
    {   
        try
		{
			Import-Module "Servermanager"
		}
		catch
		{
			$_ >>$Log
		}
        if($global:VDAServer -eq "True")
        {
            "Uninstalling prototypes for VDA server" >>$Log
			try
			{
				$TotalRoles =@("CMAK","RSAT-RDS-Licensing-Diagnosis-UI","RDS-Licensing-UI","RSAT-RemoteAccess-Mgmt","RSAT-RemoteAccess-PowerShell","WAS-Process-Model","WAS-Config-APIs")            
				foreach($Role in $TotalRoles)
				{
					PrintDateTime
					"`n RoleName $Role" >>$Log
					try
					{
						Uninstall-WindowsFeature -Name $Role >>$Log
					}
					catch
					{
						$_ >>$Log
						"Unable to install $Role feature Please perform manually"  >>$Log
					}
				}
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
				$Script:TaskValue = $Script:TaskValue + 1
            }
            catch
            {
                $_ >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
            }
        }
        else
        {
            "Uninstalling prototypes for server" >>$Log
            try
            {
			    $TotalRoles =@("CMAK","RSAT-RDS-Licensing-Diagnosis-UI","RDS-Licensing-UI","RSAT-RemoteAccess-Mgmt","RSAT-RemoteAccess-PowerShell","WAS-Process-Model","WAS-Config-APIs")
			    foreach($Role in $TotalRoles)
                {
                    PrintDateTime
                    "`n RoleName $Role" >>$Log
                    try
                    {
                        UnInstall-WindowsFeature -Name $Role
                    }
                    catch
                    {
                        $_ >>$Log
                        "Unable to install $Role feature Please perform manually"  >>$Log
                    }
                }
				<# try
                {      
					UnInstall-WindowsFeature RDS-Connection-Broker -IncludeManagementTools >>$Log
                }
                catch
                {
                    $_ >>$Log
                    "Unable to install RDS-Connection-Broker feature Please perform manually"  >>$Log
                } #>
	            $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
                $Script:TaskValue = $Script:TaskValue + 1   
            }
            catch
            {
                $_ >>$Log
                $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                $Script:ErrorCount = $Script:ErrorCount +1
            }    
        }
    }
    catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj	
}

#------------------------------------------------------------------------
# Enable HSTS
#------------------------------------------------------------------------

function EnableHSTS()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Enabling HSTS" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enabling HSTS"
    try
    {
        [void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration")
        $PSPath =  'MACHINE/WEBROOT/APPHOST/' + $WebSiteName 
         
        Remove-WebConfigurationProperty -PSPath $PSPath -Name . -Filter system.webServer/httpProtocol/customHeaders -AtElement @{name =$HeaderName } *>$null

        $iis = new-object Microsoft.Web.Administration.ServerManager 
        $config = $iis.GetWebConfiguration($WebSiteName)
        $httpProtocolSection = $config.GetSection("system.webServer/httpProtocol") 
        $customHeadersCollection = $httpProtocolSection.GetCollection("customHeaders") 
        
        $addElement = $customHeadersCollection.CreateElement("add") 
        $addElement["name"] = $HeaderName 
        $addElement["value"] = $HeaderValue 
 
        $new_Value=$customHeadersCollection.Add($addElement) 
 
        $iis.CommitChanges()
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
        $Script:TaskValue = $Script:TaskValue + 1      
    }
    catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj	
}

#------------------------------------------------------------------------
# Disable HSTS
#------------------------------------------------------------------------

function DisableHSTS()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Disabling HSTS" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Disabling HSTS"
    try
    {
        $PSPath =  'MACHINE/WEBROOT/APPHOST/' + $WebSiteName 
        Remove-WebConfigurationProperty -PSPath $PSPath -Name . -Filter system.webServer/httpProtocol/customHeaders -AtElement @{name =$HeaderName } *>$null
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
        $Script:TaskValue = $Script:TaskValue + 1   
    }
    catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }    
    $script:output_table += $script:output_obj	
}

#------------------------------------------------------------------------
# Removal of X-Powered-By HTTP Response Header
#------------------------------------------------------------------------

function RemoveXPoweredByHeader()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Removal of X-Powered-By HTTP Response Header" >>$Log
	$HeaderName = "X-Powered-By"
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Removal of X-Powered-By HTTP Response Header"
    try
    {
	    [void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration")
        $PSPath =  'MACHINE/WEBROOT/APPHOST/' + $WebSiteName 
        Remove-WebConfigurationProperty -PSPath $PSPath -Name . -Filter system.webServer/httpProtocol/customHeaders -AtElement @{name =$HeaderName } *>$null
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
        $Script:TaskValue = $Script:TaskValue + 1      
    }
    catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }
    $script:output_table += $script:output_obj	
}

#------------------------------------------------------------------------
# Addition of  X-Powered-By HTTP Response Header
#------------------------------------------------------------------------

function AddXPoweredByHeader()
{
    PrintDateTime
    PrintActionAndResetVariables
    "`n Addition of X-Powered-By HTTP Response Header" >>$Log
	$HeaderName = "X-Powered-By"
	$HeaderValue = "ASP.NET"
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Addition of X-Powered-By HTTP Response Header"
    try
    {
		[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration")
        $PSPath =  'MACHINE/WEBROOT/APPHOST/' + $WebSiteName  
        $iis = new-object Microsoft.Web.Administration.ServerManager 
        $config = $iis.GetWebConfiguration($WebSiteName)
        $httpProtocolSection = $config.GetSection("system.webServer/httpProtocol") 
        $customHeadersCollection = $httpProtocolSection.GetCollection("customHeaders") 
        
        $addElement = $customHeadersCollection.CreateElement("add") 
        $addElement["name"] = $HeaderName 
        $addElement["value"] = $HeaderValue 
 
        $new_Value=$customHeadersCollection.Add($addElement) 
 
        $iis.CommitChanges()
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
        $Script:TaskValue = $Script:TaskValue + 1   
    }
    catch
    {
        $_ >>$Log
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
        $Script:ErrorCount = $Script:ErrorCount +1
    }    
    $script:output_table += $script:output_obj	
}


#------------------------------------------------------------------------
# Enable ExternalURLDetection
#------------------------------------------------------------------------
function EnableExternalURL()
{
    PrintDateTime
    PrintActionAndResetVariables
    "Remove External URLS"
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Remove External URLS"
    $checkcount = 0
    if((Test-Path -Path "C:\inetpub\wwwroot\iisstart.htm"))
    {
       if(Test-Path -Path "C:\Windows_Hardening") 
       {       
            try
            {
                 Copy-Item "C:\inetpub\wwwroot\iisstart.htm" -Destination "C:\Windows_Hardening" -Force              
                 $content = Get-Content -Path C:\inetpub\wwwroot\iisstart.htm
                 $removeline ='<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="iisstart.png" alt="IIS" width="960" height="600" /></a>'    
                 foreach($line in $content)
                 {
                    if($line -like $removeline)
                    {            
                       try
                       {
                           $content | where {$_ -notlike $removeline} | Out-File C:\inetpub\wwwroot\iisstart.htm
                           $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
                           $checkcount = $checkcount + 1 
                       }
                       catch
                       {
                           $_ >>$Log
                           $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                           $Script:ErrorCount = $Script:ErrorCount +1
                       }
                    }
                 }
                 if($checkcount -eq 0)
                 {
                    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
                 }
            }
            catch
            {
                 $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                 $Script:ErrorCount = $Script:ErrorCount +1
            }
       }
       else
       {
            Write-Host "A expected folder is missing in the server."
            $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
            $Script:ErrorCount = $Script:ErrorCount +1
       }
    }
    else
    {      
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
    }
    $script:output_table += $script:output_obj	
}

#------------------------------------------------------------------------
# Disable ExternalURLDetection
#------------------------------------------------------------------------

function DisableExternalURL()
{
    PrintDateTime
    PrintActionAndResetVariables
    "Rollback of Remove External URLS"
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Rollback of Remove External URLS"
    if(Test-Path -Path "C:\inetpub\wwwroot")
    {
        if(Test-Path -Path "C:\Windows_Hardening")
        {
            $files = Get-ChildItem -Path 'C:\inetpub\wwwroot' -Recurse
            ForEach ($file In $files)
            {
              if($file.Name -eq 'iisstart.htm')
              {
                try
                {                
                    Remove-Item  "C:\inetpub\wwwroot\iisstart.htm"
                    Copy-Item  "C:\Windows_Hardening\iisstart.htm" -Destination "C:\inetpub\wwwroot"
                    Remove-Item "C:\Windows_Hardening\iisstart.htm"
                    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
                }
                catch
                {
                    $_ >>$Log
                    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
                    $Script:ErrorCount = $Script:ErrorCount +1
                }
              }
            }
        }
        else
        {
            Write-Host "A expected folder is missing in the server."
            $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
            $Script:ErrorCount = $Script:ErrorCount +1        
        }
    }
    else
    {
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
    }
    $script:output_table += $script:output_obj	
}

#------------------------------------------------------------------------
# Post Hardening for CCS
#------------------------------------------------------------------------
function PostHardeningCCS()
{
    PrintDateTime
    PrintActionAndResetVariables
    "Post Hardening steps for CCS" >>$Log
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Post Hardening steps for CCS"
    $running = 'Running'
    $SreviceRunStatus = 0
    try
    {
        sc.exe config NetTcpPortSharing start= demand			
    }
    catch
    {
        $_ >>$Log
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"	
		$Script:ErrorCount = $Script:ErrorCount +1
    }
    try
    {
        [string[]]$services=@('Citrix Peer Resolution Service','Citrix Configuration Replication','Citrix Credential Wallet','Citrix Subscriptions Store')
        foreach($service in $services)
        {
           $getservice = Get-Service -Name $service
           if($getservice.Status -ne $running)
           {
               Start-Service -Name $service *>$null
               sleep -Seconds 60
               $getservice = Get-Service -Name $service
               if($getservice.Status -ne $running)
               {
                 "$service is not running. Please perform manual procedure" >>$Log
                 $SreviceRunStatus = $SreviceRunStatus + 1
               }
               else
               {
                 "$service is running." >>$Log
               }
           }
           else
           {
               "$service is running" >>$Log
           }
        }        
        if($SreviceRunStatus -gt 0)
        {
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"	
		$Script:ErrorCount = $Script:ErrorCount +1		
	    }
	    else
	    {
	    	$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
            $Script:TaskValue = $Script:TaskValue + 1
	    }               
    }
    catch
    {
        $_ >>$Log
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"	
		$Script:ErrorCount = $Script:ErrorCount +1	
    }
	$script:output_table += $script:output_obj
}

#-------------------------------------------------------------------------------------
# Checking Task Existence activity to PowerShell
#-------------------------------------------------------------------------------------
Function Check-TasksInTaskScheduler ($currentTask) 
{
    try 
	{
        $schedule = new-object -com("Schedule.Service")
        $schedule.connect()
        $tasks = $schedule.getfolder("\").gettasks(0)
        foreach ($t in $tasks)
		{
            $taskName=$t.Name
            if(($taskName -eq $currentTask))
			{
				$t.Enabled
				return $true
            }
        }
    } 
	catch 
	{
       $errorMessage = $_.Exception.Message
	   $errorMessage >> $log
       "Check Tasks in task scheduler Failed" >> $log
       return $False
    }
}

#-------------------------------------------------------------------------------------
# Creating/Changing Windows Legal Notice task activity to PowerShell
#-------------------------------------------------------------------------------------

function LegalNoticeTask
{
	$isTaskExist = Check-TasksInTaskScheduler "Windows Legal Notice"
	$powershellVar = "powershell.exe "
	$ebid_LegalNoticeFile = $powershellVar + "C:\Windows_Hardening\windows_master_script.ps1 UpdateLegalNotice"
	if($isTaskExist)
	{
		"Windows Legal Notice task exist, hence deleting" >>$log
		Unregister-ScheduledTask -TaskName "Windows Legal Notice" -Confirm:$false
	}
	else
	{
		"Windows Legal Notice task doesn't exist, hence creating" >>$log
	}
	
	$testActionNew = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument 'C:\Windows_Hardening\windows_master_script.ps1 UpdateLegalNotice' 
	
	[int]$current_year = Get-Date -Format yyyy
	$next_year = $current_year + 1
	$testTriggerNew = New-ScheduledTaskTrigger -once -At 1.1.$next_year
	#$testTriggerNew = New-ScheduledTaskTrigger -At 12:00AM -Monthly January -DayofMonth 1
	
	$testTriggerNew.StartBoundary = [DateTime]::Parse($testTriggerNew.StartBoundary).ToLocalTime().ToString("s")
	$testSettingsNew = New-ScheduledTaskSettingsSet -WakeToRun
	$userSystem="NT AUTHORITY\SYSTEM"
	Register-ScheduledTask -TaskName 'Windows Legal Notice' -Description "Windows task to Update Windows Log On Legal Notice" -Action $testActionNew -Trigger $testTriggerNew -Settings $testSettingsNew -User $userSystem -RunLevel Highest
	
	$isTaskExist = Check-TasksInTaskScheduler "Windows Legal Notice"
	if($isTaskExist)
	{
		"Windows Legal Notice task created successfully" >>$log
	}
	else
	{
		"Windows Legal Notice task creation unsuccessful" >>$log
	}
}

#------------------------------------------------------------------------
# Applying Legal Notice Settings
#------------------------------------------------------------------------
function LegalNotice($Argument)
{	
	PrintDateTime
    PrintActionAndResetVariables
	"Creating/Updating Legal Notice" >>$Log
	$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Updating Legal Notice"
	try
	{
		if(Test-Path -Path "C:\Windows_Hardening\LegalNotice.ini")
		{
			$FileContent = Get-Content -Path "C:\Windows_Hardening\LegalNotice.ini"
			foreach($SourceFolder in $FileContent)
			{
				if($SourceFolder -match "Title")
				{
					$line_split = "$SourceFolder".split("=",2)
					$NoticeTitle = $line_split[1].Trim()
				}
				
				if($SourceFolder -match "Message")
				{
					$line_split = "$SourceFolder".split("=",2) 
					$NoticeMessage = $line_split[1].Trim()
					
					$current_year = Get-Date -Format "yyyy"
					
					if($NoticeMessage -match "YYYY")
					{
						"'YYYY' found in LegalNotice.ini file" >>$Log
						$new_NoticeMessage = $NoticeMessage.replace("YYYY", $current_year)
						$NoticeMessage = $new_NoticeMessage
						
						LegalNoticeTask
					}
					
					elseif($NoticeMessage -match "2013- " -or $NoticeMessage -match "2013-" -or $NoticeMessage -match "2013 -")
					{
						if($NoticeMessage -match "2013- ")
						{
							"'2013- ' found in LegalNotice.ini file" >>$Log
							$index_year = $NoticeMessage.IndexOf("2013- ")
							$before_year = $index_year + 6
							$after_year = $before_year + 4
						}
						
						elseif($NoticeMessage -match "2013-")
						{
							"'2013-' found in LegalNotice.ini file" >>$Log
							$index_year = $NoticeMessage.IndexOf("2013-")
							$before_year = $index_year + 5
							$after_year = $before_year + 4
						}
						
						elseif($NoticeMessage -match "2013 -")
						{
							"'2013 -' found in LegalNotice.ini file" >>$Log
							$index_year = $NoticeMessage.IndexOf("2013 -")
							$before_year = $index_year + 6
							$after_year = $before_year + 5
						}
						
						$new_NoticeMessage = $NoticeMessage.SubString(0, $before_year) + $current_year + $NoticeMessage.SubString($after_year)
						$NoticeMessage = $new_NoticeMessage
						
						LegalNoticeTask
					}
					
					else
					{
						"'YYYY' or '2013- ' or '2013-' or '2013 -' not found in LegalNotice.ini file" >>$Log
						$isTaskExist = Check-TasksInTaskScheduler "Windows Legal Notice"
						if($isTaskExist)
						{
							"Windows Legal Notice task exist, hence deleting" >>$log
							Unregister-ScheduledTask -TaskName "Windows Legal Notice" -Confirm:$false
						}
					}
				}
			}
			
			$NewLine = "$NoticeMessage".split("#")
			for($i = 0 ; $i -lt $NewLine.Length; $i++)
			{
				$FinalNotice = $NewLine + "`r"
			}
			$FinalNotice = $FinalNotice | Out-String
			if($NoticeTitle -ne '')
			{
				if([bool](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption"  -ErrorAction SilentlyContinue))
				{
					Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value $NoticeTitle					
				}
				else
				{
					Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value $NoticeTitle
				}
			}
			
			if($NoticeMessage -ne '')
			{
				if([bool](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -ErrorAction SilentlyContinue))
				{
					Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'legalnoticetext'
					$a = New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'legalnoticetext' -Value $FinalNotice 
					$a.multistring
				}
				else
				{
					$a = New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'legalnoticetext' -Value $FinalNotice 
					$a.multistring				
				}								
			} 
			
			if([bool](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption"))
			{
				if([bool](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext"))
				{
					"Legal Notice Updated Successfully" >>$Log
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
					$Script:TaskValue = $Script:TaskValue + 1									
				}
				else
				{
					"Notice Text is not updated in registry" >>$Log
					$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
					$Script:ErrorCount = $Script:ErrorCount +1
				}
			}
			else
			{
				"Notice Title is not updated in registry" >>$Log
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
				$Script:ErrorCount = $Script:ErrorCount +1
			}
		}
		else
		{
			"LegalNotice.ini file is missing in C:\Windows_Hardening folder. Copy LegalNotice.ini file from Windows Hardening media and run script with UpdateLegalNotice argument" >>$Log
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
			$Script:ErrorCount = $Script:ErrorCount +1
		}
	}
	catch
    {
		"Exception in script." >>$Log
        $_ >>$Log		
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"	
		$Script:ErrorCount = $Script:ErrorCount +1	
    }
	$script:output_table += $script:output_obj
}

#------------------------------------------------------------------------
# Removing Legal Notice Settings
#------------------------------------------------------------------------
function RemoveLegalNotice()
{
	PrintDateTime
    PrintActionAndResetVariables
	"Removing Legal Notice" >>$Log
	$RemoveCount = 0
	$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Removing Legal Notice"
	try
	{
		if([bool](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -ErrorAction SilentlyContinue))
		{
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption"
		}
		if([bool](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -ErrorAction SilentlyContinue))
		{
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext"
		}
		
		
		if(![bool](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -ErrorAction SilentlyContinue))
		{	
			$RemoveCount += 1
		}
		else
		{
			"Notice Caption information is not removed in registry" >>$Log
			"Remove registry key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\legalnoticecaption" >>$Log
		}
		if(![bool](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -ErrorAction SilentlyContinue))
		{
			$RemoveCount += 1
		}
		else
		{
			"Notice text information is not removed in registry" >>$Log
			"Remove registry key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\legalnoticetext" >>$Log
		}
		
		if($RemoveCount -eq 2 )
		{
			"All registry entries related to Legal Notice removed Successfully" >>$Log
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
		elseif($RemoveCount -gt 0)
		{
			"few registry entries related to Legal Notice not removed. Check log and remove those entries" >>$Log
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Completed With Erros"
			$Script:TaskValue = $Script:TaskValue + 1
		}
		else
		{
			"All registry entries related to Legal Notice not removed" >>$Log
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
			$Script:ErrorCount = $Script:ErrorCount +1
		}
		
		$isTaskExist = Check-TasksInTaskScheduler "Windows Legal Notice"
		if($isTaskExist)
		{
			"Windows Legal Notice task exist, hence deleting" >>$log
			Unregister-ScheduledTask -TaskName "Windows Legal Notice" -Confirm:$false
		}
	}
	catch
    {
        $_ >>$Log
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"	
		$Script:ErrorCount = $Script:ErrorCount +1	
    }
	$script:output_table += $script:output_obj
	
}

#------------------------------------------------------------------------
#Self Signed certificate replacement with CA certificate for Remote Desktop Services
#------------------------------------------------------------------------
function SSCertRemovalRDP()
{
	PrintDateTime
    PrintActionAndResetVariables
	"Self Signed Certificate replacement with CA certificate for RDP" >>$Log    
    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Self Signed Certificate Removal for RDP"
	$count = 0
	try
	{	
		"`nChecking if ENM_PKI_Root_CA is imported in MMC.." >>$Log
		if( [bool](Get-ChildItem -Path Cert:\LocalMachine\Root | Select-Object Subject | Select-String -Pattern  'CN=ENM_PKI_Root_CA' -CaseSensitive -SimpleMatch))
		{
			"ENM_PKI_Root_CA is already imported. Hence, Skipping." >>$Log
			$count = $count + 1
		}
		else
		{	
			"ENM_PKI_Root_CA is not imported in MMC." >>$Log
			if(Test-Path -Path "C:\Certificates\ENM_PKI_Root_CA.cer")
			{
				"ENM_PKI_Root_CA.cer is present in C:\Certificates folder. Importing.."  >>$Log
				Import-Certificate -FilePath "C:\Certificates\ENM_PKI_Root_CA.cer" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
				"Imported ENM_PKI_Root_CA successfully." >>$Log
				$count = $count + 1
			}
			else
			{
				"ENM_PKI_Root_CA.cer is not present in C:\Certificates folder. Import the certificate manually."  >>$Log
			}
		}
		
		"`nChecking if ENM_External_Entity_CA is imported in MMC.." >>$Log
		if( [bool](Get-ChildItem -Path Cert:\LocalMachine\CA | Select-Object Subject | Select-String -Pattern  'CN=ENM_External_Entity_CA' -CaseSensitive -SimpleMatch))
		{
			"ENM_External_Entity_CA is already imported. Hence, Skipping" >>$Log
			$count = $count + 1
		}
		else
		{
			"ENM_External_Entity_CA is not imported in MMC." >>$Log
			if(Test-Path -Path "C:\Certificates\ENM_External_Entity_CA.cer")
			{
				"ENM_External_Entity_CA.cer is present in C:\Certificates folder. Importing.."  >>$Log
				Import-Certificate -FilePath "C:\Certificates\ENM_External_Entity_CA.cer" -CertStoreLocation Cert:\LocalMachine\CA | Out-Null
				"Imported ENM_External_Entity_CA successfully." >>$Log
				$count = $count + 1
			}
			else
			{
				"ENM_External_Entity_CA.cer is not present in C:\Certificates folder. Import the certificate manually."  >>$Log
			}
		}
		
		"`nChecking if $serverCertRDP is imported in MMC.." >>$Log
		if( [bool](Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Subject | Select-String -Pattern  $serverCertRDP -SimpleMatch))
		{
			"$serverCertRDP is already imported. Hence, Skipping" >>$Log
			$count = $count + 1
			$cert = Get-ChildItem  -Path Cert:\LocalMachine\MY | Where-Object {$_.Subject -Match $serverCertRDP} | Select-Object Thumbprint, Subject
			$thumbprint = $cert.thumbprint
			wmic /namespace:\\root\cimv2\TerminalServices PATH Win32_TSGeneralsetting set SSLCertificateSHA1Hash=$thumbprint >> $Log
			"Imported $serverCertRDP successfully." >>$Log
		}
		else
		{
			"$serverCertRDP is not imported in MMC." >>$Log
			if(Test-Path -Path "C:\Certificates\rdp.p12")
			{
				"rdp.p12 is present in C:\Certificates folder. Proceeding.."  >>$Log
				if(Test-Path -Path "C:\ebid\TempPwd.ini")
				{
					foreach($line in Get-Content "C:\ebid\TempPwd.ini") 
					{ 
						if($line -match "RDP_CertPassword=")
						{            
							$LineSplit = "$line".split("=",2)
							$password = $LineSplit[1].Trim()
							$password = ConvertTo-SecureString $password -AsPlainText -Force	
						}                       	            
					}
					Import-PfxCertificate -FilePath C:\Certificates\rdp.p12 -CertStoreLocation Cert:\LocalMachine\My -Password $password | Out-Null
					$cert = Get-ChildItem  -Path Cert:\LocalMachine\MY | Where-Object {$_.Subject -Match $serverCertRDP} | Select-Object Thumbprint, Subject
					$thumbprint = $cert.thumbprint
					wmic /namespace:\\root\cimv2\TerminalServices PATH Win32_TSGeneralsetting set SSLCertificateSHA1Hash=$thumbprint >> $Log
					"Imported $serverCertRDP successfully." >>$Log
					$count = $count + 1
				}
				else
				{	
					"unable to find C:\ebid\TempPwd.ini for fetching required inputs" >>$Log
				}
			}
			else
			{
				"rdp.p12 is not present in C:\Certificates folder."  >>$Log
			}
		}
		if($count -eq 3)
		{
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
			$Script:TaskValue = $Script:TaskValue + 1
		}
		else
		{
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
			$Script:ErrorCount = $Script:ErrorCount +1
		}	
	}
    catch
	{
		$_ >>$Log
		$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"	
		$Script:ErrorCount = $Script:ErrorCount +1
	}
	$script:output_table += $script:output_obj
}

#------------------------------------------------------------------------																					
#function for Checking if server is Active directory
#------------------------------------------------------------------------
function CheckAD()
{
    try
    {
        Get-ADForest | Out-Null
        return $true
    }
    catch
    {
        $_ >>$Log
        return $false
    }
}

#-----------------------------------------------------
# Check if logged user is BIS Administrator or Not
#-----------------------------------------------------
function CheckBISAdmin()
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
	$CheckUser  = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if($CheckUser)
    {
        "`n Logged user is Administrator" >>$Log
        #Write-Host "`n Logged user is Administrator"
		return $true
    }
    else
    {        
        "`n Logged user is not Administrator. Please logon as Administrator and run the script for firewall settings" >>$Log        
        return $false
    }
}

#-----------------------------------------------------
# Check if logged user is Domain Administrator or Not
#-----------------------------------------------------
function CheckDomainAdministrator()
{
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent() 
    $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)  
    if($WindowsPrincipal.IsInRole("Domain Admins")) 
    {     
        #Write-Host "`n Logged on user is Domain Administrator" 
        "`n Logged on user is Domain Administrator" >>$Log
		return $true
    } 
    else 
    {    
        Write-Host "`n Logged on user is not Domain Administrator and exiting from script" 
        "`n Logged on user is not Domain Administrator and exiting from script" >>$Log
        return $false
    } 
}

#----------------------------------------------------------
# Checking the server configuration 
#----------------------------------------------------------
function CheckServer()
{
    PrintDateTime
    if(Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4*\config Manager")
    {
		if(Test-Path -Path "C:\Ericsson\NetAnServer\Server")
        {
            "It's a Co-Deployed (BIS and NetAn) server" >>$Log
            $AdminCheck = CheckBISAdmin 
            if($AdminCheck)
            {
                $global:NetAnServer = "True"
                $global:BISServerCheck = "True"
                return $true
            }
            else
            {
                return $false
            }
        }
        else
        {
			"It's a BIS server" >>$Log
			$AdminCheck = CheckBISAdmin        
			if($AdminCheck)
			{
				$global:BISServerCheck = "True"
				return $true
			}
			else
			{
				return $false
			}
		}
	}
    elseif(Test-path -Path "C:\Ericsson\NetAnServer\Server")
    {
        "It's NetAn Server" >>$Log
		$AdminCheck = CheckBISAdmin
		if($AdminCheck)
		{
			$global:NetanServer = "True"
			return $true
		}
		else
		{
			return $false
		}
    }	
    elseif((Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent") -AND (Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora"))
    {
        "It's VDA server with BO Client installed" >>$Log 
        $AdminCheck = CheckBISAdmin
		if($AdminCheck)
		{
			$global:OCSServer = "True"   
            $global:VDAServer = "True"     
			return $true
		}
		else
		{
			return $false
		}        
    }
    elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Desktop Delivery Controller")
    {   
        if(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Desktop Delivery Controller' -Name InstallDir).InstallDir)
        {
            "It's CCS server" >>$Log
            $global:CCSServer = "True"
        }
        elseif(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Virtual Desktop Agent' -Name InstallDir).InstallDir)
        {
            "It's VDA server" >>$Log
            $global:VDAServer = "True"
        }    	
        $AdminCheck = CheckDomainAdministrator
		if($AdminCheck)
		{
			$global:OCSServer = "True"
			return $true
		}
		else
		{
			return $false
		}		               
    }
    elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent")
    {
        if(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Virtual Desktop Agent' -Name InstallDir).InstallDir)
        {
            "It's VDA server without BO Client installed" >>$Log
            $AdminCheck = CheckDomainAdministrator
			if($AdminCheck)
			{
				$global:OCSServer = "True"
                $global:VDAServer = "True"
				return $true
			}
			else
			{
				return $false
			}
        }
    }
	elseif(Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora")
	{
		"It's OCS without Citrix Server with BO Client installed" >>$Log
		$AdminCheck = CheckBISAdmin
		if($AdminCheck)
		{
			$global:OCSwithoutCitrixServer = "True"   
			return $true
		}
		else
		{
			return $false
		}
	}
    if(($BISServer -ne "True") -AND ($OCSServer -ne "True"))
    {
        $CheckADServer = CheckAD        
        if($CheckADServer)
        {                
            "It's an AD server" >>$Log
			$AdminCheck = CheckDomainAdministrator
			if($AdminCheck)
			{
				$global:OCSServer = "True" 
				$global:ADServer = "True"
				$dGpoSet = Get-GPO -Name "winharauto_gpo" -ErrorAction SilentlyContinue
				if ($dGpoSet)
				{
					"`n winharauto_gpo is already configured" >>$Log
					return $true  
				}
				else 
				{
					"`n winharauto_gpo is not configured" >>$Log
					$ocsConfigPath = "C:\OCS\install_config\ADDS_config\adds_config.ini"
					if(Test-Path -Path $ocsConfigPath)
					{
						$addomainName = (Get-Content $ocsConfigPath | Where-Object {$_ -like "*domainname*" }).Split("=")[1].trim()
						try
						{
							New-GPO -Name "winharauto_gpo" -Domain $addomainName                                                
						}
						catch
						{
							$_ >>$Log
							Write-Host "Unable to create winharauto_gpo group policy object"                        
						}     
						return $true               
					}
					else
					{
						"$ocsConfigPath is not found and exiting from script."
						return $false
					}        
				}				
			}
			else
			{
				return $false
			}                                  
        }
        else
        {            
            "`n Unable to recognize server" >>$Log
            return $false                    
        }
    }
}


#######################################
#######          MAIN           #######
#######################################
$TimeStamp = Get-Date -Format yyyy-MM-dd_HH_mm_ss
$LogDir = "C:\Windows_Hardening\log"
$global:BISServerCheck = "False"
$global:OCSServer = "False"
$global:ADServer = "False"
$global:CCSServer = "False"
$global:VDAServer = "False"
$global:NetAnServer="False"
$global:OCSwithoutCitrixServer = "False"								  
$WindowsMedia = "C:\Windows_Hardening\WINDOWS_HARDENING.iso"
$GroupPolicy = "C:\group_policy\Group_Policy.ps1"
$FirewallScript = "C:\Firewall\Firewall_Settings.ps1"
$CertificateExpiryScript = "C:\Certificate-expiry\Schedule_task.ps1"											  
$script:output_table = @()
$Script:TaskValue = 0
$Script:ErrorCount = 0
$WebSiteName = "Default Web Site"
$HeaderName = "Strict-Transport-Security"
$HeaderValue = "max-age=31536000;includeSubdomains" 
$serverCertRDP = (Get-WmiObject win32_computersystem).DNSHostName+"_RDP"

$KBCheck = $False

if(Test-Path $LogDir)
{     
    $Log = New-Item C:\Windows_Hardening\log\Windows_Hardening-"$args"-"$TimeStamp".txt -ItemType File
    PrintDateTime
    "New log file created in C:\Windows_Hardening\log directory" >>$Log
}
else
{    
    New-Item -Path $LogDir -ItemType Directory | Out-Null
	$Log = New-Item C:\Windows_Hardening\log\Windows_Hardening-"$args"-"$TimeStamp".txt -ItemType File
    PrintDateTime
    "New log file created in C:\Windows_Hardening\log directory" >>$Log
}

$ServerStatus = CheckServer
"Server status $ServerStatus" >>$Log
if($ServerStatus)
{
    PrintDateTime
    #------------------------------------------------------------------------
    #Checking if user has given correct argument or not
    #------------------------------------------------------------------------
    if($args.Count -lt 1)
    {
        "`n [ERROR]: No arguments are given when running the script. Please use anyone of the following arguments to run the script Enable, Disable, UpdateLegalNotice." >>$Log 
		return $false
        exit
    }
    elseif($args.Count -gt 1)
    {
        "`n [ERROR]: Only one argument should be given when running the script. Please use Enable or Disable or UpdateLegalNotice arguments and try running the script." >>$Log
		return $false
        exit
    }
    if(($args -ne "Enable") -AND ($args -ne "Disable") -AND ($args -ne "UpdateLegalNotice"))
    {
        "`n [ERROR]: $args is an Invalid argument. Enable, Disable, UpdateLegalNotice are valid arguments" >>$Log
		return $false
        exit
    }
    else
    {
        "`n Script is running with $args argument" >>$Log
    }
    CheckMedia
    
    if($args -eq "Enable")
    {    	
		#Call CopyLatestFolders function
		CopyLatestFolders
		
		##rollback disableweakciphers enabled at previous ii/upgrade
		rollback_old_disableweakciphers
		
		#Create the Prototype Security Policy
        EnableRDInstallFeature		
		
		#Call Disable weak ciphers script
        DisableWeakCiphers       
			
		#Call Enable Firewall script
        EnableFirewall   
		
		if(($global:NetanServer -eq "True") -OR ($global:OCSwithoutCitrixServer -eq "True"))
        {
			#Call Enable Certificate-expiry script
			EnableCertificateExpiry
		
        }
		
		#Call BlockICMP script
        BlockICMP				       
		
		#Disabling Autorun
        DisableAutoRunBO
			
		#Disabling Autoplay
        DisableAutoPlayBO
			
		#setting max idle time 
        SetRDMaxIdleTimeBO
			
		#setting remote desktop session timeout
        SetRDSessionTimeoutBO
		
		#Update Legal Notice
		LegalNotice	"Enable"
		
		if(($global:BISServerCheck -eq "True") -OR ($global:OCSwithoutCitrixServer -eq "True"))
		{
			#Self signed cert removal for RDP
			If(Test-Path -Path "C:\ebid\TempPwd.ini")
			{
				foreach($line in Get-Content "C:\ebid\TempPwd.ini") 
				{	
					"`n $line available in C:\ebid\TempPwd.ini ">>$Log
					If($line -match "RDP_CertPassword" -And $line -ne "RDP_CertPassword=No")
					{
						SSCertRemovalRDP
					}
				}
			}
			else
			{
				"`n Unable to get C:\ebid\TempPwd.ini file." >>$Log
			}	
		}																				 
        if(($global:BISServerCheck -eq "True") -OR ($global:NetAnServer -eq "True") -OR ($global:OCSwithoutCitrixServer -eq "True"))
        {
			#Calling Enable Group Policy Script
            EnableGroupPolicy		
            
            #Enabling SMB Protocols
            EnableSMBProtocols
        }
        if($global:ADServer -eq "True")
        {
		    #Disabling SMB Protocols enabled at 20.4 level after upgrade
			Disable-OldSMBProtocols
			
			#Calling Enable Group Policy Script
            EnableGroupPolicy
			
			<#Disabling Autorun
            DisableAutoRunOCS
			
			#Disabling Autoplay
            DisableAutoPlayOCS
			
			#setting max idle time 
            SetRDMaxIdleTimeOCS

            #setting remote desktop session timeout
            SetRDSessionTimeoutOCS#>
        }
        if(($global:CCSServer -eq "True") -OR ($global:VDAServer -eq "True"))
        {
            EnableHSTS
            EnableExternalURL
            #Enabling SMB Protocols
            EnableSMBProtocols
        }
		if($global:CCSServer -eq "True")
		{
		    RemoveXPoweredByHeader
			PostHardeningCCS
		}
		
		try 
		{
		if ($global:VDAServer -eq "True")
			{
				EnableVDANLA
			}
		else
			{
				EnableNLA
			}
		}
		catch
		{
			$_ >>$Log
			"Unable to get all updates installed in the system." >>$Log
			PrintDateTime
			PrintActionAndResetVariables  
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enable NLA"
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
			$script:output_table += $script:output_obj    
			$Script:ErrorCount = $Script:ErrorCount +1  
		}
		
		<#try
		{
			#Enabling Network level Authentication
			$wu = new-object -com "Microsoft.Update.Searcher"
			$totalupdates = $wu.GetTotalHistoryCount()
			$all = $wu.QueryHistory(0,$totalupdates)								
			Foreach ($update in $all)
			{
				$string = $update.title
				$ResultStatus = $update.ResultCode
				if(($string -match "KB4103723") -AND ($ResultStatus -eq "2"))
				{
					$KBCheck = $True
				}
			}
			if($KBCheck)
			{
				"KBPatch(KB4103723) is installed" >>$Log
				if ($global:VDAServer -eq "True")
				{
					EnableVDANLA
				}
				else
				{
					EnableNLA
				}													
			}                
			else
			{
				"KB4103723 is not installed or unable find required KBPatch. Perform Manual procedure from Node Hardening for BIS, OCS and Network Analytics Server Document" >>$Log				
				PrintDateTime
				PrintActionAndResetVariables  
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enable NLA"
				$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
				$script:output_table += $script:output_obj    
				$Script:ErrorCount = $Script:ErrorCount +1  
			}
		}
		catch
		{
			$_ >>$Log
			"Unable to get all updates installed in the system." >>$Log
			PrintDateTime
			PrintActionAndResetVariables  
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Action" -value "Enable NLA"
			$script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
			$script:output_table += $script:output_obj    
			$Script:ErrorCount = $Script:ErrorCount +1  
		}#>
    }
    elseif($args -eq "Disable")
    {	
		#Calling rollback Disable weak ciphers script
        RollbackDisableWeakCiphers 

		#Call Disable Firewall script		
        DisableFirewall
		
		#Call UnBlockICMP script
        UnblockICMP			

		#Disabling Network level Authentication		
        if (Test-Path -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Virtual Desktop Agent" )
        {
            DisableVDANLA
        }
        else
        {	
            DisableNLA
        }

        #Rollback of Prototype Security Policy
        DisableRDInstallFeature
		
		#Enabling Autorun
        EnableAutorunBO
			
		#Enabling Autoplay
        EnableAutoPlayBO  
			
		#rollback max idle time 
        RollbackMaxIdleTimeBO
			
		#rollback remote desktop session timeout
        RollbackSessionTimeoutBO
		
		#Remove Legal Notice
		RemoveLegalNotice
		
        if(($global:BISServerCheck -eq "True") -OR ($global:NetAnServer -eq "True") -OR ($global:OCSwithoutCitrixServer -eq "True"))
        {		
			#Calling Disable Group Policy Script
            DisableGroupPolicy

			DisableSMBProtocols			
        } 
        if($global:ADServer -eq "True")
        {
			#Calling Disable Group Policy Script
            DisableGroupPolicy
			
			<#Enabling Autorun
            EnableAutorunOCS
			
			#Enabling Autoplay
            EnableAutoPlayOCS  
			
			#rollback max idle time 
            RollbackMaxIdleTimeOCS
			
			#rollback remote desktop session timeout
            RollbackSessionTimeoutOCS #>         
        }   
        if(($global:CCSServer -eq "True") -OR ($global:VDAServer -eq "True"))
        {
            DisableHSTS
            DisableExternalURL
			DisableSMBProtocols
        }
		if($global:CCSServer -eq "True")
		{
		    AddXPoweredByHeader
		}
    }
	elseif($args -eq "UpdateLegalNotice")
    {		
        LegalNotice	"UpdateLegalNotice"			
        gpupdate /force >>$Log
		$output_table | Format-Table -Wrap -AutoSize
    }
    if($global:BISServerCheck -eq "True")
	{
		$output_table | Format-Table -Wrap -AutoSize >>$Log
	}
	else
	{
		$output_table | Format-Table -Wrap -AutoSize >>$Log
	}       
    "`n Successfull tasks values $Script:TaskValue" >>$Log
    "`n Failed tasks values $Script:ErrorCount" >>$Log
	if(($global:BISServerCheck -eq "True") -OR ($global:ADServer -eq "True") -OR ($global:NetanServer -eq "True") -OR ($global:OCSwithoutCitrixServer -eq "True"))
	{
		try
		{
			gpupdate /force >>$Log
		}
		catch
		{
			$_ >>$Log
			"Failed to invoke GP update. Please update it manually" >>$Log
			Write-Host "Failed to invoke GP update. Please update it manually" -ForegroundColor Red
		}
	}
    if($Script:ErrorCount -eq 0)
    {
        Write-Host "`nAll tasks executed successful"		
		if(($global:BISServerCheck -eq "True") -OR ($global:VDAServer -eq "True") -OR ($global:OCSwithoutCitrixServer -eq "True"))
        {
			return $true
		}        
    }
    else
    {
        Write-Host "`nOne or more tasks execution failed"		
		if(($global:BISServerCheck -eq "True") -OR ($global:VDAServer -eq "True") -OR ($global:OCSwithoutCitrixServer -eq "True"))
        {			
			return $false
		}        
    }	
}
else
{
    Write-Host "`nUnable to recognize server or Logged user is not administrator" -ForegroundColor Red 
	return $false
}
