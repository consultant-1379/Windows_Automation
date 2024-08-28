# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2021 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ************************************************************************
# Name     		: distinct_cert_configuration.ps1
# Purpose 		: Automation of distinct certificates configuration in  ADDS,CCS and VDA servers
# Last Updated	: 10-Dec-2021
#
# *************************************************************************

#------------------------------------------------
# Function to initiate action and reset variables
#------------------------------------------------
Function PrintActionAndResetVariables()
{
	$script:output_obj = New-Object System.Object	
}

#------------------------------------------------
# Function to print date and time in log file
#------------------------------------------------
Function PrintDateTime()
{    
    "----------------------------------------------- " >>$log 
    Get-Date -Format "dddd [MM/dd/yyyy] [HH:mm:ss]" >>$log
    "----------------------------------------------- " >>$log      
}

#------------------------------------------------
# Function to handle the error
#------------------------------------------------
Function ErrorHandle ($usermessage)
{
    Read-host $usermessage
    EXIT(1)
}

#------------------------------------------------------------------------
#Function for Checking if server is Active directory
#------------------------------------------------------------------------
Function CheckAD()
{
    try
    {
        Get-ADForest | Out-Null
        return $true
    }
    catch
    {
        $_ >>$log
        return $false
    }
}

#-----------------------------------------------------
# Check if logged user is Domain Administrator or Not
#-----------------------------------------------------
Function CheckDomainAdministrator()
{
try
{
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent() 
    $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)  
    if($WindowsPrincipal.IsInRole("Domain Admins")) 
    {     
        "`n Logged on user is Domain Administrator" >>$log
		return $true
    } 
    else 
    {    
        Write-Host "`n Logged on user is not Domain Administrator and exiting from script" 
        "`n Logged on user is not Domain Administrator and exiting from script" >>$log
        return $false
    }
}
catch
{
   "$_" >>$log
   ErrorHandle "Error occured while checking the user is domain administrator or not. Check $($log_file) file for more details. Press enter to exit code:"
}	
}

#----------------------------------------------------------
# Checking the server configuration 
#----------------------------------------------------------
Function CheckServer()
{
try
{
    PrintDateTime
    if((Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent") -AND (Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora"))
    {
        "It's VDA server with BO Client installed" >>$log 
        $admin_check = CheckDomainAdministrator
		if($admin_check)
		{  
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
            "It's CCS server" >>$log
            $global:CCSServer = "True"
        }
        elseif(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Virtual Desktop Agent' -Name InstallDir).InstallDir)
        {
            "It's VDA server" >>$log
            $global:VDAServer = "True"
        }
        else
        {
			"Unable to find server status." >>$log
		}  
         if($global:CCSServer -or $global:VDAServer)
		 {		 
            $admin_check = CheckDomainAdministrator
		    if($admin_check)
		    {
		    	return $true
		    }
		    else
		    {
		    	return $false
		    }	
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
            "It's VDA server without BO Client installed" >>$log
            $admin_check = CheckDomainAdministrator
			if($admin_check)
			{
                $global:VDAServer = "True"
				return $true
			}
			else
			{
				return $false
			}
        }
		else
		{
			return $false
		}
    }
    else
	{
        $CheckADServer = CheckAD        
        if($CheckADServer)
        {                
            "It's An AD server" >>$log
			$admin_check = CheckDomainAdministrator
			if($admin_check)
			{
				$global:ADServer = "True"
				return $true
			}
			else
			{
				return $false
			}                                  
        }
        else
        {            
            "`n Unable to recognize server" >>$log
            return $false                    
        }
    }
}
catch
{
  "$_" >> $log
  ErrorHandle "Error occured while check the type of server. Check $($log_file) file for more details. Press enter to exit code:"
}
}

#Function to mount OCS Media
Function CheckOCSMedia($OCSMedia)
{
try
{
    if(Test-Path -Path $OCSMedia)
    {
        if((Get-DiskImage -ImagePath $OCSMedia).Attached)
        {
 	        Write-Host 'Media: OCS Automation Package already mounted'
 	        $DriveLetter = (Get-DiskImage -ImagePath $OCSMedia | Get-Volume).DriveLetter
 	        $DriveLetter = $DriveLetter + ":\" 
            "Media mounted on "+$DriveLetter >>$log
            return $DriveLetter
                 
        }
        else
        {
 	         Write-Host "Media: OCS Automation Package media Not mounted and mounting..." 
 	        $DriveLetter = (Mount-DiskImage -ImagePath $OCSMedia -PassThru | Get-Volume).DriveLetter        
 	        $DriveLetter = $DriveLetter + ":\"
            "Media mounted on "+$DriveLetter >>$log   
            return $DriveLetter     
        }
    }    
    else
    {
        "Media: OCS Automation Package not available in $OCSMedia path. Please place media in correct path and execute script again" >> $log
		[void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")
        [Microsoft.VisualBasic.Interaction]::MsgBox("Media OCS Automation Package is not available in $OCSMedia path. Please place media in correct path and execute script again. Check C:\OCS\cert_config\log for further details.", "OKOnly,SystemModal,Information", "Success")    
        DeleteTempFile
		DeleteNewTask
		EXIT(1)		       
    }   
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while checking the OCS media. Check $($log_file) file for more details. Press enter to exit code:"
}
} 
  
#-------------------------------------------------------------------
# Function to verify Windows hardening media is not present or not
#-------------------------------------------------------------------
Function CheckMedia()
{ 
try
{        
    if($global:VDAServer -match $True)
    {
        $WindowsMedia = "C:\ebid\ebid_medias\WINDOWS_HARDENING.iso"
    }
    else
    {
        $WindowsMedia = "C:\Windows_Hardening\WINDOWS_HARDENING.iso"
    }

    if(Test-Path -Path $WindowsMedia)
    {
        if((Get-DiskImage -ImagePath $WindowsMedia).Attached)
        {
 	        "Media: $WindowsMedia already mounted" >> $log
 	        $script:WHDriveLetter = (Get-DiskImage -ImagePath $WindowsMedia | Get-Volume).DriveLetter
 	        $script:WHDriveLetter = $script:WHDriveLetter + ":\"      
        }
        else
        {
 	        "Media: $WindowsMedia Not mounted and mounting..." >> $log
 	        $script:WHDriveLetter = (Mount-DiskImage -ImagePath $WindowsMedia -PassThru | Get-Volume).DriveLetter        
 	        $script:WHDriveLetter = $script:WHDriveLetter + ":\"        
        }
        "Windows Hardening drive $script:WHDriveLetter" >> $log
    }    
    else
    {
        "Windows media not available in $WindowsMedia path. Please place media in correct path and execute script again" >> $log 
        DeleteTempFile
		DeleteNewTask		
        ErrorHandle "Windows media not available in $WindowsMedia path. Please place media in correct path and execute script again. Check $($log_file) file for more details. Press enter to exit code:"
    } 
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while checking the windows media. Check $($log_file) file for more details. Press enter to exit code:"
}
return $script:WHDriveLetter  
}

Function GetCertPassword()
{
	if($log_dir)
	{
		try
		{
		   if((Test-Path -Path "C:\Distinct_certificates\log\tmppass.log") -and (Test-Path -Path "C:\Distinct_certificates\log\tmppass_new.log"))
		   {
		       $temp_file_common = "C:\Distinct_certificates\log\tmppass.log"
			   $temp_file_purpose = "C:\Distinct_certificates\log\tmppass_new.log"
			   "Expected temporary files are already present in the server." >>$log
		   }
		   else
		   {
		       $temp_file_common = New-Item -ItemType File -Path $log_dir -Name tmppass.log
		       $temp_file_purpose = New-Item -ItemType File -Path $log_dir -Name tmppass_new.log
		   }
		}
        catch
        {
		  DeleteTempFile
		  DeleteNewTask
          ErrorHandle "Error occured while creating the log file. Check $($log_file) file for more details. Press enter to exit code:"
        }
	}
	else
	{
		try
	    {
           New-Item -Path $log_dir -ItemType Directory | Out-Null
		   $temp_file_common = New-Item -ItemType File -Path $log_dir -Name tmppass.log
		   $temp_file_purpose = New-Item -ItemType File -Path $log_dir -Name tmppass_new.log
        }
	    catch
        {
		  DeleteTempFile
		  DeleteNewTask
          ErrorHandle "Error occured while creating the log file. Check $($log_file) file for more details. Press enter to exit code:"
        }
	}
	#Get password for certificates present in C:\Certificates\purpose_specific_certificates
	if($cert_path -or $specific_cert_path)
	{
	  if(Get-Content -path $temp_file_common)
	  {
		  "Temporary file for common certificates is available in the server." >> $log
	  }
	  else
	  {
		#Get details for common certificates present in the server
		for($k=0;$k -lt $cert_path.Count;$k++)
		{
			if(Test-Path -Path $cert_path[$k])
            {	
              Write-Host "Provide the password of the certificate in location $($cert_path[$k]),if prompted."
			   $count = 0
               while ($count -lt 4) 
	           {
                   if($count -eq 3) 
		           {
				      "Count for getting the common certificate password in $($cert_path[$k]) exceeded. " >> $log
					  DeleteTempFile
		              DeleteNewTask
                      ErrorHandle "Maximum attempts to enter password reached. Check $($log_file) file for more details. Press enter to exit code:"
                   }
                  $encryptedpassword = Read-host "Enter certificate password" -AsSecureString
                  $unencryptedpassword = (New-Object System.Management.Automation.PSCredential 'N/A', $encryptedpassword).GetNetworkCredential().Password
                  $count++
                  $confirmpassword = Read-Host "Confirm certificate password" -AsSecureString
                  $unencryptedconfirmpassword = (New-Object System.Management.Automation.PSCredential 'N/A', $confirmpassword).GetNetworkCredential().Password
                  if ($unencryptedpassword -ceq $unencryptedconfirmpassword) 
		          {
                     break
                  } 
		          else
		          {
                     Write-Host "Password is not matching.Re-enter password"            
		          }
               }
			  $cert_name[$k]+">"+$unencryptedconfirmpassword >>$temp_file_common
			}
			else
			{
				continue
			}
	    }
	  }
	  if(Get-Content -path $temp_file_purpose)
	  {
		 "Temporary file for purpose specific certificates is available in the server." >> $log 
	  }
	  else
	  {
		#Get details for purpose specific certificates present in the server
		for($j=0;$j -lt $specific_cert_path.Count;$j++)
		{
			if(Test-Path -Path $specific_cert_path[$j])
            {	
              Write-Host "Provide the password of the certificate in location $($specific_cert_path[$j]),if prompted."
			   $count = 0
               while ($count -lt 4) 
	           {
                   if($count -eq 3) 
		           {
				      "Count for getting the purpose certificate password in $($cert_path[$k]) exceeded. " >> $log
					  DeleteTempFile
		              DeleteNewTask
                      ErrorHandle "Maximum attempts to enter password reached. Check $($log_file) file for more details. Press enter to exit code:"
                   }
                  $encryptedpassword = Read-host "Enter certificate password" -AsSecureString
                  $unencryptedpassword = (New-Object System.Management.Automation.PSCredential 'N/A', $encryptedpassword).GetNetworkCredential().Password
                  $count++
                  $confirmpassword = Read-Host "Confirm certificate password" -AsSecureString
                  $unencryptedconfirmpassword = (New-Object System.Management.Automation.PSCredential 'N/A', $confirmpassword).GetNetworkCredential().Password
                  if ($unencryptedpassword -ceq $unencryptedconfirmpassword) 
		          {
                     break
                  } 
		          else
		          {
                     Write-Host "Password is not matching.Re-enter password"            
		          }
               }
			  $specific_cert_name[$j]+">"+$unencryptedconfirmpassword >>$temp_file_purpose
			}
			else
			{
				continue
			}
		}
	  }
	}
	else
	{
	   "No certificates are available in path C:\Certificates\purpose_specific_certificates." >>$log
	   DeleteTempFile
		DeleteNewTask
	   ErrorHandle "No certificates are available in path C:\Certificates\purpose_specific_certificates. Check $($log_file) file for more details. Press enter to exit code:"
	}
return $temp_file_common,$temp_file_purpose
}

Function StorePassword()
{
	[string[]]$present_common_cert,[string[]]$present_purpose_cert=@()
	[string[]]$common_cert_password_obtained,[string[]]$purpose_cert_password_obtained=@()
	[string[]]$seperate_certs,[string[]]$seperate_purpose_certs=@()
	$data_not_found=0
	try
	{
	   $req_common_data = Get-Content -Path  $temp_file_common
	   $req_purpose_data = Get-Content -Path $temp_file_purpose
	   #Get details from the common CA certificates present in C:\Certificates path
	   if($req_common_data)
	   {
	      $seperate_certs += $req_common_data.Split( )
	      for($i=0;$i -lt $seperate_certs.Count;$i++)
	      {
		     $split_line = $seperate_certs[$i].Split('>') 
             $present_common_cert +=($split_line[0] -split ".p12")
             $common_cert_password_obtained += $split_line[1]
	      }
	   }
	   else
	   {
	    $data_not_found++
	   }
	   #Get details from the purpose specific CA certificates present in C:\Certificates\purpose_specific_certificates path
	   if($req_purpose_data)
	   {
	      $seperate_purpose_certs += $req_purpose_data.Split( )
	      for($j=0;$j -lt $seperate_purpose_certs.Count;$j++)
	      {
	    	  $split_line_new = $seperate_purpose_certs[$j].Split('>') 
              $present_purpose_cert +=($split_line_new[0] -split ".p12")
              $purpose_cert_password_obtained += $split_line_new[1]
	      }
	   }
	   else
	   {
	     $data_not_found++
	   }
	   if($data_not_found -eq 2)
	   {
	     "No values are available to proceed with the script execution." >> $log
		 DeleteTempFile
		 DeleteNewTask
		 ErrorHandle "No values are available to proceed with the script execution. Check $($log_file) file for more details. Press enter to exit code:"
	   }
       else
	   {
	   	"--------------------------------------------------" >>$log
	   }
	}
    catch
	{
		$_ >>$log
		$time = get-date -Format "yyyy MM dd HH:mm:ss"
		DeleteTempFile
		DeleteNewTask
		ErrorHandle "`n$time : [ERROR] Check $($log_file) for more details. Press enter to exit code:"
	}	
	return $present_common_cert,$common_cert_password_obtained,$present_purpose_cert,$purpose_cert_password_obtained
}

Function DeleteTempFile()
{
try
{
	if(Test-Path -Path $temp_file_common)
	{ 
	    Get-ChildItem $temp_file_common | Remove-Item
		"Temporary file removed successfully." >>$log
	}
	else
	{
	    "Temporary file not available in path $($temp_file_common)." >>$log
	}
	if(Test-Path -Path $temp_file_purpose)
	{ 
		Get-ChildItem $temp_file_purpose | Remove-Item
		"Temporary file removed successfully." >>$log
	}
	else
	{
		"Temporary file not available in path $($temp_file_purpose)." >>$log
	}
}
catch
{
   "$_" >>$log
   ErrorHandle "Error occured while deleting the temporary file. Check $($log_file) file for more details. Press enter to exit code:"
}
}

#------------------------------------------------
# To get details of server certificates
#------------------------------------------------
Function GetCertificateDetails()
{
PrintDateTime
[int[]]$CA_signed_Certificate,[int[]]$Self_signed_Certificate,[int[]]$days=@()
[string[]]$cert_thumbprint,[string[]]$certificates_name,[string[]]$NotAfter=@()
[string[]]$cert_present=@()
try
{
[string[]]$certificates_available = Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Subject,Issuer,NotAfter,Thumbprint
for($i=0;$i -lt $certificates_available.Count;$i++)
{
  $cert_details=$certificates_available[$i].Split('{',2)
  $cert_properties=$cert_details[1].Split('}',2)
  $cert_parameters=$cert_properties[0].Split(';',4)
  for($j=0;$j -lt $cert_parameters.Count;$j++)
  {
    if($cert_parameters[$j] -match "Issuer=")
	{
	  if($cert_parameters[$j] -match "CN=ENM_External_Entity_CA")
	  {
	     $CA_signed_Certificate+=$i
	  }
	  else
	  {
	     $Self_signed_Certificate+=$i
	  }
	}
	elseif($cert_parameters[$j] -match "Thumbprint=")
	{
	     $thumbprint=$cert_parameters[$j].Split('=',2)
	     $cert_thumbprint+= $thumbprint[1]
	}
	elseif($cert_parameters[$j] -match "NotAfter=")
	{
	     $NotAfter=$cert_parameters[$j].Split('=',2)
		 $format=$NotAfter[1]
	        try
            {
                 $converted_Date = [datetime]::ParseExact($format,'MM/dd/yyyy HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture)
            }
            catch [System.Management.Automation.MethodInvocationException]
            { 
                 $converted_Date = $format
            } 
            $days+=(New-TimeSpan -Start (Get-Date) -End $converted_Date).Days
	}
	else
	{
	  [string[]]$commonname=$cert_parameters[$j].Split(',')
	  for($a=0;$a -lt $commonname.Count;$a++)
	  {
		  if($commonname[$a] -match "CN=")
		  {
			  $splitname= $commonname[$a].Split("=",2)
			  if($splitname[0] -notmatch "CN")
			  {
			    $secondsplit = $splitname[1].Split("=",2)
				$certificates_name+= $secondsplit[1]
			  }
			  else
			  {
			    $certificates_name+= $splitname[1]
			  }
		  }
		  else
		  {
			  continue
		  }
	  }
	}
  }
 }
    if($global:CCSServer -match $True)
	{
     #Get citrix license certificates details
	   for($h=0;$h -lt $certificate_filepath.Count;$h++)
	   {
	      $certificate = Get-ChildItem -Path $certificate_filepath[$h]  | where {$_.Name -like "server.crt"} | Import-Certificate -CertStoreLocation Cert:\LocalMachine\My
	      $cert_days =$certificate.GetExpirationDateString()
		  if(($certificate.GetName()) -match ("CN="+$certname))
	      {
	        if(($certificate.GetIssuerName()) -match "CN=ENM_External_Entity_CA")
		    {
		      $cert_present += "CA_signed"
			  $license_cert_thumbprint += $certificate.Thumbprint
		    }
		    else
		    {
		      $cert_present += "Self_signed"
			  $license_cert_thumbprint += $certificate.Thumbprint
		    }
	    }
	      else
	      {
	      $cert_present += "Purpose_specific_CA_signed"
		  $license_cert_thumbprint += $certificate.Thumbprint
	    }
	  }
	  #Get expiry days of citrix license certificate
	  for($f=0;$f -lt $cert_present.Count;$f++)
	  {
	    if((((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "Purpose_specific_CA_signed"}).Count -eq 2) -or (((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "CA_signed"}).Count -eq 2) -or (((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "Self_signed"}).Count -eq 2))
		{
		    try
            {
                 $date = [datetime]::ParseExact($cert_days,'MM/dd/yyyy HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture)
            }
            catch [System.Management.Automation.MethodInvocationException]
            { 
                 $date = $cert_days
            } 
            $days_toexpire =(New-TimeSpan -Start (Get-Date) -End $date).Days
		}
		else
		{
		  "Certificates present in C:\Program Files (x86)\Citrix\Licensing\LS\conf\ path are not similar to the certificates in C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\ path. Place same certificates in both paths." >> $log
          DeleteTempFile
		  DeleteNewTask
		  ErrorHandle "Certificates present in C:\Program Files (x86)\Citrix\Licensing\LS\conf\ path are not similar to the certificates in C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\ path. Place same certificates in both paths. Check $($log_file) file for more details. Press enter to exit code:"
		}
	  }
	  #Remove the certificates if imported in the server
	   for($g=0;$g -lt $license_cert_thumbprint.Count;$g++)
	  {  
	   if(Test-Path -Path Cert:\LocalMachine\My\$($license_cert_thumbprint[$g]))
	   {
	     Remove-Item Cert:\LocalMachine\My\$($license_cert_thumbprint[$g]) 
	   }
	   else
	   {
	     "Cerificate is not imported in the server. " >> $log
	   }
	 }
    }
	else
	{
	  "All available certificate's details are collected. " >> $log
	}
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while getting the certificate details. Check $($log_file) file for more details. Press enter to exit code:"
}
 return $CA_signed_Certificate,$Self_signed_Certificate,$cert_thumbprint,$days,$certificates_name,$cert_present,$days_toexpire
}

#------------------------------------------------------------
# To get type of server certificates present in the server
#------------------------------------------------------------
Function GetCertificateType()
{
	PrintDateTime
	[string[]]$certificate_type = @()
	$common_cert_with_purpose = 1
	$purpose_specific_cert_with_purpose = 1
try
{
	$rdp_Thumbprint = ((Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices).SSLCertificateSHA1Hash).Split(" ")
if($cert_thumbprint)
{
   for($k=0;$k -lt $cert_thumbprint.Count;$k++)
   {
     if($global:ADServer -match $True)
	 {
       $test_Path="Registry::"+"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates\"+$cert_thumbprint[$k]
       if($certificates_name[$k] -match $certname)
       {
         if((Test-Path -Path $test_Path) -and ($rdp_Thumbprint -match $cert_thumbprint[$k]))
         {
            if($CA_signed_Certificate -contains $k)
	        {
		       $certificate_type += "common_cert"
	           $common_SSO_RDP_CA_cert = $cert_thumbprint[$k]
	           "A CA_signed_"+$certificates_name[$k]+" certificate is used for SSO and RDP feature.It expires in "+$days[$k]+" days." >> $log
	        }
	        else
	        {
	           " A self signed certificate can't be used for SSO and RDP feature.Not possible" >> $log
	        }
         }
         elseif((Test-Path -Path $test_Path) -and !($rdp_Thumbprint -match $cert_thumbprint[$k]))
         {
            if($CA_signed_Certificate -contains $k)
	        {
		       $certificate_type += "common_cert"
	           $common_SSO_CA_cert = $cert_thumbprint[$k]
	           " A CA_signed_"+$certificates_name[$k]+" certificate is used for SSO feature.It expires in "+$days[$k]+" days." >> $log
	        }
	        else
	        {
		       $certificate_type += "common_cert"
	           $common_SSO_SS_cert = $cert_thumbprint[$k]
	           " A Self_signed_"+$certificates_name[$k]+" certificate is used for SSO feature.It expires in "+$days[$k]+" days." >> $log
	        } 
         }
         elseif(!(Test-Path -Path $test_Path) -and ($rdp_Thumbprint -match $cert_thumbprint[$k]))
         {
            if($CA_signed_Certificate -contains $k)
	        {
		       $certificate_type += "common_cert"
	           $common_RDP_CA_cert = $cert_thumbprint[$k]
	           " A CA_signed_"+$certificates_name[$k]+" certificate is used for RDP feature.It expires in "+$days[$k]+" days." >> $log
	        }
	        else
	        {
	           continue
	        }
         }
         else
         {
	         $common_cert_with_purpose =0
         }
      }
       else
       {
        if((Test-Path -Path $test_Path) -and !($rdp_Thumbprint -match $cert_thumbprint[$k]))
        {
            if($CA_signed_Certificate -contains $k)
	        {
		        $certificate_type += "purpose_specific_cert"
	            $purpose_specific_SSO_CA_cert = $cert_thumbprint[$k]
	            " A CA_signed_"+$certificates_name[$k]+" certificate is used for SSO feature.It expires in "+$days[$k]+" days." >> $log
	        }
	        else
	        {
	            continue
	        }
        }
        elseif(!(Test-Path -Path $test_Path) -and ($rdp_Thumbprint -match $cert_thumbprint[$k]))
        {
            if($CA_signed_Certificate -contains $k)
	        {
		        $certificate_type += "purpose_specific_cert"
	            $purpose_specific_RDP_CA_cert = $cert_thumbprint[$k]
	            " A CA_signed_"+$certificates_name[$k]+" certificate is used for RDP feature.It expires in "+$days[$k]+" days." >> $log
	        }
	        else
	        {
	            continue
	        }
        }
        else
        {
		   $purpose_specific_cert_with_purpose = 0
	    }		
      }
     }
	 elseif($global:CCSServer -match $True)
	 {
	    Get-ChildItem -Path IIS:SSLBindings | ForEach-Object -Process `
        {
           $httpCert_Thumbprint= $_.Thumbprint
        }
	   if($certificates_name[$k] -match $certname)
       {
		  if(($cert_thumbprint[$k] -match $httpCert_Thumbprint) -and ($rdp_Thumbprint -match $cert_thumbprint[$k]))
		  {
		    if($CA_signed_Certificate -contains $k)
	        {
		       $certificate_type += "common_cert"
	           $common_HTTPS_RDP_CA_cert = $cert_thumbprint[$k]
	           "A CA_signed_"+$certificates_name[$k]+" certificate is used for HTTPS and RDP feature.It expires in "+$days[$k]+" days." >> $log
	        }
            else
            {
			   " A self signed certificate can't be used for HTTPS and RDP feature.Not possible" >> $logs
			}			
		  }
		  elseif(($cert_thumbprint[$k] -match $httpCert_Thumbprint) -and !($rdp_Thumbprint -match $cert_thumbprint[$k]))
		  {
		     if($CA_signed_Certificate -contains $k)
	         {
			   $certificate_type += "common_cert"
	           $HTTPS_CA_cert = $cert_thumbprint[$k]
	           "A CA_signed_"+$certificates_name[$k]+" certificate is used for HTTPS feature.It expires in "+$days[$k]+" days." >> $log
	         }
			 else
			 {
			    continue
			 }
		  }
		  elseif(!($cert_thumbprint[$k] -match $httpCert_Thumbprint) -and ($rdp_Thumbprint -match $cert_thumbprint[$k]))
		  {
		     if($CA_signed_Certificate -contains $k)
	         {
			   $certificate_type += "common_cert"
	           $common_RDP_CA_cert = $cert_thumbprint[$k]
	           "A CA_signed_"+$certificates_name[$k]+" certificate is used for RDP feature.It expires in "+$days[$k]+" days." >> $log
	         }
			 else
			 {
			    continue
			 }
		  }
		  else
		  {
		    $common_cert_with_purpose =0
		  }
	   }
	   else
	   {
	     if(!($cert_thumbprint[$k] -match $httpCert_Thumbprint) -and ($rdp_Thumbprint -match $cert_thumbprint[$k]))
		 {
		    if($CA_signed_Certificate -contains $k)
	         {
			   $certificate_type += "purpose_specific_cert"
	           $purpose_specific_RDP_CA_cert = $cert_thumbprint[$k]
	           "A CA_signed_"+$certificates_name[$k]+" certificate is used for RDP feature.It expires in "+$days[$k]+" days." >> $log
	         }
			 else
			 {
			    continue
			 }
	     }
		 else
		 {
		   $purpose_specific_cert_with_purpose = 0
		 }
	   }
   }
	 elseif($global:VDAServer -match $True)
	 {
	     #Get the tls certificate detail if present
          if(Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd")
          {
		    $tls_cert = Get-ItemPropertyValue -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd" -Name "SSLEnabled"
		    if($tls_cert -eq 1)
			{
			   $tlscert_temp = Get-ItemPropertyValue -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd" -Name "SSLThumbprint"
			   $tls_thumbprint = ($tlscert_temp | Format-Hex | Select-Object -Expand Bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ''
			}
			else
			{
			  $tls_thumbprint = $null
			}   
          }
          else
          {
            $tls_cert = $null
          }
		 #Get certificates present in the server
		 if($certificates_name[$k] -match $certname)
         {
           if(($tls_thumbprint -match $cert_thumbprint[$k]) -and ($rdp_Thumbprint -match $cert_thumbprint[$k]))
           {
		      if($CA_signed_Certificate -contains $k)
	          {
		         $certificate_type += "common_cert"
	             $common_TLS_RDP_CA_cert = $cert_thumbprint[$k]
	             "A CA_signed_"+$certificates_name[$k]+" certificate is used for TLS and RDP feature.It expires in "+$days[$k]+" days." >> $log
	          }
              else
              {
			     " A self signed certificate can't be used for TLS and RDP feature.Not possible" >> $log
			  }	
		   }
           elseif(($tls_thumbprint -match $cert_thumbprint[$k]) -and !($rdp_Thumbprint -match $cert_thumbprint[$k]))
           {
		      if($CA_signed_Certificate -contains $k)
	          {
			     $certificate_type += "common_cert"
	             $common_TLS_CA_cert = $cert_thumbprint[$k]
	             "A CA_signed_"+$certificates_name[$k]+" certificate is used for TLS feature.It expires in "+$days[$k]+" days." >> $log
	          }
			  else
			  {
			    continue
			  }
		   }
           elseif(!($tls_thumbprint -match $cert_thumbprint[$k]) -and ($rdp_Thumbprint -match $cert_thumbprint[$k]))	
           {
		      if($CA_signed_Certificate -contains $k)
	          {
			     $certificate_type += "common_cert"
	             $common_RDP_CA_cert = $cert_thumbprint[$k]
	             "A CA_signed_"+$certificates_name[$k]+" certificate is used for RDP feature.It expires in "+$days[$k]+" days." >> $log
	          }
			  else
			  {
			    continue
			  }
		   }
           else
		   {
		     $common_cert_with_purpose =0
		   }
         }
         else
         {
		    if(($tls_thumbprint -match $cert_thumbprint[$k]) -and !($rdp_Thumbprint -match $cert_thumbprint[$k]))
			{
			    if($CA_signed_Certificate -contains $k)
	            {
			      $certificate_type += "purpose_specific_cert"
	              $purpose_specific_TLS_CA_cert = $cert_thumbprint[$k]
	              "A CA_signed_"+$certificates_name[$k]+" certificate is used for TLS feature.It expires in "+$days[$k]+" days." >> $log
	            }
			    else
			    {
			      continue
			    } 
			}
			elseif(!($tls_thumbprint -match $cert_thumbprint[$k]) -and ($rdp_Thumbprint -match $cert_thumbprint[$k]))
			{
			    if($CA_signed_Certificate -contains $k)
	            {
			      $certificate_type += "purpose_specific_cert"
	              $purpose_specific_RDP_CA_cert = $cert_thumbprint[$k]
	              "A CA_signed_"+$certificates_name[$k]+" certificate is used for RDP feature.It expires in "+$days[$k]+" days." >> $log
	            }
			    else
			    {
			      continue
			    }
			}
			else
		    {
		       $purpose_specific_cert_with_purpose = 0
		    }
		 }		 
	 }
	 else
	 {
	   continue
	 }
   }
    #Get server.crt certificate details
      if($global:CCSServer -match $True)
	  {
	     if(((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "Purpose_specific_CA_signed"}).Count -eq 2)
	     {
	        "A Purpose_specific_CA_signed Server.crt certificate is used for Citrix license feature.It expires in "+$days_toexpire+" days." >>$log
	     }
	     elseif(((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "CA_signed"}).Count -eq 2)
	     {
		    "A CA_signed Server.crt certificate is used for Citrix license feature.It expires in "+$days_toexpire+" days. " >>$log	
	     }
	     elseif(((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "Self_signed"}).Count -eq 2)
	     {
	        "A Self_signed Server.crt certificate is used for Citrix license feature.It expires in "+$days_toexpire+" days. " >> $log
	     }
	     else
	     {
	        "Certificates present in C:\Program Files (x86)\Citrix\Licensing\LS\conf\ path are not similar to the certificates in C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\ path. Place same certificates in both paths." >> $log
             DeleteTempFile
		    DeleteNewTask
			ErrorHandle "Certificates present in C:\Program Files (x86)\Citrix\Licensing\LS\conf\ path are not similar to the certificates in C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\ path. Place same certificates in both paths. Check $($log_file) file for more details. Press enter to exit code:"	
	     }
	  }	 
   #Find if there are certs without purpose or no certs available
   if(($common_cert_with_purpose -eq 0) -and ($purpose_specific_cert_with_purpose -eq 0))
   {
	  $certificate_type += "no_cert"
	  "No CA signed certificate(s) are available in the server. " >>$log
   }
   elseif($common_cert_with_purpose -eq 0)
   {
	  $certificate_type += "no_cert" 
	  "Some CA signed certificate(s) available in the server does not handle any features. " >>$log
   }
   elseif($purpose_specific_cert_with_purpose -eq 0)
   {
	   $certificate_type += "no_cert"
	   "Some CA signed certificate(s) available in the server does not handle any features. " >>$log
   }
   else
   {
      $certificate_type += " "
   }
}
else
{
	 $certificate_type += "no_cert"
     "No CA signed certificate available in the server handles features." >> $log
}
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while getting type of certificates. Check $($log_file) file for more details. Press enter to exit code:"
}
return $certificate_type,$common_RDP_CA_cert,$common_SSO_RDP_CA_cert,$common_SSO_CA_cert,$common_SSO_SS_cert,$common_HTTPS_RDP_CA_cert,$HTTPS_CA_cert,$common_TLS_RDP_CA_cert,$common_TLS_CA_cert,$purpose_specific_SSO_CA_cert,$purpose_specific_RDP_CA_cert,$purpose_specific_TLS_CA_cert
}

Function ReplaceFolders ()
{
    [string[]]$cert_temp=@()
try
{
    $script:drive = CheckOCSMedia($OCSMedia)
	if($global:ADServer -match $True)
    {
	    $SourceDirectory = $script:drive+"ENM-SSO"
        $DestinationDirectory = "C:\"
        copy-item -path $SourceDirectory -destination $DestinationDirectory -Recurse -Force >> $log
        if(Test-Path -Path ($DestinationDirectory+"ENM-SSO"))
        {
            "ENM-SSO folder copied successfully" >> $log
			if((Test-Path -path "C:\Certificates\purpose_specific_certificates\$($cert_name_SSO)*") -and (Test-Path -path "C:\Certificates\purpose_specific_certificates\ENM_External*") -and (Test-Path -path "C:\Certificates\purpose_specific_certificates\ENM_PKI*"))
			{
			  if($common_SSO_CA_cert)
			  {
			     # Test Certificates folder is available or not for SSO_CA script
				 if(Test-Path -path "C:\ENM-SSO\Certificates\")
		         {
		              "C:\ENM-SSO\Certificates path is available. " >> $log
					  [string[]]$temp_array_SSO = Get-ChildItem "C:\ENM-SSO\Certificates\"
					  if($temp_array_SSO)
					  {
					     for($i=0;$i -lt $temp_array_SSO.Count;$i++)
			             {
			                Remove-Item -Path "C:\ENM-SSO\Certificates\$($temp_array_SSO[$i])" 
			             }
			          }
					  else
					  {
					    "Certificates folder under C:\ENM-SSO\Certificates\ path is empty. " >> $log
					  }
		         }
		         else
		         {
		             New-Item -ItemType Directory -Force -Path "C:\ENM-SSO\Certificates" | Out-Null
		         }
			   copy-item -path "C:\Certificates\purpose_specific_certificates\$($cert_name_SSO)*" -destination "C:\ENM-SSO\Certificates\" -Recurse -Force
			   copy-item -path "C:\Certificates\purpose_specific_certificates\ENM_External*" -destination "C:\ENM-SSO\Certificates\" -Recurse -Force
			   copy-item -path "C:\Certificates\purpose_specific_certificates\ENM_PKI*" -destination "C:\ENM-SSO\Certificates\" -Recurse -Force
			  }
			  elseif($common_SSO_SS_cert)
			  {
			      # Test Certificates folder is available or not for Certificate_replace script
		          if(Test-Path -path "C:\ENM-SSO\Selfsigned_remove\Certificates\")
		          {
		             "C:\ENM-SSO\Selfsigned_remove\Certificates path is available. " >> $log
					  [string[]]$temp_array_SSO = Get-ChildItem "C:\ENM-SSO\Selfsigned_remove\Certificates\"
					  if($temp_array_SSO)
					  {
					     for($i=0;$i -lt $temp_array_SSO.Count;$i++)
			             {
			                Remove-Item -Path "C:\ENM-SSO\Selfsigned_remove\Certificates\$($temp_array_SSO[$i])" 
			             }
			          }
					  else
					  {
					    "Certificates folder under C:\ENM-SSO\Selfsigned_remove\Certificates\ path is empty. " >> $log
					  }
		          }
		          else
		          {
		              New-Item -ItemType Directory -Force -Path "C:\ENM-SSO\Selfsigned_remove\Certificates" | Out-Null
		          }
			   copy-item -path "C:\Certificates\purpose_specific_certificates\$($cert_name_SSO)*" -destination "C:\ENM-SSO\Selfsigned_remove\Certificates\" -Recurse -Force
			   copy-item -path "C:\Certificates\purpose_specific_certificates\ENM_External*" -destination "C:\ENM-SSO\Selfsigned_remove\Certificates\" -Recurse -Force
			   copy-item -path "C:\Certificates\purpose_specific_certificates\ENM_PKI*" -destination "C:\ENM-SSO\Selfsigned_remove\Certificates\" -Recurse -Force
			  }
			}
            else
            {
			   "$($cert_name_SSO)_cert.p12 or External Entity or Root certificate is not available in the folder." >> $log
			   DeleteTempFile
			   DeleteNewTask
			   ErrorHandle "$($cert_name_SSO)_cert.p12 or External Entity or Root certificate is not available in the folder C:\Certificates\purpose_specific_certificates. Check $($log_file) file for more details. Press enter to exit code:"
			}			
        } 
		else
		{
		  "Copying ENM_SSO folder  from media failed. " >> $log
		  DeleteTempFile
		  DeleteNewTask
		  ErrorHandle " Copying ENM_SSO folder  from media failed. Check $($log_file) file for more details. Press enter to exit code:"
		}
	}
    elseif($global:VDAServer -match $True)
    {
        $SourceDirectory = $script:drive+"OCS-Automation\TLS1.2\TLS1.2_VDA_config"
        $DestinationDirectory = "C:\OCS\install_config\"
        Copy-Item -path $SourceDirectory -destination $DestinationDirectory -Recurse -Force
		if(Test-Path -path "C:\OCS\install_config\TLS1.2_VDA_config\Certificates\")
		{
		   [string[]]$temp_array = Get-ChildItem "C:\OCS\install_config\TLS1.2_VDA_config\Certificates\"
		    for($i=0;$i -lt $temp_array.Count;$i++)
			{
			   if($temp_array[$i] -match ".gitkeep")
			   {
			      continue
			   }
			   else
			   {
			      Remove-Item -Path "C:\OCS\install_config\TLS1.2_VDA_config\Certificates\$($temp_array[$i])" 
			   }
			}
		}
		else
		{
		   "No files are available in C:\OCS\install_config\TLS1.2_VDA_config\Certificates\ path. " >> $log
		}
        if(Test-Path -Path ($DestinationDirectory+"TLS1.2_VDA_config"))
        {
            "TLS1.2_VDA_config folder copied successfully" >> $log
             if(((Get-ChildItem C:\OCS\install_config\TLS1.2_VDA_config\Counter.txt).IsReadOnly) -and ((Get-ChildItem C:\OCS\install_config\TLS1.2_VDA_config\PsLogon.bat).IsReadOnly))
             {
			    (Get-ChildItem  C:\OCS\install_config\TLS1.2_VDA_config\Counter.txt).Set_IsReadOnly($False)
			    (Get-ChildItem  C:\OCS\install_config\TLS1.2_VDA_config\PsLogon.bat).Set_IsReadOnly($False)
			 }
			 #Checking the presence of certificates and add the certificates into array
            if(Get-ChildItem $specific_cert_dir | Where-Object {$_.name -like "$cert_name_TLS*"})
            {
			   $cert_temp += Get-ChildItem $specific_cert_dir | Where-Object {$_.name -like "$cert_name_TLS*"}
			}
            else
            {
			   "The $($cert_name_TLS)_cert.p12 certificate is not available in $($specific_cert_dir) folder." >> $log
			   DeleteTempFile
               DeleteNewTask
			   ErrorHandle "Error occured  due to unavailability of the $($cert_name_TLS)_cert.p12 certificate. Check $($log_file) file for more details. Press enter to exit code:" 
			} 
            if(Get-ChildItem $specific_cert_dir | Where-Object {$_.name -match "ENM_External*"})
            {			
               $cert_temp += Get-ChildItem $specific_cert_dir | Where-Object {$_.name -match "ENM_External*"}
			}
			else
            {
			   "The ENM_External_Entity certificate is not available in $($specific_cert_dir) folder." >> $log
			   DeleteTempFile
               DeleteNewTask
			   ErrorHandle "Error occured due to unavailability of the ENM_External_Entity certificate. Check $($log_file) file for more details. Press enter to exit code:" 
			}
            if(Get-ChildItem $specific_cert_dir | Where-Object {$_.name -match "ENM_PKI*"})
            {			
               $cert_temp += Get-ChildItem $specific_cert_dir | Where-Object {$_.name -match "ENM_PKI*"}
			}
			else
            {
			   "The ENM_PKI_Root certificate is not available in $($specific_cert_dir) folder." >> $log
			   DeleteTempFile
               DeleteNewTask
			   ErrorHandle "Error occured due to unavailability of the ENM_PKI_Root certificate. Check $($log_file) file for more details. Press enter to exit code:" 
			}
			#Copying the certificates into C:\OCS\install_config\TLS1.2_VDA_config\Certificates\ folder
            for($i=0;$i -lt $cert_temp.Count;$i++)
            {
			 Copy-Item -path "$($specific_cert_dir)$($cert_temp[$i])" -destination "C:\OCS\install_config\TLS1.2_VDA_config\Certificates\" -Recurse -Force
			 "$($cert_temp[$i]) copied successfully. " >> $log
		    }	
        } 
		else
		{
		    "Copying the new TLS1.2_VDA_config folder failed. " >>$log
			DeleteTempFile
            DeleteNewTask
			ErrorHandle "Error occured while copying the new TLS1.2_VDA_config folder failed. Check $($log_file) file for more details. Press enter to exit code:"
		}
    }    
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while replacing the folders. Check $($log_file) file for more details. Press enter to exit code:"
}
}

#-------------------------------------------------------------------------------------------------------------
# Function to rollback CA signed certificate to self signed certificate for Remote Desktop Services feature
#-------------------------------------------------------------------------------------------------------------
Function RollbackOfRDPCert ()
{
	PrintDateTime
    "Rollback of CA signed certificate to self signed certificate for RDP has started.." >> $log
	Write-Host "Rollback of CA signed certificate to self signed certificate for RDP has started.."
  try
  {
   if($common_RDP_CA_cert -or $common_SSO_RDP_CA_cert -or $common_HTTPS_RDP_CA_cert -or $common_TLS_RDP_CA_cert)
   {
       Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name SSLCertificateSHA1Hash
	  "Rollback to self signed certificate for RDP feature completed successfully." >> $log
	  Write-Host "Rollback to self signed certificate for RDP feature completed successfully.System will restart now."
	  RemoveCASignedCert
	  TaskCreation
      shutdown -r
	  EXIT(1)
   }
   elseif($purpose_specific_RDP_CA_cert)
   {
      "Purpose specific certificate for RDP feature is already available in server. Hence rollback not required." >>$log
	  Write-Host "Purpose specific certificate for RDP feature is already available in server. Hence rollback not required." 
   }
   else
   {
      "Currenly self signed certificate is used for RDP feature." >> $log
	  Write-Host "Currenly self signed certificate is used for RDP feature."
   }
  }
  catch
  {
		$_ >>$log
		"Error while performing rollback of CA signed certificate to self signed certificate for rdp feature." >> $log
		DeleteTempFile
		DeleteNewTask
		ErrorHandle "Error while performing rollback of CA signed certificate to self signed certificate for rdp feature. Check $($log_file) file for more details. Press enter to exit code:"			
  }
} 

#-------------------------------------------------------------------------------------------------------------
# Function to rollback CA signed certificate to self signed certificate for Citrix License feature
#-------------------------------------------------------------------------------------------------------------
Function RollbackOfLicenseCert ()
{
  PrintDateTime
  [string[]]$cert_present,[string[]]$license_cert_thumbprint = @()
  [string]$condition = $null
try
{
  "Rollback of CA signed certificate to self signed certificate for Citrix license has started.." >> $log
  Write-Host "Rollback of CA signed certificate to self signed certificate for Citrix license has started.."
     $license_cert = Get-ChildItem -Path "C:\Certificates"  | where {$_.Name -like "server.crt"} | Import-Certificate -CertStoreLocation Cert:\LocalMachine\My
	 #Find the type of certificates present in C:\Certificates path
	 if($license_cert)
	 {
	   if(($license_cert.GetName()) -match ("CN="+$certname))
	   {
	     if(($license_cert.GetIssuerName()) -match "CN=ENM_External_Entity_CA")
	     {
	       $condition = $false
	       "Certificates present in C:\Certificates path are common CA signed certificates. " >>$log
	     }
	     else
	     {
	       $condition = $true
	       $license_cert_thumbprint += $license_cert.Thumbprint
	       "Certificates present in C:\Certificates path are self signed certificates. " >>$log
	     }
	   }
	   else
	   {
	      $condition = $false
	      $license_cert_thumbprint += $license_cert.Thumbprint
	      "Certificates present in C:\Certificates path are purpose specific CA signed certificates. " >>$log
	   }
	 }
	 else
	 {
	    "Self signed certificates are available for citrix license in the server. " >> $log
	 }
	 # Find the certificates present in the expected path
	 for($h=0;$h -lt $certificate_filepath.Count;$h++)
	 {
	   $certificate = Get-ChildItem -Path $certificate_filepath[$h]  | where {$_.Name -like "server.crt"} | Import-Certificate -CertStoreLocation Cert:\LocalMachine\My
	   if(($certificate.GetName()) -match ("CN="+$certname))
	   {
	     if(($certificate.GetIssuerName()) -match "CN=ENM_External_Entity_CA")
		 {
		    $cert_present += "common_ca-signed"
		 }
		 else
		 {
		    $cert_present += "self-signed"
			$license_cert_thumbprint += $certificate.Thumbprint
		 }
	   }
	   else
	   {
	     $cert_present += "purpose_specific_ca-signed"
		 $license_cert_thumbprint += $certificate.Thumbprint
	   }
	 }
	  #Remove the certificates if imported in the server
	 for($g=0;$g -lt $license_cert_thumbprint.Count;$g++)
	 { 
	   if(Test-Path -Path Cert:\LocalMachine\My\$($license_cert_thumbprint[$g]))
	   {
	     Remove-Item Cert:\LocalMachine\My\$($license_cert_thumbprint[$g]) 
	   }
	   else
	   {
	     "Cerificate is not imported in the server. " >> $log
	   }
	 }
	 # Replace the CA signed certificates with self signed certificates if applicable
	 if(((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "purpose_specific_ca-signed"}).Count -eq 2)
	 {
	    "Expected purpose specific certificates are already available in the server for Citrix licence feature. " >>$log
		Write-Host "Expected purpose specific certificates are already available in the server for Citrix licence feature. " 
	 }
	 elseif(((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "common_ca-signed"}).Count -eq 2)
	 {
	    if($condition)
		{
		  Copy-Item  -Path "C:\Certificates\server.crt" -Destination "C:\Program Files (x86)\Citrix\Licensing\LS\conf\" -Recurse -force
		  Copy-Item  -Path "C:\Certificates\server.key" -Destination "C:\Program Files (x86)\Citrix\Licensing\LS\conf\" -Recurse -force
		  Copy-Item  -Path "C:\Certificates\server.crt" -Destination "C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\" -Recurse -force
		  Copy-Item  -Path "C:\Certificates\server.key" -Destination "C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\" -Recurse -force
		  Get-Service -Name "Citrix Licensing"  | Restart-Service -WarningAction Ignore
		  Get-Service -Name "Citrix Web Services for Licensing"  | Restart-Service -WarningAction Ignore
		  "Rollback of self signed certificate for citrix license feature completed successfully. " >>$log
		  Write-Host "Rollback of self signed certificate for citrix license feature completed successfully. "
		}
		else
		{
		  "Backup certificates available for citrix license feature is CA signed certificates.Place required self signed certificates in the C:\Certificates paths." >> $log
		  DeleteTempFile
          DeleteNewTask
		  ErrorHandle "Backup certificates available for citrix license feature is CA signed certificates.Place required self signed certificates in the C:\Certificates path. Check $($log_file) file for more details. Press enter to exit code:"
		}
	 }
	 elseif(((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "self-signed"}).Count -eq 2)
	 {
	    "Self signed certificates are already available in expected paths. " >> $log
		Write-Host "Self signed certificates are already available in expected paths. "
		Copy-Item  -Path "C:\Program Files (x86)\Citrix\Licensing\LS\conf\server.crt" -Destination "C:\Certificates" -Recurse -force
		Copy-Item  -Path "C:\Program Files (x86)\Citrix\Licensing\LS\conf\server.key" -Destination "C:\Certificates" -Recurse -force
	 }
	 else
	 {
	    "Certificates present in C:\Program Files (x86)\Citrix\Licensing\LS\conf\ path are not similar to the certificates in C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\ path. Place same certificates in both paths." >> $log
         DeleteTempFile
         DeleteNewTask
		 ErrorHandle "Certificates present in C:\Program Files (x86)\Citrix\Licensing\LS\conf\ path are not similar to the certificates in C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\ path. Place same certificates in both paths. Check $($log_file) file for more details. Press enter to exit code:"
	 }
  #Check whether the certificates are available in C:\Certificates path 
  if((Test-Path -path "C:\Certificates\server.key") -and (Test-Path -path "C:\Certificates\server.crt"))
  {
     "Expected backup certificates for citrix license feature are available in C:\Certificates path." >> $log
	 Write-Host "Expected backup certificates for citrix license feature are available in C:\Certificates path."
  }
  else
  {     
     "Expected backup certificates for citrix license feature are not available in C:\Certificates path." >>$log
	 Write-Host "Expected backup certificates for citrix license feature are not available in C:\Certificates path." 
  }
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while performing rollback of license cert. Check $($log_file) file for more details. Press enter to exit code:"
}
  return $cert_present
 }

#-------------------------------------------------------------------------------
# Function to remove the existing CA signed certificates if present
#------------------------------------------------------------------------------- 
Function RemoveCASignedCert ()
{
	PrintDateTime
	[string[]]$common_cert_thumbprint =@()
	$cert_count=0
	$cert_count_mmc=0
try
{
  # To get the thumbprint of the .p12 certificate in C:\Certificates location.
  "Removing the CA signed certificates if imported in the server.." >> $log
  Write-Host "Removing the old CA signed certificates if imported in the server.."
   if($cert_path)
   {
     for($m=0;$m -lt $cert_path.Count;$m++)
     {
       if(Test-Path -Path $cert_path[$m])
       {
			  $password =  ConvertTo-SecureString -AsPlainText -String $common_cert_password_obtained[$m] -Force
			  $cert_file = Get-PfxData -FilePath $cert_path[$m] -Password $password
              $cert_thumbprint_available = $cert_file.EndEntityCertificates.Thumbprint
              if($common_SSO_CA_cert -or $common_RDP_CA_cert -or $common_TLS_CA_cert)
			  {
			     if($common_SSO_CA_cert -match $cert_thumbprint_available)
			     {
				    $temp_cert_name = $cert_name[$m]
			       if(Test-Path -Path C:\Certificates\$temp_cert_name)
	               {
	                 Get-ChildItem -Path C:\Certificates\$temp_cert_name | Remove-Item
                     "Certificate present in C:\Certificates path for SSO feature is removed from the server." >> $log
					 $cert_count += 1
	               }
	               else
	               {
                    "$($cert_name[$m]) certificate present in C:\Certificates is not available Cert:\LocalMachine\My path." >> $log
	               }
			     }
                 elseif($common_RDP_CA_cert -match $cert_thumbprint_available)
			     {
				    $temp_cert_name = $cert_name[$m]
			       if(Test-Path -Path C:\Certificates\$temp_cert_name)
	               {
	                 Get-ChildItem -Path C:\Certificates\$temp_cert_name | Remove-Item
                     "Certificate present in C:\Certificates path for RDP feature is removed from the server." >> $log
					 $cert_count += 1
	               }
	               else
	               {
                    "$($cert_name[$m]) certificate present in C:\Certificates is not available Cert:\LocalMachine\My path." >> $log
	               }
			     }
				 elseif($common_TLS_CA_cert -match $cert_thumbprint_available)
			     {
				    $temp_cert_name = $cert_name[$m]
			       if(Test-Path -Path C:\Certificates\$temp_cert_name)
	               {
	                 Get-ChildItem -Path C:\Certificates\$temp_cert_name | Remove-Item
                     "Certificate present in C:\Certificates path for TLS feature is removed from the server." >> $log
					 $cert_count += 1
	               }
	               else
	               {
                    "$($cert_name[$m]) certificate present in C:\Certificates is not available Cert:\LocalMachine\My path." >> $log
	               }
			     }
                 else
                 {
				    continue
				 }				 
			  }
			  else
		      {
			     if($m -eq $cert_path.Count-1)
				 {
				    if($cert_count -eq 0)
					{
					  "No CA signed certificates needs to be removed from the server. " >> $log
					}
				    else
					{
					   break
					}	
				 }
				 else
				 {
				    continue
				 }
		      }
	   }
	   else
	   {
	      continue
	   }
     }
   }
   else
   {
     "There are no CA signed certificates which needs to be removed from C:\Certificates path ." >> $log
   }
  if(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -match $certname})
  {
      for($t=0;$t -lt $certificates_name.Count;$t++)
	  {
		  if($certificates_name[$t] -match $certname)
		  {
		     $common_cert_thumbprint =(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -match $certname}).Thumbprint
			   for($v=0;$v -lt $common_cert_thumbprint.Count;$v++)
			   {
				   $thumbprint_temp = $common_cert_thumbprint[$v]
					    if($common_SSO_RDP_CA_cert  -match $thumbprint_temp) 
				        {
						  if(($purpose_specific_rdp_cert_found -eq 1) -and ($purpose_specific_sso_cert_found -eq 1))
						  {
						    Get-ChildItem Cert:\LocalMachine\My\$thumbprint_temp | Remove-Item
                            "Certificate present for RDP and SSO feature in Cert:\LocalMachine\My path is removed from the server." >> $log
							$cert_count_mmc += 1
						  }
				          elseif(($purpose_specific_rdp_cert_found -eq 1) -and ($purpose_specific_sso_cert_found -eq 0))
						  {
						    "Same certificate is used for SSO and RDP features. Alternate purpose specific certificate for SSO feature is not found. Hence certificate will not be deleted." >> $log
						  }
						  elseif(($purpose_specific_rdp_cert_found -eq 0) -and ($purpose_specific_sso_cert_found -eq 1))
						  {
						    "Same certificate is used for SSO and RDP features. Alternate purpose specific certificate for RDP feature is not found. Hence certificate will not be deleted." >> $log
						  }
						  else
						  {
						    "Same certificate is used for SSO and RDP features. No alternate purpose specific certificates are found. Hence certificate will not be deleted." >> $log
						  }
				        }
						elseif($common_TLS_RDP_CA_cert  -match $thumbprint_temp) 
				        {
						  if(($purpose_specific_rdp_cert_found -eq 1) -and ($purpose_specific_tls_cert_found -eq 1))
						  {
						    Get-ChildItem Cert:\LocalMachine\My\$thumbprint_temp | Remove-Item
                            "Certificate present for RDP and TLS feature in Cert:\LocalMachine\My path is removed from the server." >> $log
							$cert_count_mmc += 1
						  }
				          elseif(($purpose_specific_rdp_cert_found -eq 1) -and ($purpose_specific_tls_cert_found -eq 0))
						  {
						    "Same certificate is used for TLS and RDP features. Alternate purpose specific certificate for TLS feature is not found. Hence certificate will not be deleted." >> $log
						  }
						  elseif(($purpose_specific_rdp_cert_found -eq 0) -and ($purpose_specific_tls_cert_found -eq 1))
						  {
						    "Same certificate is used for TLS and RDP features. Alternate purpose specific certificate for RDP feature is not found. Hence certificate will not be deleted." >> $log
						  }
						  else
						  {
						    "Same certificate is used for TLS and RDP features. No alternate purpose specific certificates are found. Hence certificate will not be deleted." >> $log
						  }
				        }
						elseif($common_HTTPS_RDP_CA_cert -match $thumbprint_temp) 
				        {
						    "Same certificate is used for HTTPS and RDP features.Hence certificate will not be deleted." >> $log
				        }
						elseif($common_RDP_CA_cert -match $thumbprint_temp)
						{
						   if($purpose_specific_rdp_cert_found -eq 1)
						   {
						     Get-ChildItem Cert:\LocalMachine\My\$thumbprint_temp | Remove-Item
                            "Certificate present for RDP feature in Cert:\LocalMachine\My path is removed from the server." >> $log
							 $cert_count_mmc += 1
						   }
						   else
						   {
						     "Alternate purpose specific certificate for RDP feature is not found. Hence certificate will not be deleted." >> $log
						   }
						}
						elseif($common_SSO_CA_cert -match $thumbprint_temp)
						{
						   if($purpose_specific_sso_cert_found -eq 1)
						   {
						     Get-ChildItem Cert:\LocalMachine\My\$thumbprint_temp | Remove-Item
                            "Certificate present for SSO feature in Cert:\LocalMachine\My path is removed from the server." >> $log
							 $cert_count_mmc +=1
						   }
						   else
						   {
						     "Alternate purpose specific certificate for SSO feature is not found. Hence certificate will not be deleted." >> $log
						   }
						}
						elseif($common_TLS_CA_cert -match $thumbprint_temp)
						{
						   if($purpose_specific_tls_cert_found -eq 1)
						   {
						     Get-ChildItem Cert:\LocalMachine\My\$thumbprint_temp | Remove-Item
                            "Certificate present for TLS feature  in Cert:\LocalMachine\My path is removed from the server." >> $log
							 $cert_count_mmc += 1
						   }
						   else
						   {
						     "Alternate purpose specific certificate for TLS feature is not found. Hence certificate will not be deleted." >> $log
						   }
						}
						else
						{
						   continue
						}
				}
		  }
		  else
          {
		       continue
	      }
		  #Details of certificates removed
		  if($certificates_name.Count -eq 1)
		  {
		          TaskCreation
                   shutdown -r
	               EXIT(1)
		  }
		  elseif($t -eq $certificates_name.Count-1)
		  {

			   if($cert_count_mmc -eq 0)
			   {
		         "No CA signed certificates needs to be removed from the server. " >> $log
			   }
			   else
			   {
			       TaskCreation
                   shutdown -r
	               EXIT(1)
			   }
		  }
	      else
		  {
	         continue
	      }
      }
  }
  else
  {
     "There are no CA signed certificates which needs to be removed from Cert:\LocalMachine\My path ." >> $log
  }
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while removing the old ca certificates. Check $($log_file) file for more details. Press enter to exit code:"
}
} 

#-------------------------------------------------------------------------------
# Function to import the new certificates added to the specific path
#-------------------------------------------------------------------------------
Function ImportNewCACert ()
{
try
{
	PrintDateTime
	"Checking for certificates which needs to be imported if applicable in the server.." >> $log
	Write-Host "Checking for certificates which needs to be imported if applicable in the server.."
  if(($global:ADServer -match $True) -and $rdp_cert -and $sso_cert)
  {
	  "CA signed certificates for RDP feature is already imported in the server." >> $log
	  Write-Host "CA signed certificates for RDP feature is already imported in the server."
  }
  elseif(($global:CCSServer -match $True) -and $rdp_cert)
  {
      "CA signed certificate for RDP feature is already imported in the server." >> $log 
	  Write-Host "CA signed certificate for RDP feature is already imported in the server."
  }
  elseif(($global:VDAServer -match $True) -and $rdp_cert -and $tls_cert)
  {
      "CA signed certificate for RDP and TLS feature is already imported in the server." >> $log 
	  Write-Host "CA signed certificate for RDP and TLS feature is already imported in the server."
  }
  else
  {
    for($p=0;$p -lt $specific_cert_path.Count;$p++)
    {
	   if($specific_cert_name[$p] -match $present_purpose_cert[$p])
       {
			$password =  ConvertTo-SecureString -AsPlainText -String $purpose_cert_password_obtained[$p] -Force
            $cert_file = Get-PfxData -FilePath $specific_cert_path[$p] -Password $password
            $cert_thumbprint_available=$cert_file.EndEntityCertificates.Thumbprint
	        if(Test-Path -Path Cert:\LocalMachine\My\$cert_thumbprint_available)
	        {
		       "$($specific_cert_name[$p]) is already imported in the server." >> $log
	        }
	        else
	        {
			  if($external_entity_cert -and $root_cert)
			  {
			    "External Entity and Root certificates are already available in the server. " >> $log
			  }
			  else
			  {
			     $enm_pki_cert = $specific_cert_dir+(Get-ChildItem $specific_cert_dir | Where-Object {$_.name -match "ENM_External*"})
                 $enm_pki_root_cert  = $specific_cert_dir+(Get-ChildItem $specific_cert_dir | Where-Object {$_.name -match "ENM_PKI*"})
				 if($enm_pki_cert -and $enm_pki_root_cert)
				 {
			       $certificate_CA = Import-Certificate -FilePath $enm_pki_cert  -CertStoreLocation 'Cert:\LocalMachine\CA'
                   $certificate_root = Import-Certificate -FilePath $enm_pki_root_cert  -CertStoreLocation 'Cert:\LocalMachine\Root'
				 }
				 else
				 {
				    "The external entity and root certificates are not available in $($specific_cert_dir) path. " >> $log
					DeleteTempFile
					DeleteTask
					ErrorHandle "The external entity and root certificates are not available in $($specific_cert_dir) path. Check $($log_file) file for more details. Press enter to exit code:"
				 }
			  }
		       "Importing $($specific_cert_name[$p]) certificate in IIS.." >> $log
		       Write-Host "Importing $($specific_cert_name[$p]) certificate.." 
               try 
	           {
                   $Flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet `
                        -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
                   $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($specific_cert_path[$p],$purpose_cert_password_obtained[$p], $Flags)
                   $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                   [System.Security.Cryptography.X509Certificates.StoreName]::My, 
                   [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                   $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                   $Store.Add($pfx)
                   $Store.Close()
		           $certificate_thumbprint = $pfx.Thumbprint
                   $certificate_personal_thumbprint+=$pfx.Thumbprint
	           }
	           catch 
               {   
                  $_ >> $log
				  DeleteTempFile
		          DeleteNewTask
		          ErrorHandle "Error found while importing a certificate. Check $($log_file) file for more details. Press enter to exit code:"
               }
               Test-Certificate "Cert:\LocalMachine\My\$certificate_thumbprint"  >>$log
               if($?)
	           {
                  "Personal certificate $($specific_cert_name[$p]) is validated successfully." >>$log
				   Write-Host "Personal certificate $($specific_cert_name[$p]) is validated successfully."
               }
	           else
               {
			       $_ >> $log
				   DeleteTempFile
				   DeleteNewTask
		           ErrorHandle "Error found in personal certificate. Check $($log_file) file for more details. Press enter to exit code:"
               }
            }    
	   }
	   else
	   {
		 continue
	   }
    }
  }
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while importing new certificates. Check $($log_file) file for more details. Press enter to exit code:"
}
  return $certificate_personal_thumbprint
}

#----------------------------------------------------------------------------------------------------------------
# Function to replace the CA signed certificate to self signed certicate for Remote Desktop Services feature 
#----------------------------------------------------------------------------------------------------------------
Function ReplaceCACertRDP()
{
try
{
	PrintDateTime
	Write-Host "Replacing new purpose specific certificate for RDP feature started.."
    "Replacing new purpose specific certificate for RDP feature started.." >> $log
	$rdp_cert = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -match $cert_name_RDP})
    if($rdp_cert.Thumbprint)
   { 
	   if($rdp_thumbprint -match $rdp_cert.Thumbprint)
	   {
		 "A CA signed certificate($cert_Name_RDP) is available in the server for RDP feature." >> $log
		 Write-Host "A CA signed certificate($cert_Name_RDP) is available in the server for RDP feature." 
	   }
	   else
	   {
	       $new_thumbprint = $rdp_cert.Thumbprint
		   wmic /namespace:\\root\cimv2\TerminalServices PATH Win32_TSGeneralsetting set SSLCertificateSHA1Hash="$new_thumbprint"
           "Replacing the certificate($cert_Name_RDP) for RDP feature completed successfully.System will restart now." >> $log
	       TaskCreation
	       shutdown -r
		   EXIT(1)
	   }
   }
   else
   {
       "Purpose specific CA signed certificate($cert_Name_RDP) is unavailable in the expected path for RDP feature ." >> $log
	   Write-Host "Purpose specific CA signed certificate($cert_Name_RDP) is unavailable in the expected path for RDP feature."
   }
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while replacing RDP cert. Check $($log_file) file for more details. Press enter to exit code:"
}
}

#----------------------------------------------------------------------
# Function to replace the CA signed certificate for SSO feature 
#----------------------------------------------------------------------
Function CACertSSO()
{
try
{
	PrintDateTime
	Write-Host "Replace purpose specific certificate for SSO feature.." 
	"Replace purpose specific certificate for SSO feature.." >> $log
   $thumbprint_SSO = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -match $cert_name_SSO}).Thumbprint
   if($thumbprint_SSO)
   {
      $test_sso_cert="Registry::"+"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates\"+$thumbprint_SSO
		if(!(Test-Path -path $test_sso_cert))
		{
		  if(Test-Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\PSLogon_SSO.bat")
          {
		    Write-Host "Certificate_replace.ps1 script is running to replace self signed certificate with purpose specific CA signed certificates.."
			sleep -seconds 100
			   $log_file_dir = "C:\ENM-SSO\Selfsigned_remove\log\"
			   $log_file_SSO = Get-ChildItem -Path $log_file_dir | Sort-Object LastAccessTime -Descending | Select-Object -First 1
               if($log_file_SSO)
               {
                 if((Get-Content $log_file_SSO -Tail 1) -like '*Logon script deleted successfully.')
	             {
	                 "Purpose specific CA signed certificate($cert_name_SSO) is available in the expected path  for SSO feature." >> $log
	                 Write-Host "Purpose specific CA signed certificate($cert_name_SSO) is available in the expected path for SSO feature."
	             }
	             else
	             {
	                "Error found in running Certificate_replace.ps1 script." >> $log
					DeleteTempFile
					DeleteNewTask
	                 ErrorHandle "Error found in running Certificate_replace.ps1 script. Check $($log_file) file for more details. Press enter to exit code:"
	             }
               }
               else
               {
                    "Log file not available for Certificate_replace script." >> $log
					Write-Host "Latest log file not available for Certificate_replace script."
               }
		  }	
		  elseif($common_SSO_CA_cert)
		  {
             ReplaceFolders
			 TaskCreation
             try
	         {
			   Write-Host "SSO_CA.ps1 script will start executing ............"
			   Set-ExecutionPolicy unrestricted
		       Invoke-Expression "C:\ENM-SSO\SSO_CA.ps1" >> $log
			   sleep -seconds 100
	         }
	         catch
	         {
		       "$_" >>$log
			   DeleteTempFile
		       DeleteNewTask
			   ErrorHandle "Error found in running SSO_CA.ps1 script. Check $($log_file) file for more details. Press enter to exit code:"
	         }
          }
          elseif($common_SSO_SS_cert)
          {
		     ReplaceFolders
			 TaskCreation
             try
	         {
			   Write-Host "Certificate_replace.ps1 script will start executing ............"
		       Invoke-Expression "C:\ENM-SSO\Selfsigned_remove\Certificate_replace.ps1" >> $log
	         }
	         catch
	         {
			   "$_" >>$log
			   DeleteTempFile
		       DeleteNewTask
			   ErrorHandle "Error found in running Certificate_replace.ps1 script. Check $($log_file) file for more details. Press enter to exit code:"
	         }
		  }
          else
          {
		    "No certificate is available for SSO feature in Cert:\LocalMachine\My path. Make the certificate available and rerun the script." >>$log
            DeleteTempFile
            DeleteNewTask
            ErrorHandle "No certificate is available for SSO feature in Cert:\LocalMachine\My path. Check $($log_file) file for more details. Press enter to exit code:"
		  }		  
		}
		else
		{  
           "Purpose specific CA signed certificate($cert_name_SSO) is available in the expected path  for SSO feature." >> $log
	       Write-Host "Purpose specific CA signed certificate($cert_name_SSO) is available in the expected path for SSO feature."
		}
   }
   else
   {
      "Purpose specific CA signed certificate($cert_name_SSO) is unavailable in the expected path  for SSO feature." >> $log
	   Write-Host "Purpose specific CA signed certificate($cert_name_SSO) is unavailable in the expected path for SSO feature."
   }
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while replacing sso cert. Check $($log_file) file for more details. Press enter to exit code:"
}
}

#----------------------------------------------------------------------
# Function to replace the CA signed certificate for Citrix License feature 
#----------------------------------------------------------------------
Function CACertLicense()
{
try
{
  PrintDateTime
  "Replacing the self signed certificates with purpose specific certificates for Citrix License feature has started.." >>$log
  Write-Host "Replacing the self signed certificates with purpose specific certificates for Citrix License feature has started.."
  [string[]]$cert_present,[string[]]$license_cert_thumbprint = @()
  [string[]]$certificate_filepath = @("C:\Program Files (x86)\Citrix\Licensing\LS\conf\","C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\")
     # Find the certificates present in the expected path
	 for($h=0;$h -lt $certificate_filepath.Count;$h++)
	 {
	   $certificate = Get-ChildItem -Path $certificate_filepath[$h]  | where {$_.Name -like "server.crt"} | Import-Certificate -CertStoreLocation Cert:\LocalMachine\My
	   if(($certificate.GetName()) -match ("CN="+$certname))
	   {
	     if(($certificate.GetIssuerName()) -match "CN=ENM_External_Entity_CA")
		 {
		    $cert_present += "common_ca-signed"
		 }
		 else
		 {
		    $cert_present += "self-signed"
			$license_cert_thumbprint  += $certificate.Thumbprint
		 }
	   }
	   else
	   {
	     $cert_present += "purpose_specific_ca-signed"
		 $license_cert_thumbprint  += $certificate.Thumbprint
	   }
	 }
	 #Remove the certificates if imported in the server
	 for($g=0;$g -lt $license_cert_thumbprint.Count;$g++)
	 { 
	   if(Test-Path -Path Cert:\LocalMachine\My\$($license_cert_thumbprint[$g]))
	   {
	     Remove-Item Cert:\LocalMachine\My\$($license_cert_thumbprint[$g]) 
	   }
	   else
	   {
	     "No certificate needs to be removed from the server. " >> $log
	   }
	 }
	 # Replace the self signed certificates with new CA signed certificates if applicable
	 if(((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "purpose_specific_ca-signed"}).Count -eq 2)
	 {
	    $global:available_certificate += "purpose_specific_ca-signed" 
	    "Expected purpose specific certificates are already available in the server for Citrix licence feature. " >>$log
		Write-Host "Expected purpose specific certificates are already available in the server for Citrix licence feature. "
	 }
	 elseif(((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "self-signed"}).Count -eq 2)
	 {
		  for($i=0;$i -lt $certificate_filepath.Count;$i++)
		  {
		     Copy-Item  -Path "C:\Certificates\purpose_specific_certificates\server.crt" -Destination $certificate_filepath[$i] -Recurse -force
		     Copy-Item  -Path "C:\Certificates\purpose_specific_certificates\server.key" -Destination $certificate_filepath[$i] -Recurse -force
		  }
		  Get-Service -Name "Citrix Licensing"  | Restart-Service -WarningAction Ignore
		  Get-Service -Name "Citrix Web Services for Licensing"  | Restart-Service -WarningAction Ignore
		  "Replacing CA signed certificates in place of self signed certificate for citrix license feature completed successfully. " >>$log
	      Write-Host "Replacing CA signed certificates in place of self signed certificate for citrix license feature completed successfully. "
	      $global:available_certificate += "purpose_specific_ca-signed"
	 }
	 elseif(((0..($cert_present.Count-1)) | Where {$cert_present[$_] -match "common_ca-signed"}).Count -eq 2)
	 { 
	    $global:available_certificate += "common_ca-signed"
	    "CA signed certificates are available in expected paths hence replacing cerificates is not possible. " >> $log
		DeleteTempFile
        DeleteNewTask
		ErrorHandle "CA signed certificates are available in expected paths hence replacing cerificates is not possible. Check $($log_file) file for more details. Press enter to exit code:"
	 }
	 else
	 {
	    $global:available_certificate += $cert_present
	    "Certificates present in C:\Program Files (x86)\Citrix\Licensing\LS\conf\ path are not similar to the certificates in C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\ path. Place same certificates in both paths." >> $log		
	    DeleteTempFile
        DeleteNewTask
        ErrorHandle "Certificates present in C:\Program Files (x86)\Citrix\Licensing\LS\conf\ path are not similar to the certificates in C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\ path. Place same certificates in both paths. Check $($log_file) file for more details. Press enter to exit code:"
	 }
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while replacing license certs. Check $($log_file) file for more details. Press enter to exit code:"
}
  return $global:available_certificate
}

#----------------------------------------------------------------------
# Function to replace the CA signed certificate for TLS feature 
#----------------------------------------------------------------------
Function CACertTLS()
{
try
{
    PrintDateTime
	"Replacing the purpose specific certificates for TLS feature has started.." >>$log
  Write-Host "Replacing the purpose specific certificates for TLS feature has started.."
	if(Get-ChildItem -Path $specific_cert_dir | Where-Object {$_.Name -match "$cert_name_TLS*"})
    {	
	     if($tls_cert_available.Thumbprint -match $tls_thumbprint)
		 {
		     Write-Host "TLS script executed successfully."
		     "TLS script executed successfully.">> $log
			  if(((Get-ChildItem C:\OCS\install_config\TLS1.2_VDA_config\Counter.txt).IsReadOnly) -and ((Get-ChildItem C:\OCS\install_config\TLS1.2_VDA_config\PsLogon.bat).IsReadOnly))
              {
			    "Expected files are available at expected type." >> $log
			  }
			  else
			  {
			    (Get-ChildItem  C:\OCS\install_config\TLS1.2_VDA_config\Counter.txt).Set_IsReadOnly($True)
			    (Get-ChildItem  C:\OCS\install_config\TLS1.2_VDA_config\PsLogon.bat).Set_IsReadOnly($True)
			  }
		      "A CA signed certificate($cert_Name_tls) is available in the server for TLS feature." >> $log
		      Write-Host "A CA signed certificate($cert_Name_TLS) is available in the server for TLS feature."   
		 }
	     else
	     {
	      try
	      {
		     ReplaceFolders
		     TaskCreation
			 Write-Host "TLS1.2_VDA_configuration.ps1 will start executing......................"
		     $tlsscript_status = Invoke-Expression "$tlsscript" 
             sleep -seconds 100
             if(!$tlsscript_status)
             {
		       "$_" >> $log
			   DeleteTempFile
		       DeleteNewTask
		       ErrorHandle "Error found in running TLS1.2_VDA_configuration.ps1 script.Check $($log_file) file for more details. Press enter to exit code:"
		     }		   
	      }
	      catch
	      {
		    "$_" >>$log
		    Write-Host "Error found in running TLS1.2_VDA_configuration.ps1 script.Check $($log_file) file for more details."
	      }
         }		
	}
	else
    {
	  if($purpose_specific_TLS_CA_cert)
	  {
	    "A CA signed certificate($cert_name_TLS) is available in the server for TLS feature." >> $log
		Write-Host "A CA signed certificate($cert_name_TLS) is available in the server for TLS feature." 
	  }
	  else
	  {
      "Purpose specific CA signed certificate($cert_name_TLS) is unavailable in the expected path  for TLS feature." >> $log
	   Write-Host "Purpose specific CA signed certificate($cert_name_TLS) is unavailable in the expected path for TLS feature."
	  }
    }
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while replacing TLS cert. Check $($log_file) file for more details. Press enter to exit code:"
}
}

Function CheckRDPCert()
{
try
{
      if($rdp_thumbprint -match $rdp_cert.Thumbprint)
 	  {
	    $rdp_cert_found = 1
      }
      else
      {
	    $rdp_cert_found = 0
      }
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while checking purpose specific rdp cert is present or not. Check $($log_file) file for more details. Press enter to exit code:"
}
	  return $rdp_cert_found
}

Function CheckSSOCert()
{
try
{
	  if($sso_cert.Thumbprint)
      {
	    $sso_cert_found = 1
      }
	  else
	  {
	    $sso_cert_found = 0
      }
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while checking purpose specific sso cert is present or not. Check $($log_file) file for more details. Press enter to exit code:"
}
	  return $sso_cert_found
}

Function CheckTLSCert()
{
try
{
      if($tls_cert_available.Thumbprint -match $tls_thumbprint)
	  {
	    $tls_cert_found = 1
	  }
	  else
	  {
	    $tls_cert_found = 0
	  }
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while checking purpose specific tls cert is present or not. Check $($log_file) file for more details. Press enter to exit code:"
}
	  return $tls_cert_found
}

#----------------------------------------------------------------------
# Function to perform the certificate procedure according to server 
#----------------------------------------------------------------------
Function DistinctServerCerts()
{
	if($global:ADServer -match $True)
	{
	    #Replace the purpose specific certificate for SSO
	       CACertSSO
    }
	elseif($global:CCSServer -match $True)
    {
	    #Replace the purpose specific certificate for Citrix license
	       $global:available_certificate = CACertLicense
    }
	elseif($global:VDAServer -match $True)
	{
	    #Replace the purpose specific certificate for TLS feature
		  CACertTLS
	}
}

Function ReplaceNewCerts ()
{	
	 #Import the generated certificates in the specified path
	   $certificate_personal_thumbprint = ImportNewCACert
		 
     #Replace the self signed certificate to CA signed certificates for RDP
	   ReplaceCACertRDP
		 
	   DistinctServerCerts
}

Function RemoveOldCertsAndReplace()
{
    if((Test-Path -path "$($specific_cert_dir)server.crt") -and (Test-path -path "$($specific_cert_dir)server.key"))
	{
	   $expected_path_certs = RollbackOfLicenseCert
	}
	RemoveCASignedCert
	ReplaceNewCerts
}

#----------------------------------------------------------------------
# Function to print summary of certificates present in the server 
#----------------------------------------------------------------------
Function PrintCertificateSummary
{
  [string[]]$array=@()
   $CA_signed_Certificate,$Self_signed_Certificate,$cert_thumbprint,$days,$certificates_name,$cert_present,$days_toexpire = GetCertificateDetails
  $certificate_type,$common_RDP_CA_cert,$common_SSO_RDP_CA_cert,$common_SSO_CA_cert,$common_SSO_SS_cert,$common_HTTPS_RDP_CA_cert,$HTTPS_CA_cert,$common_TLS_RDP_CA_cert,$common_TLS_CA_cert,$purpose_specific_SSO_CA_cert,$purpose_specific_RDP_CA_cert,$purpose_specific_TLS_CA_cert = getCertificateType
  [string[]]$array_new = @($common_RDP_CA_cert,$common_SSO_RDP_CA_cert,$common_SSO_CA_cert,$common_SSO_SS_cert,$common_HTTPS_RDP_CA_cert,$HTTPS_CA_cert,$common_TLS_RDP_CA_cert,$common_TLS_CA_cert,$purpose_specific_SSO_CA_cert,$purpose_specific_RDP_CA_cert,$purpose_specific_TLS_CA_cert,$global:available_certificate)
try
{  
  for($j=0;$j -lt $array_new.Count;$j++)
  {
    if($array_new[$j])
	{
	  $array += $array_new[$j]
	}
	else
	{
	   continue
	}
  }
  #Print summary of certificates in respect to server
  if($global:ADServer -match $True)
  {
    foreach($array_element in $array)
	{
     if($common_RDP_CA_cert -match $array_element)
	 {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$certname"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "RDP feature"
		$script:output_table += $script:output_obj
	 }
	 elseif($common_SSO_CA_cert -match $array_element)
	 {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$certname"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "SSO feature"
		$script:output_table += $script:output_obj
	 }
	 elseif($common_SSO_SS_cert -match $array_element)
	 {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$certname"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "SSO feature"
		$script:output_table += $script:output_obj
	 }
	 elseif($common_SSO_RDP_CA_cert -match $array_element)
	 {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$certname"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "SSO And RDP feature"
		$script:output_table += $script:output_obj
	 }
	 elseif($purpose_specific_RDP_CA_cert -match $array_element)
	 {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$cert_name_RDP"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "RDP feature"
		$script:output_table += $script:output_obj
	 }
	 elseif($purpose_specific_SSO_CA_cert -match $array_element)
	 {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$cert_name_SSO"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "SSO feature"
		$script:output_table += $script:output_obj
	 }
	 else
	 {
	    continue
	 }
	}
  }
  elseif($global:CCSServer -match $True)
  {
	foreach($array_element in $array)
	{
	  if($common_HTTPS_RDP_CA_cert -match $array_element)
	  {  
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$certname"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "HTTP and RDP feature"
	    $script:output_table += $script:output_obj
	  }
	  elseif($HTTPS_CA_cert -match  $array_element)
	  {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$certname"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "HTTPS feature"
	    $script:output_table += $script:output_obj
	  }
	  elseif($common_RDP_CA_cert -match $array_element)
	  {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$certname"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "RDP feature"
		$script:output_table += $script:output_obj
	  }
	  elseif($purpose_specific_RDP_CA_cert -match $array_element)
	  {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$cert_name_RDP"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "RDP feature"
	    $script:output_table += $script:output_obj
	  }
	  elseif($global:available_certificate -match $array_element)
	  {
	    if($global:available_certificate.Count -eq 2)
		{
	     if(((0..($global:available_certificate.Count-1)) | Where {$global:available_certificate[$_] -match "purpose_specific_ca-signed"}).Count -eq 2)
		 {
		    PrintActionAndResetVariables
		     $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "Server.crt(Purpose specific CA signed certificate)"
             $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "Citrix License feature"
		     $script:output_table += $script:output_obj
		 }
		 elseif(((0..($global:available_certificate.Count-1)) | Where {$global:available_certificate[$_] -match "common_ca-signed"}).Count -eq 2)
		 {
		     PrintActionAndResetVariables
		     $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "Server.crt(Common CA signed certificate)"
             $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "Citrix License feature"
		     $script:output_table += $script:output_obj
		 }
		 elseif(((0..($global:available_certificate.Count-1)) | Where {$global:available_certificate[$_] -match "self-signed"}).Count -eq 2)
		 {
		     PrintActionAndResetVariables
		     $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "Server.crt(Self signed certificate)"
             $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "Citrix License feature"
		     $script:output_table += $script:output_obj
		 }
		}
        else
        {
		  if($global:available_certificate -match "purpose_specific_ca-signed")
		  {
		     PrintActionAndResetVariables
		     $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "Server.crt(Purpose specific CA signed certificate)"
             $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "Citrix License feature"
		     $script:output_table += $script:output_obj
		  }
		  elseif($global:available_certificate -match "common_ca-signed")
		  {
		     PrintActionAndResetVariables
		     $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "Server.crt(Purpose specific CA signed certificate)"
             $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "Citrix License feature"
		     $script:output_table += $script:output_obj
		  }
		  else
		  {
		    continue
		  }
		}		
	  }
	  else
	  {
	    continue 
	  }
	}
  }
  else
  {
    foreach($array_element in $array)
	{
     if($common_RDP_CA_cert -match $array_element)
	 {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$certname"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "RDP feature"
		$script:output_table += $script:output_obj
	 }
	 elseif($common_TLS_CA_cert -match $array_element)
	 {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$certname"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "TLS feature"
		$script:output_table += $script:output_obj
	 }
	 elseif($common_TLS_RDP_CA_cert -match $array_element)
	 {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$certname"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "TLS And RDP feature"
		$script:output_table += $script:output_obj
	 }
	 elseif($purpose_specific_RDP_CA_cert -match $array_element)
	 {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$cert_name_RDP"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "RDP feature"
		$script:output_table += $script:output_obj
	 }
	 elseif($purpose_specific_TLS_CA_cert -match $array_element)
	 {
	    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Certificate Name" -value "$cert_name_TLS"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Purpose" -value "TLS feature"
		$script:output_table += $script:output_obj
	 }
	 else
	 {
	    continue
	 }
	}
  }
  #Adding the status of enabling certificate-expiry feature in the server
  if($status)
  {
    PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Task" -value "Enabling Certificate-Expiry"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Successful"
		$script:output_table += $script:output_obj
  }
  PrintActionAndResetVariables
	    $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Task" -value "Enabling Certificate-Expiry"
        $script:output_obj | Add-Member -type NoteProperty -ErrorAction SilentlyContinue -name "Status" -value "Failed"
		$script:output_table += $script:output_obj
  $output_table | Format-Table -Wrap -AutoSize
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while printing certificate summary. Check $($log_file) file for more details. Press enter to exit code:"
}
}

#----------------------------------------------------------------------
# Function to create a task in task scheduler 
#----------------------------------------------------------------------
Function TaskCreation
{
	$task_found = 0
	try
	{
		$schedule = new-object -com("Schedule.Service")
        $schedule.connect()
        $tasks = $schedule.getfolder("\").gettasks(0)
        foreach ($t in $tasks)
		{ 
		   $taskName=$t.Name
            if(($taskName -eq $global:login_taskname))
			{
				$task_found =1
			}
			else
			{
				continue
			}
		}
		#Schedule the task if not scheduled already
        if($task_found -eq 0)
		{
	        $argument = "ImportMultipleCert"
            $testAction = New-ScheduledTaskAction  -Execute 'powershell.exe' -Argument '-windowstyle Maximized  C:\Distinct_certificates\distinct_cert_configuration.ps1 ImportMultipleCert'
		    $testTrigger = New-ScheduledTaskTrigger -AtLogon
	    	$testSettings = New-ScheduledTaskSettingsSet -Compatibility Win8 
	    	Register-ScheduledTask -TaskName $global:login_taskname -Action $testAction -Trigger $testTrigger -Settings $testSettings 
	    	"Task has been created successfully." >>$log
		}
		else
		{
			"Task already exists in the server." >> $log
		}
    }
	catch
	{
		$_ >>$log
		"`nException in TaskCreation function" >>$log
		$time = get-date -Format "yyyy MM dd HH:mm:ss"
		DeleteTempFile
		DeleteNewTask
        ErrorHandle "`n$time : [ERROR] Check $($log_file) file for more details. Press enter to exit code:"
	}
}

#-------------------------------------------------------------------------
# Function to delete a new task in task scheduler 
#-------------------------------------------------------------------------
Function DeleteNewTask
{
	 PrintDateTime
	"`n Deleting new Task from Task Scheduler  " >>$log
	try
	{
		$schedule = new-object -com("Schedule.Service")
        $schedule.connect()
        $tasks = $schedule.getfolder("\").gettasks(0)
        foreach ($t in $tasks)
		{
            $taskName=$t.Name
            if(($taskName -eq $global:login_taskname))
			{
				 "Task exist, hence deleting it." >> $log
				schtasks /delete /tn $global:login_taskname /f >> $log
            }
			else
			{
				continue
			}
        }		
	}
	catch
	{
		$_ >>$log
		"`nException in DeleteNewTask function" >>$log
		$time = get-date -Format "yyyy MM dd HH:mm:ss"
		DeleteTempFile
		DeleteNewTask
		ErrorHandle "`n$time : [ERROR] Check $($log_file) file for more details. Press enter to exit code:"
	}
}

#-------------------------------------------------------------------------
# Function to delete a Certificate-Expiry related task in task scheduler 
#-------------------------------------------------------------------------
Function DeleteTask
{
	 PrintDateTime
	"`n Deleting Task from Task Scheduler  " >>$log
	try
	{
		$schedule = new-object -com("Schedule.Service")
        $schedule.connect()
        $tasks = $schedule.getfolder("\").gettasks(0)
        foreach ($t in $tasks)
		{
            $taskName=$t.Name
            if($taskName -eq "Certificate_Expiry_Check")
			{
			     "Task exist, hence deleting it." >> $log
				schtasks /delete /tn "Certificate_Expiry_Check" /f >> $log
			}
			elseif($taskName -eq "Certificate_Expiry_Notification")
			{
			     "Task exist, hence deleting it." >> $log
				schtasks /delete /tn "Certificate_Expiry_Notification" /f >> $log
			}
            else
			{
				continue
			}
        }		
	}
	catch
	{
		$_ >>$log
		"`nException in DeleteTask function" >>$log
		$time = get-date -Format "yyyy MM dd HH:mm:ss"
		DeleteTempFile
		DeleteNewTask
		ErrorHandle "`n$time : Error occured while deleting tasks regarding certificate-expiry. Check $($log_file) file for more details. Press enter to exit code:"
	}
}

#----------------------------------------------------------------------
# Function to enable certificate expiry scripts
#----------------------------------------------------------------------
Function EnableCertificateExpiryScript()
{
try
{
   PrintDateTime
   $CertificateExpiryStatus = "Failed"
    if(Test-Path -path "C:\Certificate-expiry")
	{
	   Get-ChildItem -Path "C:\Certificate-expiry" -Recurse | Foreach-object {Remove-item -Force -Recurse -path $_.FullName }
	   "Certificate-expiry folder is removed from the server. " >> $log
	}
	else
	{
	   "Certificate-expiry folder is not available in the server. " >> $log
	}
	   if(Test-Path -Path ($script:WHDriveLetter+"Certificate-expiry"))
	   {
	       $SourceDirectory = $script:WHDriveLetter+"Certificate-expiry"
           $DestinationDirectory = "C:\"
           Copy-Item -path $SourceDirectory -destination $DestinationDirectory -Recurse -Force
	       if(Test-path -Path ($DestinationDirectory+"Certificate-expiry"))
           {
              "Certificate-expiry folder copied successfully" >> $log
	          "Enabling Certificate-expiry scripts " >> $log
		      $CertificateExpiryStatus = Invoke-Expression "$CertificateExpiryScript"
	          "`n Enable Certificate-expiry Status $CertificateExpiryStatus">> $log
	          Write-Host "`n Enable Certificate-expiry Status $CertificateExpiryStatus"
			  return $true
           }
		   else
		   {
		      "Copying Certificate-expiry folder failed." >> $log   
              return $false			  
		   }
	    }
	   else
	   {
		 "Certificate-expiry folder is not available in Windows Hardening Media. " >> $log
		 return $false
	   }
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while enabling certificate-expiry script. Check $($log_file) file for more details. Press enter to exit code:"
}
}

#Main Function

$TimeStamp = Get-Date -Format yyyy-MM-dd_HH_mm_ss
$global:ADServer = "False"
$global:CCSServer = "False"
$global:VDAServer = "False"
$global:login_taskname = "ImportCertificatesandReplace"
$global:available_certificate = @()
$log_dir= "C:\Distinct_certificates\log"
$log_file= "C:\Distinct_certificates\log\cert_configuration.log"
$WindowsMedia = "C:\Windows_Hardening\WINDOWS_HARDENING.iso"
$OCSMedia = "C:\OCS\OCS_Automation_Package_Media.iso"
$VDAWindowsMedia = "C:\ebid\ebid_medias\WINDOWS_HARDENING.iso"
$tlsscript = "C:\OCS\install_config\TLS1.2_VDA_config\TLS1.2_VDA_configuration.ps1"
$CertificateExpiryScript = "C:\Certificate-expiry\Schedule_task.ps1"
[string[]]$certificate_filepath = @("C:\Program Files (x86)\Citrix\Licensing\LS\conf\","C:\Program Files (x86)\Citrix\Licensing\WebServicesForLicensing\Apache\conf\")
$script:output_table = @()
[string[]]$cert_path,[string[]]$specific_cert_path=@()
[string[]]$cert_thumbprint_available=@()
[string[]]$certificate_personal_thumbprint=@()
$purpose_specific_rdp_cert_found,$purpose_specific_sso_cert_found,$purpose_specific_tls_cert_found,$no_purpose_specific_cert_found =0
$certname = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
$cert_name_RDP = (Get-WmiObject win32_computersystem).DNSHostName+"_RDP"
$cert_name_SSO = (Get-WmiObject win32_computersystem).DNSHostName+"_SSO"
$cert_name_TLS = (Get-WmiObject win32_computersystem).DNSHostName+"_TLS"
$external_entity_cert = Get-ChildItem -Path Cert:\LocalMachine\CA | Where-Object {$_.Subject -match "ENM_External_Entity_CA"}
$root_cert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -match "ENM_PKI_Root"}
$rdp_cert = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -match $cert_name_RDP})
$sso_cert = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -match $cert_name_SSO})
$tls_cert_available = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -match $cert_name_TLS})

Write-Host "Started checking for purpose specific certificates in the server....Dont close the window. "
#Get details of CA signed RDP certificate if present
try
{
if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name SSLCertificateSHA1Hash -ErrorAction Ignore)
{
  $rdp_cert_value = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name SSLCertificateSHA1Hash -ErrorAction SilentlyContinue
  $rdp_thumbprint =  ($rdp_cert_value | Format-Hex | Select-Object -Expand Bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ''
}
else
{
  $rdp_thumbprint = $null
}
}
catch
{
   "$_" >>$log
   DeleteTempFile
   DeleteNewTask
   ErrorHandle "Error occured while getting current server rdp certificate. Check $($log_file) file for more details. Press enter to exit code:"
}

if(Test-Path $log_dir)
{    
    if(!(Test-Path $log_file))
	{
		try
		{
		  $log = New-Item -ItemType File -Path $log_dir -Name cert_configuration.log
         PrintDateTime
         "New log file created in $($log_dir) directory." >>$log
		}
        catch
        {
		  ErrorHandle "Error occured while creating the log file $($log_file). Press enter to exit code:"
        }
	}
    else
	{
		$log = "C:\Distinct_certificates\log\cert_configuration.log"
		PrintDateTime
		"Log file is already created in $($log_dir) directory." >>$log
	}
}
else
{    
    try
	{
      New-Item -Path $log_dir -ItemType Directory | Out-Null
	  $log = New-Item -ItemType File -Path $log_dir -Name cert_configuration.log
      PrintDateTime
      "New log file created in $($log_dir) directory." >>$log
    }
	catch
    {
	    "$_" >> $log
        ErrorHandle "Error occured while creating the log file $($log_file). Press enter to exit code:"
    }
}

try
{
$server_status = CheckServer
"Server status $server_status" >> $log
if($server_status)
{
	 #Import module for finding Web App certificate
	 if ($global:CCSServer -match $True) 
	 {
      try
      {
       Import-Module -Name WebAdministration
      }
      catch
      {
        $errorMessage = $_.Exception.Message
	    $errorMessage >> $debuglog
        $_ >>$debuglog
        Write-Host "Error occured while importing a module"
        EXIT(1)
      }
	 }
	 elseif($global:VDAServer -match $True)
	 {
	    #Get details of CA signed TLS certificate if present
        if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name SSLCertificateSHA1Hash -ErrorAction Ignore)
        {
          $tlscert_temp = Get-ItemPropertyValue -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd" -Name "SSLThumbprint"
          $tls_thumbprint = ($tlscert_temp | Format-Hex | Select-Object -Expand Bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ''		  
        }
        else
        {
          $tls_thumbprint = $null
        }   
	 }
	  
	  $script:WHDriveLetter = CheckMedia

	  #Get the current certificate details in server
	  $CA_signed_Certificate,$Self_signed_Certificate,$cert_thumbprint,$days,$certificates_name,$cert_present,$days_toexpire = GetCertificateDetails 
	 	 
	  #Getting type of certificates present in the server
	  $certificate_type,$common_RDP_CA_cert,$common_SSO_RDP_CA_cert,$common_SSO_CA_cert,$common_SSO_SS_cert,$common_HTTPS_RDP_CA_cert,$HTTPS_CA_cert,$common_TLS_RDP_CA_cert,$common_TLS_CA_cert,$purpose_specific_SSO_CA_cert,$purpose_specific_RDP_CA_cert,$purpose_specific_TLS_CA_cert = GetCertificateType
      
	  PrintDateTime
	  #Get common certificates present in the server
      $cert_dir = "C:\Certificates\"
      if(Test-Path $cert_dir)
      {
	   [string[]]$cert_name = (Get-ChildItem $cert_dir | Where-Object {$_.name -like "*.p12"}).name
       if($cert_name)
       {
         for($l=0;$l -lt $cert_name.Count;$l++)
         {
            $cert_path += $cert_dir + $cert_name[$l]
         }
       }
       else
       {
	     "Expected certificates of .p12 format is not available in the server." >> $log
       }
      }
      else
      {
         "Expected path[C:\Certificates] is not available in the server." >> $log
      }
     #Get purpose specific certificates present in the server
     $specific_cert_dir = "C:\Certificates\purpose_specific_certificates\"
     if(Test-Path $specific_cert_dir)
     {
	    $format = (Get-WmiObject win32_computersystem).DNSHostName
		[string[]]$specific_cert_name = @()
	    [string[]]$specific_cert_array = (Get-ChildItem $specific_cert_dir | Where-Object {$_.name -like "*.p12"}).name
		for($m=0;$m -lt $specific_cert_array.Count;$m++)
		{
		   if($specific_cert_array[$m] -match "$format*")
		   {
		     $specific_cert_name += $specific_cert_array[$m]
		   } 
		}
		$license_cert_present = (Get-ChildItem $specific_cert_dir | Where-Object {$_.name -match "server.crt"}).name
        if($specific_cert_name -or $license_cert_present)
        {
          for($l=0;$l -lt $specific_cert_name.Count;$l++)
          {
			#To get details of  the purpose specific certificates present in the path C:\Certificates\purpose_specific_certificates\
			 if($global:ADServer -match $true)
			 {
				if($specific_cert_name[$l] -match "$cert_Name_RDP*")
		        {
					$purpose_specific_rdp_cert_found = 1
					$specific_cert_path += $specific_cert_dir + $specific_cert_name[$l]
			    }
			    elseif($specific_cert_name[$l] -match "$cert_Name_SSO*")
			    {
				    $purpose_specific_sso_cert_found = 1
					$specific_cert_path += $specific_cert_dir + $specific_cert_name[$l]
			    }
			    else
			    {
					$no_purpose_specific_cert_found = 1
			    }
		    }
			 elseif($global:CCSServer -match $true)
			 {
			    if($specific_cert_name[$l] -match "$cert_Name_RDP*")
		        {
					$purpose_specific_rdp_cert_found = 1
					$specific_cert_path += $specific_cert_dir + $specific_cert_name[$l]
			    }
			    else
			    {
					$no_purpose_specific_cert_found = 1
			    }
			}
			 else
			 {
			    if($specific_cert_name[$l] -match "$cert_Name_RDP*")
		        {
					$purpose_specific_rdp_cert_found = 1
					$specific_cert_path += $specific_cert_dir + $specific_cert_name[$l]
			    }
			    elseif($specific_cert_name[$l] -match "$cert_Name_TLS*")
			    {
				    $purpose_specific_tls_cert_found = 1
					$specific_cert_path += $specific_cert_dir + $specific_cert_name[$l]
			    }
			    else
			    {
					$no_purpose_specific_cert_found = 1
			    }
			}				  
         }
        }
        else
        {
	       "Expected certificates are not available in C:\Certificates\purpose_specific_certificates\ path." >> $log
			ErrorHandle "Expected certificates are not available in C:\Certificates\purpose_specific_certificates\ path. Check $($log_file) for current server details. Press enter to exit code:"
        }
     }
     else
     {
        "Expected path[C:\Certificates\purpose_specific_certificates] is not available in the server." >> $log
        [void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")
        [Microsoft.VisualBasic.Interaction]::MsgBox("Place the purpose specific certificates in the following path : C:\Certificates\purpose_specific_certificates and execute the script again!! Check $($log_file) for current server certificate's details.", "OKOnly,SystemModal,Information", "Success")
		EXIT(1)
     }
     
     $temp_file_common,$temp_file_purpose = GetCertPassword
     $present_common_cert,$common_cert_password_obtained,$present_purpose_cert,$purpose_cert_password_obtained = StorePassword
	 
	  if($args -eq "ImportMultipleCert")
	  {
          RemoveOldCertsAndReplace     
	  }
	  else
      {	  
	     if($certificate_type -match "common_cert") 
         {
	    	if(Test-Path -path "$specific_cert_dir$cert_name_RDP*")
	    	{
	           RollbackOfRDPCert
               RemoveOldCertsAndReplace
	        }
		    else
		    {
	       	   RemoveOldCertsAndReplace
		    }
	     }
	     elseif($certificate_type -match "purpose_specific_cert")
	     {
			$type=(0..($certificate_type.Count-1)) | where {$certificate_type[$_] -match "purpose_specific_cert"} 
			if($type.Count -eq 2)
			{
			    "The server has purpose specific certificates installed already." >> $log
	    	    Write-Host "The server has purpose specific certificates installed already."
			}
			else
			{
			   $rdp_cert_found = CheckRDPCert
			   if($global:ADServer -match $True)
			   {
			      $sso_cert_found = CheckSSOCert
			      if(($rdp_cert_found -eq 0) -and ($sso_cert_found -eq 1))
			      {
				     RollbackOfRDPCert
			      }
			      elseif(($sso_cert_found -eq 0) -and ($rdp_cert_found -eq 1))
			      {
				     RemoveOldCertsAndReplace 
			      }
			      else
			      {
				     "Not possible." >> $log
				     DeleteTempFile
					 DeleteNewTask
			      }
				}
			   elseif($global:CCSServer -match $True)
			   {
				  if($rdp_cert_found -eq 0)
				  {
				    RollbackOfRDPCert
				  }
				  else
				  {
				     RemoveOldCertsAndReplace
				  }
			   }
			   else
			   {
				  $tls_cert_found = CheckTLSCert
			      if(($rdp_cert_found -eq 0) -and ($tls_cert_found -eq 1))
			      {
				    if(!$rdp_thumbprint)
					{
					  RollbackOfRDPCert
					  RemoveOldCertsAndReplace
					}
					else
					{
				     RollbackOfRDPCert
					}
			      }
			      elseif(($tls_cert_found -eq 0) -and ($rdp_cert_found -eq 1))
			      {
				     RemoveOldCertsAndReplace 
			      }
			      else
			      {
				     "Not possible." >> $log
				     DeleteTempFile
					 DeleteNewTask
			      }
			   }
			}
	     }
	     else
	     {
	        ReplaceNewCerts		
	     }
	  } 
}
else
{
    DeleteTempFile
	"`n Unable to recognize server or Logged user is not administrator" >>$log
	Write-Host "`n Unable to recognize server or Logged user is not administrator" 
}
DeleteNewTask
DeleteTask
DeleteTempFile
$status = EnableCertificateExpiryScript
PrintCertificateSummary
[void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")
[Microsoft.VisualBasic.Interaction]::MsgBox("Process completed successfully. Check $($log_file) for further details.Click OK.", "OKOnly,SystemModal,Information", "Success")
"**************************************************************" >>$log
}
catch
{
   "$_" >> $log
   ErrorHandle "Error occured in the main function. Check $($log_file) for further details. Press Enter to exit code:"
}
	