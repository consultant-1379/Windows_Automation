
#   (c) Ericsson Radio Systems AB 2019 - All rights reserved.
#   The copyright to the computer program(s) herein is the property
#   The copyright to the computer program(s) herein is the property
# 	and/or copied only with the written permission from Ericsson Radio
# 	Systems AB or in accordance with the terms and conditions stipulated
# 	in the agreement/contract under which the program(s) have been
# 	supplied.
#
# **************************************************************************************
#	Name    : Certificate_expiry_check_NetAn.ps1
# 	Date    : 06/15/2023
# 	Purpose : This file is used to find the expiry date
#             of the certificates and log the required details 
#             in the log file.   	
#
# 	Usage   : Certificate_expiry_check_NetAn.ps1  find expiry date and log the information

# ********************************************************************************************************************************************
# ------------------------------------------------------   SUB  functions   ---------------------------------------------------------------
# ********************************************************************************************************************************************

# *****************************************************************************
#	To check the type of Server
# *****************************************************************************

 function check_ServerType()
 {
    if(Test-Path -Path "C:\Ericsson\NetAnServer\Server")
    {
		if(Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4*\config Manager")
		{	
			$NetAnServer = 2
		}
		else
		{
			$NetAnServer = 1
		}        
    }
	return $NetAnServer
 }
 
# **********************************************************************
#	Get the required inputs from configuration file
# **********************************************************************

function get_Inputs_From_File()
{
  try
  {
        [int[]]$frequencyValue=@()
         [int[]]$lowerInterval=@()
		 [int[]]$upperInterval=@()
      foreach($line in Get-Content -Path "C:\Certificate-expiry\config_file.ini")
     {
        if($line -match "_severity")
       {
         try
         {
          $split = "$line".Split("|",3)
          $split_Value = $split[2].Trim()
          $frequencyValue+=$split_Value
          $interval = $split[1].Split("-",2)
          $lowerInterval+=$interval[0]
          $upperInterval+=$interval[1]
         }
         catch
         {
          $errorMessage = $_.Exception.Message
	      $errorMessage >> $script:log
           "Obtaining the intervals and frequency for notification of certificate from the configuration file failed." >>$script:log
           EXIT(1)
         }  
        }  
     }
    } 
    catch
    {
     $_ >>$script:log
     EXIT(1)
	 }
    return $frequencyValue,$lowerInterval,$upperInterval
}
  

# **********************************************************************
#	Get the days before expiry of all the certificates
# **********************************************************************

function get_Expiry_Date()
{
    [System.Collections.ArrayList]$certNames_List=$certNames
	[int[]]$day=@()
    [string[]]$expiryDate=@()
	[string[]]$expiryTime=@()
  try
  {
     $date=@()
	 for($i=0;$i -lt $certNames.Count; $i++)
	 {
	 $endat=get_netancert_details -certName $certNames[$i]
	 
	 $endat_Split=$endat.ToString().Split(" ",2)
	 $expiryDate+=$endat_Split[0] | Get-Date -Format dd/MM/yyyy
	 $expiryTime+=$endat_Split[1] | Get-Date -Format HH:mm:ss
	 
     $date=(New-TimeSpan -Start (Get-Date) -End $endat).Days
	 
	 if((Get-Date).TimeOfDay -gt $endat.TimeOfDay -AND (Get-Date) -lt $endat)
     {
		$day+=$date+1
	 }
	 elseif((Get-Date).TimeOfDay -gt $endat.TimeOfDay)
	 {
		$day+=$date-1
	 }
	 elseif((Get-Date).TimeOfDay -lt $endat.TimeOfDay -AND (Get-Date) -gt $endat)
	 {
		$day+=$date-1
	 }
	 else
	 {
		$day+=$date
	 }
	 }

  }
  catch
      {
         $errorMessage = $_.Exception.Message
	     $errorMessage >> $script:log
          $_ >>$script:log
         "Obtaining the no of days left for expiry of certificate failed." >>$script:log
          EXIT(1)
       }
       return $expiryDate,$day,$certNames_List,$expiryTime
}

function get_netancert_details($certName)
{
	if($certName -eq $certNames[0])
	{
		$cert=(Get-PfxData -Password $sec_keypass -FilePath $cert_fullPath)
		return $cert.EndEntityCertificates.NotAfter	
	}
	else
	{
		$certdetails = Get-ChildItem "Cert:\LocalMachine\My" | Select-Object Subject,NotAfter | Select-String -Pattern "$certName" -CaseSensitive -SimpleMatch
		for($m=0;$m -lt $certdetails.Count;$m++)
        { 
            $test_NotAfter=([Regex]::Match($certdetails[$m],"NotAfter=\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}")).toString()
            
			$date=$test_NotAfter.Split("=",2)
			$exp_date = [datetime]::ParseExact($date[1],"MM/dd/yyyy HH:mm:ss",$null)
        }
		
		return $exp_date
	}
}

# *****************************************************************************************
#	Append the log file with days before expiry and certificates present in the server
# *****************************************************************************************

function append_Log_File
{
$expiryDate,$days,$certNames_List,$expiryTime=get_Expiry_Date
$freq,$low_Limit,$up_Limit=get_Inputs_From_File
  try
  { 
    for($j=0;$j -lt $days.Count;$j++)
    {
       if($days[$j] -gt 1)
       {
          "The "+$certNames_List[$j]+" certificate  expires in "+$days[$j]+" days( "+$expiryDate[$j]+" ).">>$script:log 
       }
	   elseif($days[$j] -eq 1)
	   {
		  $curentDateTime = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'
		  $certificateDateTime = Get-Date $($expiryDate[$j]+" "+$expiryTime[$j]) -Format 'dd/MM/yyyy HH:mm:ss'
		  $diff= New-TimeSpan -Start $curentDateTime -End $certificateDateTime
		  if(($diff.days -eq 0) -And($diff.hours -le 24)) {
			"The "+$certNames_List[$j]+" certificate expires in less than 24 hours( "+$expiryDate[$j]+" ).">>$script:log
			$days[$j] = 0
		  }
		  else {
			"The "+$certNames_List[$j]+" certificate expires in "+$days[$j]+" days( "+$expiryDate[$j]+" ).">>$script:log
		  }
	   }
       elseif($days[$j] -eq 0)
       {
        "The "+$certNames_List[$j]+" certificate expires today( "+$expiryDate[$j]+" ).">>$script:log 
       } 
       else
       {
         "The "+$certNames_List[$j]+" certificate has expired. Renew the certificate. ">>$script:log
       }
     }
	 
      if($adminui_log)
	  {
	  if(!(Test-Path $adminui_log -PathType Leaf))	
      {
		New-Item -ItemType File -Path $adminui_log | out-null		
          "Deployment::Certificate Name::Purpose::Certificate Expiry Date::Certificate Expiry(in days)`n">>$adminui_log
           for($k=0;$k -lt $days.Count;$k++)
           {
            if($days[$k] -AND !($certNames_List[$k] -match "RDP"))
            {
				"`rNetAn"+"::"+$certNames_List[$k]+"::NetAn Server::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$adminui_log
			}
			else
			{
				"`rNetAn"+"::"+$certNames_List[$k]+"::Remote Desktop Services::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$adminui_log
			}
           }
		    Windows-ToUnixFileConversionadmin
			Start-Sleep -s 4
			delete_older_logs
		}
	   }
	  
	  if($ddc_log)
	  {
	  if(!(Test-Path $ddc_log -PathType Leaf))	
      {
		New-Item -ItemType File -Path $ddc_log | out-null		
          "Deployment::Certificate Name::Purpose::Certificate Expiry Date::Certificate Expiry(in days)`n">>$ddc_log
           for($k=0;$k -lt $days.Count;$k++)
           {
            if($days[$k] -AND !($certNames_List[$k] -match "RDP"))
            {
				"`rNetAn"+"::"+$certNames_List[$k]+"::NetAn Server::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$ddc_log
			}
			else
			{
				"`rNetAn"+"::"+$certNames_List[$k]+"::Remote Desktop Services::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$ddc_log
			}
           }
		     Windows-ToUnixFileConversionddp
       }
	   }

   }
    catch
    {
      $errorMessage = $_.Exception.Message
	  $errorMessage >> $script:log
      $_ >>$script:log
      "Checking  the instances for notification of certificates failed." >>$script:log
       EXIT(1)
     }
	 
	 
	return $days,$certNames_List	
}

function Windows-ToUnixFileConversionadmin() {
   
    $certlogFiles="C:\Ericsson\Instrumentation\DDC\CertificateExpiry\System_Certificate_Expiry*.tsv"
    $currentDateFilename = Get-Date -format yyyyMMdd
     
         
      Get-ChildItem -Path $certlogFiles -Filter "*$currentDateFilename*" | ForEach-Object { 
      $certContents = [IO.File]::ReadAllText($_) -replace "`r`n?", "`n"
      $certUtf8 = New-Object System.Text.UTF8Encoding $false
      [IO.File]::WriteAllText($_, $certContents, $certUtf8)
      }

	}

function Windows-ToUnixFileConversionddp() {
   
    $certlogFiles="C:\Ericsson\Instrumentation\DDC\SystemLogs\System_Certificate_Expiry*.tsv"
    $currentDateFilename = Get-Date -format yyyyMMdd
     
         
      Get-ChildItem -Path $certlogFiles -Filter "*$currentDateFilename*" | ForEach-Object { 
      $certContents = [IO.File]::ReadAllText($_) -replace "`r`n?", "`n"
      $certUtf8 = New-Object System.Text.UTF8Encoding $false
      [IO.File]::WriteAllText($_, $certContents, $certUtf8)
      }

	}

function delete_older_logs
{
	try
	{
        $install_cert="C:\Ericsson\Instrumentation\DDC\CertificateExpiry"
	    $install_cert_count=( Get-ChildItem $install_cert ).Count
	    if((Test-Path $install_cert) -AND ($install_cert_count -gt 7))
	    {
			Get-ChildItem $install_cert -Recurse -File | Where CreationTime -lt  (Get-Date).AddDays(-7)  | Remove-Item -Force
		}
	}
	catch
	{
	    $errorMessage2 = $_.Exception.Message
	}
}

# ************************************************************************************************************************************************
# -----------------------------------------------------------MAIN() function----------------------------------------------------------------------
# ************************************************************************************************************************************************

     $time_Stamp=Get-Date -format "dd/MM/yyyy HH:mm:ss"
     $timeStampDefault=Get-Date -Format yyyyMMdd
     
     New-Item -ItemType Directory -Path C:\Certificate-expiry\log -erroraction 'silentlycontinue' | out-null
     $first= Test-Path C:\Certificate-expiry\log\certificate_expiry_log.log -PathType Leaf
	  #Creation of log file inside Certificate-expiry folder
       if(!$first)
	 {
      try
      {
	    New-Item -ItemType File -Path C:\Certificate-expiry\log -Name certificate_expiry_log.log 
		$script:log="C:\Certificate-expiry\log\certificate_expiry_log.log"
       }
       catch
       {
        Write-Host "Error occured while creating the log file"
        EXIT(1)
       }
	  }
     else
     {
		$script:log="C:\Certificate-expiry\log\certificate_expiry_log.log"
     } 
	 
	 $cert_fullPath=""
	 $serverXmlPath=""
	 
	 $NetAnVer = Get-ChildItem -Path C:\Ericsson\NetAnServer\Server\
     if(Test-Path -Path ("C:\Ericsson\NetAnServer\Server\" + $NetAnVer + "\tomcat\conf"))
     {
       $serverXmlPath = "C:\Ericsson\NetAnServer\Server\" + $NetAnVer + "\tomcat\conf\server.xml"
	   $xml = [xml](Get-Content $serverXmlPath)

	   $netAnCert = [string]($xml.Server.Service.Connector.SSLHostConfig.Certificate.certificateKeystoreFile)
	   $netAnCert = $netAnCert.trim()
	   $netAnCert = $netAnCert.Substring(8)
	   $cert_fullPath= "C:\Ericsson\NetAnServer\Server\" + $NetAnVer + "\tomcat\certs\" + $netAnCert
	   $netAnCert = $netAnCert.trim()
	   $netAnCert = $netAnCert.Substring(0, $netAnCert.Length - 4)
	 }
	 
	 if($serverXmlPath -match "7.11")
	 {
		$keyPass =([String]($xml.Server.Service.Connector.keystorePass)).trim()
	 }
	 else
	 {
		
        $connector = $xml.Server.Service.Connector
	    $connectorProtocol = $($connector.getAttribute("protocol")[0])
		
		
		if($connectorProtocol -eq "com.password.creation.CustomHttp11NioProtocol"){
		    
			"Certificate password in Server.xml is encypted.">>$script:log
			  
			$encryptedCertificatePassword =([String]($xml.Server.Service.Connector.SSLHostConfig.Certificate.certificateKeystorePassword)).trim()
			
			$LibPath="C:\Ericsson\NetAnServer\Server\" + $NetAnVer + "\tomcat\lib"
			$JAVA_HOME="C:\Ericsson\NetAnServer\Server\" + $NetAnVer + "\jdk"
			
			"Tomcat Lib Path $LibPath.">>$script:log
			
			$loc = Get-Location
			
			set-Location -Path $LibPath
			 
			[System.Environment]::SetEnvironmentVariable("JAVA_HOME", $JAVA_HOME)
	         
            [System.Environment]::SetEnvironmentVariable("Path", [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine) + ";$($env:JAVA_HOME)\bin")
			
			$keyPass = (java -cp ".;PasswordEncryptionDecryption.jar" com.password.creation.PasswordDecrypt $encryptedCertificatePassword)
			 
			Set-Location $loc	  
		           		
		}
		
		else{
			
		   $keyPass =([String]($xml.Server.Service.Connector.SSLHostConfig.Certificate.certificateKeystorePassword)).trim()
		   
		}
	 }
	 $sec_keypass = ConvertTo-SecureString $keyPass -AsPlainText -Force
	 
	 $NetAnServer = check_ServerType
	
# **********************************************************************
# --------------------------Start of Script----------------------------- 
# **********************************************************************
 
	if($NetAnServer -eq 1)
	{
"------------------------------------------------" >> $script:log
	 "Certificate expiry check script started on "+$time_Stamp >> $script:log
"-----------------------------------------------" >> $script:log
	 "Checking for the expiry of certificates."  >> $script:log
	}
	 #Check whether configuration file is present or not
     if(Test-Path C:\Certificate-expiry\config_file.ini -PathType Leaf)
     {
		if($NetAnServer -eq 1)
		{
			"The configuration file present in the server is found.">>$script:log
		}
     }
     else
     {
		if($NetAnServer -eq 1)
		{
			"The configuration file is not found in the specified path.">>$script:log
			Write-Host "The configuration file is not found in the specified path."
		}
       EXIT(1)
     }
	 $certNames=@("$netAnCert")
	 if($NetAnServer -eq 1)
	 {
		if(Test-Path -Path ("C:\Certificates"))
		{
			$RDP_cert = (Get-ChildItem -Path ("C:\Certificates") -Filter *.p12).BaseName
			$certNames=@("$netAnCert","$RDP_cert")
		}
	 }
	     
    
	  $ddc_log = $null
	  $adminui_log = $null
	  New-Item -ItemType Directory -Path C:\Ericsson\Instrumentation\DDC\CertificateExpiry  -erroraction 'silentlycontinue' | out-null
	  #Creation of AdminUI log file
	  if($time_Stamp -match "23:32")
	  {
		if(Test-Path -Path "C:\Ericsson\Instrumentation\DDC\CertificateExpiry")
        {
			$adminui_log="C:\Ericsson\Instrumentation\DDC\CertificateExpiry\System_Certificate_expiry_$timeStampDefault.tsv"
        }
        else
        {
			$adminui_log=$null
        }
	  }
	  
	  #Creation of DDC-DDP log file
	  if($time_Stamp -match "23:32")
	  {
		if(Test-Path -Path "C:\Ericsson\Instrumentation\DDC\SystemLogs")
        {
			$ddc_log="C:\Ericsson\Instrumentation\DDC\SystemLogs\System_Certificate_expiry_$timeStampDefault.tsv"
        }
        else
        {
			$ddc_log=$null
        }
	  }
		
      $days,$certNames_List=append_Log_File
	