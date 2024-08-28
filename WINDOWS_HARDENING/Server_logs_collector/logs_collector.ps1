# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2023 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ************************************************************************
# Name     		: logs_collector.ps1
# Purpose  		: Automation of collection of logs in Windows server
# Last Updated	: 27-December-2023
#
# *************************************************************************

#------------------------------------------------------------------------
#Print date and time in the log file
#------------------------------------------------------------------------
function PrintDateTime()
{    
    "----------------------------------------------- " >>$global:LogFile 
    Get-Date -Format "dddd [MM/dd/yyyy] [HH:mm:ss]" >>$global:LogFile
    "----------------------------------------------- " >>$global:LogFile      
}

#------------------------------------------------------------------------
#Creating a folder where logs should be copied and log file
#------------------------------------------------------------------------	
function CreateLogFolder()
{  
	try
	{                
		if(Test-Path ($LogCollectorPath+'\Logs_Collector'))
		{            
			Remove-Item ($LogCollectorPath+'\Logs_Collector\*') -Force -Recurse -Confirm:$false
            $global:CopyDestinationFolder = $LogCollectorPath+'\Logs_Collector'
			Start-Sleep -Seconds 5      
			$global:LogFile = New-Item -Path ($LogCollectorPath+'\Logs_Collector\Logs_Collector.log') -ItemType File
		}
		else
		{
			New-Item -Path ($LogCollectorPath+'\Logs_Collector') -ItemType Directory | Out-Null
            Start-Sleep -Seconds 5 
            $global:CopyDestinationFolder = $LogCollectorPath+'\Logs_Collector'
            $global:LogFile = New-Item -Path ($LogCollectorPath+'\Logs_Collector\Logs_Collector.log') -ItemType File
		}
	}
	catch
	{
		$_ >>$global:LogFile
		Write-Host "Error occurred while creating the log folder."
		EXIT(1)
	}
}

#---------------------------------------------------------------------------------------------
#Reads the value of the parameter from configuration file if parameter is security_logs
#---------------------------------------------------------------------------------------------
function readParameter_security_logs()
{
    try
    {
        foreach($SourceFolder in Get-Content  $InputFile)
        {    
            if($SourceFolder -match "TimePeriod")
            {
                $line_split = "$SourceFolder".split("=",2) 
                $global:LogretentionValue = $line_split[1].Trim()  
                $global:limit = (Get-Date).AddDays(-$LogretentionValue)     	                     
            }        
            elseif($SourceFolder -match "Security_LogFolder")
            {                                
          	   	$line_split = "$SourceFolder".split("=",2)
                $Value = $line_split[1].Trim()        	   	     
                #Write-Host "Folder " $Value 
                if($Value -ne '')
                {
					if(($Value -match "NetAnServer") -AND ($NetAnVer -ne $null))
					{
						$ver = $Value.split("\")[4]
						if($ver -ne $null -AND $ver -ne "tomcat")
						{
							$Value = $Value.replace("$ver","$NetAnVer")
						}
					}
                    CopyLogs $Value       
                }           
                else
                {
                    $Parameter = $line_split[0]
                    "`n$Parameter Value is empty" >>$global:LogFile
                }  
            }
            elseif($SourceFolder -match "Security_FileName")
            {
                $line_split = "$SourceFolder".split("=",2) 
                $Value = $line_split[1].Trim()       	   	    
                #Write-host "File " $Value 
                if($Value -ne '')
                {                    
                    CopyFile $Value
                }
                else
                {
                    $Parameter = $line_split[0]
                    "`n$Parameter Value is empty" >>$global:LogFile
                }
            }
            elseif($SourceFolder -match "Security_EventLog")
            {
                $line_split = "$SourceFolder".split("=",2) 
                $Value = $line_split[1].Trim()       	   	     
                #Write-host "Event " $Value 
                if($Value -ne '')
                {                    
                    EventLogs $Value
                }
                else
                {
                    $Parameter = $line_split[0]
                    "`n$Parameter Value is empty" >>$global:LogFile
                }
            }                    
        }
    }
    catch
    {
        $_ >>$global:LogFile
		Write-Host "Error occurred while reading the configuration file for security logs."
		EXIT(1)
    }
}

#---------------------------------------------------------------------------------------------
#Reads the value of the parameter from configuration file if parameter is application_logs
#---------------------------------------------------------------------------------------------
function readParameter_application_logs()
{
    try
    {
        foreach($SourceFolder in Get-Content  $InputFile)
        {    
            if($SourceFolder -match "TimePeriod")
            {
                $line_split = "$SourceFolder".split("=",2) 
                $global:LogretentionValue = $line_split[1].Trim()  
                $global:limit = (Get-Date).AddDays(-$LogretentionValue)     	                     
            }        
            elseif($SourceFolder -match "Application_LogFolder")
            {                                
          	   	$line_split = "$SourceFolder".split("=",2)
                $Value = $line_split[1].Trim()        	   	     
                #Write-Host "Folder " $Value 
                if($Value -ne '')
                {
					if(($Value -match "NetAnServer") -AND ($NetAnVer -ne $null))
					{
						$ver = $Value.split("\")[4]
						if($ver -ne $null -AND $ver -ne "tomcat")
						{
							$Value = $Value.replace("$ver","$NetAnVer")
						}
					}
                    CopyLogs $Value       
                }           
                else
                {
                    $Parameter = $line_split[0]
                    "`n$Parameter Value is empty" >>$global:LogFile
                }  
            }
            elseif($SourceFolder -match "Application_FileName")
            {
                $line_split = "$SourceFolder".split("=",2) 
                $Value = $line_split[1].Trim()       	   	    
                #Write-host "File " $Value 
                if($Value -ne '')
                {                    
                    CopyFile $Value
                }
                else
                {
                    $Parameter = $line_split[0]
                    "`n$Parameter Value is empty" >>$global:LogFile
                }
            }
 elseif($SourceFolder -match "Application_EventLog")
            {
                $line_split = "$SourceFolder".split("=",2) 
                $Value = $line_split[1].Trim()       	   	     
                #Write-host "Event " $Value 
                if($Value -ne '')
                {                    
                    EventLogs $value
					
					
                }
                else
                {
                    $Parameter = $line_split[0]
                    "`n$Parameter Value is empty" >>$global:LogFile
                }
            }     
			
        }
    }
    catch
    {
        $_ >>$global:LogFile
		Write-Host "Error occured while reading the configuration file for application_logs."
		EXIT(1)
    }
}

#------------------------------------------------------------------------
#Exporting event logs
#------------------------------------------------------------------------
function EventLogs($Value)
{
	try
	{
        PrintDateTime
        $EventViewerName = $Value
        if(Test-Path ($LogCollectorPath+'\Logs_Collector\Event Logs'))
        {
                        
        }
        else
        {
            New-Item -Path ($LogCollectorPath+'\Logs_Collector\Event Logs') -ItemType Directory | Out-Null 
        }        
        $CurrentDate = Get-Date
		try
		{
			
			Get-EventLog -LogName $EventViewerName -After $global:limit -Before $CurrentDate | Export-Csv -LiteralPath ($LogCollectorPath+"\Logs_Collector\Event Logs\EventViewer_"+$EventViewerName+"_log.csv") -NoTypeInformation
			if(Test-Path ($LogCollectorPath+"\Logs_Collector\Event Logs\EventViewer_"+$EventViewerName+"_log.csv"))
			{
				"$EventViewerName event logs copied to $LogCollectorPath\Logs_Collector\Event Logs" >>$global:LogFile
			}
			else
			{
				"Failed to copy $EventViewerName event logs to $LogCollectorPath\Logs_Collector\Event Logs" >>$global:LogFile
			}
		}    
		catch
		{
			"No Event Logs found with name $EventViewerName" >>$global:LogFile
			$_ >> $global:LogFile
			Write-Host "No Event Logs found with name $EventViewerName"
            EXIT(1)
		}
	}
	catch
	{
		$_ >>$global:LogFile
		Write-Host "Error occured while exporting event logs."
		EXIT(1)
	}
}

#------------------------------------------------------------------------
#Copying logs from the given path in configuration file
#------------------------------------------------------------------------
function CopyLogs($Value)
{
    try
    {    
        $SourceLogFolders = $Value    
        PrintDateTime
        $SourceLogPath = $SourceLogFolders+'\*'        
        if(Test-path $SourceLogPath)
        {
            $BeforeSplit = $SourceLogFolders
            $FolderName = "$BeforeSplit".Split("\")
            $DestinationLogName = $FolderName[$FolderName.Length-2]+" "+$FolderName[$FolderName.Length-1]
            if(Test-Path ($LogCollectorPath+'\Logs_Collector\'+$DestinationLogName))
            {
                "$SourceLogFolders path is given multiple times in configuration file" >>$global:LogFile 
                $DestinationLogName = $FolderName[$FolderName.Length-3]+" "+$FolderName[$FolderName.Length-2]+" "+$FolderName[$FolderName.Length-1]  
                New-Item -Path ($LogCollectorPath+'\Logs_Collector\'+$DestinationLogName) -ItemType Directory | Out-Null                                       
            }
            else
            {
                New-Item -Path ($LogCollectorPath+'\Logs_Collector\'+$DestinationLogName) -ItemType Directory | Out-Null
                
            }            
            $DestinationLogFolder = $LogCollectorPath+'\Logs_Collector\'+$DestinationLogName

            
                      
            CopyFiles $SourceLogPath $DestinationLogFolder

                                                            
        }
        else
        {
            "`n$SourceLogPath not found to copy logs"  >>$global:LogFile
        }     
    }
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occured while copying logs."
		EXIT(1)
	}             
}

#------------------------------------------------------------------------
#Copying file from the given path in configuration file
#------------------------------------------------------------------------
function CopyFile($Value)
{
    try
    {
        PrintDateTime
        if(Test-Path $Value)
        {
            "$Value found and copying the file" >>$global:LogFile                        
            Copy-Item $Value -Destination $CopyDestinationFolder
            "$Value file is copied to $CopyDestinationFolder" >>$global:LogFile  
        }
        else
        {
            "$Value file not found to copy" >>$global:LogFile
        }
    }
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occured while copying log files."
		EXIT(1)
	}   
}

#------------------------------------------------------------------------
#Generic function for copying logs
#------------------------------------------------------------------------
function CopyFiles($SourceLogPath , $DestinationLogFolder)
{
	$count = 0
	try
	{        
		$Files = Get-ChildItem $SourceLogPath -File
		foreach ($File in $Files)
		{        
			if ($File.LastWriteTime -gt $global:limit)
			{                
				Copy-Item $File -Destination $DestinationLogFolder  
                $count=+1
				
			}
		}
		
		if($count -eq 0)
		{
			 "Logs are not present in $SourceLogPath within the time period" >>$global:LogFile
		}
		if($count -eq 1)
		{
			"Logs are present in $SourceLogPath and copying it" >>$global:LogFile
		}
		
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occured while copying logs from source to destination folder."
		EXIT(1)
	}
}

#------------------------------------------------------------------------
#Copying Citrix  logs
#------------------------------------------------------------------------
function CopyCCSinstallationLog()
{
	try
	{
        PrintDateTime
		New-Item -Path ($LogCollectorPath+'\Logs_Collector\CCS Logs') -ItemType Directory | Out-Null   
		$SourceFolder = 'C:\OCS\install_config\CCS_config\CITRIXLOGS'
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\CCS Logs'
		if(Test-Path $SourceFolder)
		{
			Copy-item -path $SourceFolder -destination $DestinationFolder -recurse
			"CCS installtion Logs are copied" >>$global:LogFile
		}              
		else
		{
			"No CCS installation Logs are present in $SourceFolder" >>$global:LogFile
		}
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occured while copying CCS Citrix logs."
		EXIT(1)
	}
}

function CopyCCSupgradeLog()
{
	try
	{
        PrintDateTime
		New-Item -Path ($LogCollectorPath+'\Logs_Collector\CCS upgrade Logs') -ItemType Directory | Out-Null   
		$SourceFolder = 'C:\OCS\upgrade_config\CCS_upgrade_config\CITRIXLOGS'
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\CCS upgrade Logs'
		if(Test-Path $SourceFolder)
		{
			Copy-item -path $SourceFolder -destination $DestinationFolder -recurse
			"CCS installtion Logs are copied" >>$global:LogFile
		}              
		else
		{
			"No CCS upgrade Logs are present in $SourceFolder" >>$global:LogFile
		}
	}
	catch
	{
		$_>>$global:LogFile
	}
}

function CopyVDAinstallationLog()
{
	try
	{
        PrintDateTime
		New-Item -Path ($LogCollectorPath+'\Logs_Collector\VDA Logs') -ItemType Directory | Out-Null   
		$SourceFolder = 'C:\OCS\install_config\VDA_config\CITRIXLOGS'
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\VDA Logs'
		if(Test-Path $SourceFolder)
		{
			Copy-item -path $SourceFolder -destination $DestinationFolder -recurse
			"VDA installtion Logs are copied" >>$global:LogFile
		}              
		else
		{
			"No VDA installation Logs are present in $SourceFolder" >>$global:LogFile
		}
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occured while copying VDA installation logs."
		EXIT(1)
	}
}

function CopyVDAupgradeLog()
{
	try
	{
        PrintDateTime
		New-Item -Path ($LogCollectorPath+'\Logs_Collector\VDA upgrade Logs') -ItemType Directory | Out-Null   
		$SourceFolder = 'C:\OCS\upgrade_config\VDA_upgrade_config\CITRIXLOGS'
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\VDA upgrade Logs'
		if(Test-Path $SourceFolder)
		{
			Copy-item -path $SourceFolder -destination $DestinationFolder -recurse
			"VDA upgrade Logs are copied" >>$global:LogFile
		}              
		else
		{
			"No VDA upgrade Logs are present in $SourceFolder" >>$global:LogFile
		}
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occured while copying VDA upgrade logs."
		EXIT(1)
	}
}


#------------------------------------------------------------------------
#Copying BI Install directory logs
#------------------------------------------------------------------------
function CopyBiLog()
{
	try
	{
        PrintDateTime
		New-Item -Path ($LogCollectorPath+'\Logs_Collector\BI Logs') -ItemType Directory | Out-Null   
		$SourceFolder = $BiInstallDir+'SAP BusinessObjects Enterprise XI 4.0\logging\*'
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\BI Logs'
		if(Test-Path $SourceFolder)
		{
			CopyFiles $SourceFolder $DestinationFolder
			
		}              
		else
		{
			"No BI Logs are present in $SourceFolder" >>$global:LogFile
		}
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occured while copying BI install directory logs."
		EXIT(1)
	}
}

#------------------------------------------------------------------------
#Copying Tomcat logs
#------------------------------------------------------------------------
function CopyTomcatLogs()
{
	try
	{
        PrintDateTime
		New-Item -Path ($LogCollectorPath+'\Logs_Collector\BI Tomcat Logs') -ItemType Directory | Out-Null
		$SourceFolder = $BiInstallDir+'tomcat\logs\*'
		
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\BI Tomcat Logs'
		if(Test-Path $SourceFolder)
		{       
			CopyFiles $SourceFolder $DestinationFolder
			"Tomcat Logs are copied" >>$global:LogFile
		}
		else
		{
			"No Tomcat Logs are present in $SourceFolder" >>$global:LogFile
		}

        $SourceFolder = $BiInstallDir+'tomcat\*.hprof'
        if(Test-Path $SourceFolder)
		{       
			CopyFiles $SourceFolder $DestinationFolder
			
		}
		else
		{
			"No .HPROF Files are present in $SourceFolder" >>$global:LogFile
		}
        CopyTomcatBackupLogs
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occurred while copying tomcat logs."
		EXIT(1)
	}
}

#------------------------------------------------------------------------
#Copying Tomcat backup logs
#------------------------------------------------------------------------
function CopyTomcatBackupLogs()
{
	try
	{
        PrintDateTime		
		$SourceFolder = $BiInstallDir+'tomcat\tomcat_logs_backup\*'
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\BIS Tomcat Logs'
		if(Test-Path $SourceFolder)
		{       
			CopyFiles $SourceFolder $DestinationFolder
			
		}
		else
		{
			"No Tomcat Backup Logs are present in $SourceFolder" >>$global:LogFile
		}
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occured while copying tomcat backup logs."
		EXIT(1)
	}
}


#Copying Audit logs

function AuditLogs()
{
	try
	{
        PrintDateTime
		New-Item -Path ($LogCollectorPath+'\Logs_Collector\Audit Logs') -ItemType Directory | Out-Null
		$SourceFolder = 'C:\Audit\audit_log\*'
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\Audit Logs'
		if(Test-Path $SourceFolder)
		{       
			CopyFiles $SourceFolder $DestinationFolder
			
		}
		else
	    {
			"No Audit Logs are present in $SourceFolder" >>$global:LogFile
		}

        
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occurred while copying Audit logs."
		EXIT(1)
	}
}

#Copy Windows hardening  logs

function HardeningLogs()
{
	try
	{
        PrintDateTime
		New-Item -Path ($LogCollectorPath+'\Logs_Collector\Windows Hardening Logs') -ItemType Directory | Out-Null
		$SourceFolder = 'C:\Windows_Hardening\log\*'
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\Windows Hardening Logs'
		if(Test-Path $SourceFolder)
		{       
			CopyFiles $SourceFolder $DestinationFolder
			#" Windows Hardening Logs are copied" >>$global:LogFile
		}
		else
		{
			" No Windows Hardening Logs are present in $SourceFolder" >>$global:LogFile
		}

        
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occurred while copying Windows Hardening Logs."
		EXIT(1)
	}
}

#Copy Firewall Logs

function FirewallLogs()
{
	try
	{
        PrintDateTime
		New-Item -Path ($LogCollectorPath+'\Logs_Collector\Firewall Logs') -ItemType Directory | Out-Null
		$SourceFolder = 'C:\Firewall\log\*'
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\Firewall Logs'
		if(Test-Path $SourceFolder)
		{       
			CopyFiles $SourceFolder $DestinationFolder
			#"Firewall Logs are copied" >>$global:LogFile
		}
		else
		{
			"No Firewall Logs are present in $SourceFolder" >>$global:LogFile
		}

        
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occurred while copying Firewall logs."
		EXIT(1)
	}
}

#copy certificate-expiry logs
function CertificateExpiryLogs()
{
	try
	{
        PrintDateTime
		New-Item -Path ($LogCollectorPath+'\Logs_Collector\Certificate-expiry Logs') -ItemType Directory | Out-Null
		$SourceFolder = 'C:\Certificate-expiry\log\*'
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\Certificate-expiry Logs'
		if(Test-Path $SourceFolder)
		{       
			CopyFiles $SourceFolder $DestinationFolder
			#" Certificate-Expiry Logs are copied" >>$global:LogFile
		}
		else
		{
			"No Certificate-Expiry Logs are present in $SourceFolder" >>$global:LogFile
		}

        
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occurred while copying Certificate-Expiry Logs."
		EXIT(1)
	}
}


# Copy BI InstallData Logs
function CopyBIInstallDataLogs()
{
	try
	{
        PrintDateTime
		New-Item -Path ($LogCollectorPath+'\Logs_Collector\BI InstallData Logs') -ItemType Directory | Out-Null
		$a=Get-ChildItem -Path $BiInstallDir InstallData\logs\ -Name
	
		$SourceFolder = $BiInstallDir+'InstallData\logs\'+$a +'\*'
		$DestinationFolder = $LogCollectorPath+'\Logs_Collector\BI InstallData Logs'
		if(Test-Path $SourceFolder)
		{       
			CopyFiles $SourceFolder $DestinationFolder
			#"BI InstallData Logs are copied" >>$global:LogFile
		}
		
		
		else
		{
			"No BI InstallData Logs are present in $SourceFolder" >>$global:LogFile
		}

      
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occurred while copying BI InstallData logs."
		EXIT(1)
	}
}




#------------------------------------------------------------------------
#Copying SAP installed data
#------------------------------------------------------------------------
function CopyInventoryFile()
{
	try
	{	
        PrintDateTime
		$InventoryFile = $BiInstallDir+'\InstallData\inventory.txt'
        $InstallData = New-Item -Path ($LogCollectorPath+'\Logs_Collector\Software_Install_Info.txt') -ItemType File
		if(Test-Path $InventoryFile)
		{
			Get-Content -Path $InventoryFile >> $InstallData
            "SAP install info copied to Software_Install_Info.txt" >>$global:LogFile
		}
        else
        {
            "Inventory.txt file Doesn't exist in $InventoryFile, cannot get BI version" >>$global:LogFile
        }
		$WinSCP_version = (Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |Where-Object {$_.DisplayName -match "WinSCP*" }).DisplayName
		if ($WinSCP_version)
		{	
			
			Add-Content -Path $InstallData -Value "Installed WinSCP software version is $($WinSCP_version)" 
		}
		if (Test-Path "C:\ebid\universe_report_promotion\Winscp.exe")
		{
			$Winscp_universe_report=(Get-Command C:\ebid\universe_report_promotion\WinSCP.exe).fileversioninfo.productversion
			Add-Content -Path $InstallData -Value "Winscp version in universe_report_promotion is $($Winscp_universe_report)"
		}
		
		$SQLAnywhere_version = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |Where-Object {$_.DisplayName -match "SQL Anywhere*" }).DisplayName
		if ($SQLAnywhere_version)
		{	
			Add-Content -Path $InstallData -Value $SQLAnywhere_version
		}
		
		$SAPIQClient_version = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |Where-Object {$_.DisplayName -match "SAP IQ*" }).DisplayName
		if ($SAPIQClient_version)
		{	
			Add-Content -Path $InstallData -Value $SAPIQClient_version
		}
		
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occured while copying inventory logs."
		EXIT(1)
	}	
}

#---------------------------------------------------------------------
# Install NFS from server manager if not already installed
#---------------------------------------------------------------------
function Get-IPAddress 
{
  try
  {
    Write-Host ""
    if(Test-Path -Path "C:\OCS\upgrade_config\tmp.txt")
    {
      $global:eniq_server_ip = Get-Content -Path "C:\OCS\upgrade_config\tmp.txt"
      Remove-Item -path "C:\OCS\Upgrade_config\tmp.txt"
    }
    else
   {
      $global:eniq_server_ip = Read-Host -Prompt 'Enter ENIQ server IP'
   }
   $validity = ( "$eniq_server_ip" -Match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" )
   $DotCount = ( "$eniq_server_ip".ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
    If (($validity -ne "True") -or ($DotCount -ne 3))
	{
	   Write-Host ""
	   Write-Host "Please enter a valid IP address."
	   Get-IPAddress
	} 
	Else 
	{
	   ping $eniq_server_ip | Out-Null
	   If ($? -ne "True") 
	   {
			"Warning! Could not ping the server $eniq_server_ip" >> $global:LogFile
			Write-Host "Warning! Could not ping the server $eniq_server_ip!"
		}
	}
  }
  catch
  {
      $_ >> $global:LogFile
      Write-Host "Error occured while getting IP address for NFS Share."
		EXIT(1)
  }
}

function Install-NFS 
{
  try
  {
     $script:loc = Get-Location
     $script:status = Get-WmiObject -Class Win32_Service -Filter "Name='NfsService'"
     if(!$status) 
     {
        $ScriptBlockNfsService = {
            Import-Module ServerManager
            Import-Module NFS
            Add-WindowsFeature FS-NFS-Service -ErrorAction Stop -WarningAction silentlyContinue            
        }
		try
		{
            "Installing NFS service" >> $global:LogFile
            Invoke-Command -ScriptBlock $ScriptBlockNfsService -ErrorAction Stop  | Out-Null
            "NFS service installed" >> $global:LogFile
        }
		catch
		{
			$_ >> $global:LogFile
            Write-Host "NFS service installation failed" 
            EXIT(1)
        }
     } 
     else 
     {
		"NFS service is already installed" >> $global:LogFile 	
     }
  }
  catch
  {
      $_ >> $global:LogFile
      Write-Host "Error occured while installing NFS service."
		EXIT(1)
  }
}

#---------------------------------------------------------------------
# Create the folder and configure NFS Share
#---------------------------------------------------------------------
function NFS-Share 
{
  try
  {
	if((Test-Path -path "$LogCollectorPath\OCS\Logs_Collector") -or (Test-Path -path "$LogCollectorPath\ebid\Logs_Collector") -or (Test-Path -path "$LogCollectorPath\NetAn_Logs\Logs_Collector") -or (Test-Path -path "$LogCollectorPath\Codeploy_Logs\Logs_Collector"))
	{
	   "Expected folder is available in the path. " >> $global:LogFile
	}
    else
	{
       if($global:Server -eq 0)
	   {
		   if (Test-Path -path "$LogCollectorPath\ebid")
		   {
			   New-Item -ItemType directory "$LogCollectorPath\ebid\Logs_Collector" -ErrorAction stop | Out-Null
		   }
		   else
		   {
			   New-Item -ItemType directory "$LogCollectorPath\ebid" -ErrorAction stop | Out-Null
			   New-Item -ItemType directory "$LogCollectorPath\ebid\Logs_Collector" -ErrorAction stop | Out-Null
		   }   
	   }
	   elseif(($global:Server -ge 1) -and ($global:Server -lt 4))
	   {
	       New-Item -ItemType directory "$LogCollectorPath\OCS\Logs_Collector" -ErrorAction stop | Out-Null
	   }
	   elseif($global:Server -eq 4)
	   {
			 if (Test-Path -path "$LogCollectorPath\NetAn_Logs")
		   {
			   New-Item -ItemType directory "$LogCollectorPath\NetAn_Logs\Logs_Collector" -ErrorAction stop | Out-Null
		   }
		   else
		   {
			   New-Item -ItemType directory "$LogCollectorPath\NetAn_Logs\" -ErrorAction stop | Out-Null
			   New-Item -ItemType directory "$LogCollectorPath\NetAn_Logs\Logs_Collector" -ErrorAction stop | Out-Null
		   }
		   
	   }
	   elseif($global:Server -eq 6)
	   {
		   if (Test-Path -path "$LogCollectorPath\Codeploy_Logs")
		   {
			   New-Item -ItemType directory "$LogCollectorPath\Codeploy_Logs\Logs_Collector" -ErrorAction stop | Out-Null
		   }
		   else
		   {
			   New-Item -ItemType directory "$LogCollectorPath\Codeploy_Logs" -ErrorAction stop | Out-Null
			   New-Item -ItemType directory "$LogCollectorPath\Codeploy_Logs\Logs_Collector" -ErrorAction stop | Out-Null
		   }
		   
	   }
    }
	$output = Invoke-Command -ScriptBlock {Get-NfsShare}
    $listOfSharedDir = $($output.name)

	$available_folder = (0..($listOfSharedDir.Count-1)) |where {$listOfSharedDir[$_] -match "Logs_Collector"}
      if ($available_folder)
	  {
        "The Directory is already NFS share Configured" >> $global:LogFile
      }
	  else
	  {
	     if(Test-Path -path "$LogCollectorPath\OCS\Logs_Collector" )	
	     {
           $ScriptBlockNfsShare = {
            New-NfsShare -Name "Logs_Collector" -Path "$LogCollectorPath\OCS\Logs_Collector" | Out-Null
            Grant-NfsSharePermission -Name "Logs_Collector" -ClientName $eniq_server_ip -ClientType "host" -Permission "readwrite" | Out-Null
           }
	     }
	     elseif(Test-Path -path "$LogCollectorPath\ebid\Logs_Collector")
	     {
		   $ScriptBlockNfsShare = {
            New-NfsShare -Name "Logs_Collector" -Path "$LogCollectorPath\ebid\Logs_Collector" | Out-Null
            Grant-NfsSharePermission -Name "Logs_Collector" -ClientName $eniq_server_ip -ClientType "host" -Permission "readwrite" | Out-Null
           } 
	     }
		 elseif(Test-Path -path "$LogCollectorPath\NetAn_Logs\Logs_Collector")
	     {
		   $ScriptBlockNfsShare = {
            New-NfsShare -Name "Logs_Collector" -Path "$LogCollectorPath\NetAn_Logs\Logs_Collector" | Out-Null
            Grant-NfsSharePermission -Name "Logs_Collector" -ClientName $eniq_server_ip -ClientType "host" -Permission "readwrite" | Out-Null
           } 
	     }
		 elseif(Test-Path -path "$LogCollectorPath\Codeploy_Logs\Logs_Collector")
	     {
		   $ScriptBlockNfsShare = {
            New-NfsShare -Name "Logs_Collector" -Path "$LogCollectorPath\Codeploy_Logs\Logs_Collector" | Out-Null
            Grant-NfsSharePermission -Name "Logs_Collector" -ClientName $eniq_server_ip -ClientType "host" -Permission "readwrite" | Out-Null
           } 
	     }
        try 
		{
            "Attempting to configure NFS share" >> $global:LogFile
            Invoke-Command -ScriptBlock $ScriptBlockNfsShare -ErrorAction Stop | Out-Null   
		} 
		catch
		{
			$_ >> $global:LogFile
			Write-Host "Error occurred while attempting to configure NFS Share"
        }
        finally 
		{
            Set-Location $loc
        }
		
		$output = Invoke-Command -ScriptBlock {Get-NfsShare}
		$listOfSharedDir = $($output.name)
		$available_folder = (0..($listOfSharedDir.Count-1)) |where {$listOfSharedDir[$_] -match "Logs_Collector"}
           if ($available_folder)
		   {
			  "The directory is configured for NFS share successfully" >> $global:LogFile		
 		   }
		   else 
		   {
		   	  "The directory could not be configured for NFS share" >> $global:LogFile 
		   }
      }
  }
  catch
  {
     $_>>$global:LogFile
	 Write-Host "Error occurred while configuring a folder with NFS-Share."
	 EXIT(1)
  }
}

#------------------------------------------------------------------------
#Creating a zip folder for folder where all logs are copied
#------------------------------------------------------------------------
function ZipLogFolder()
{
	try
	{
		if(Test-Path ($LogCollectorPath+"\OCS\Logs_Collector\$ZipName*.zip"))
		{
			Remove-Item ($LogCollectorPath+"\OCS\Logs_Collector\$ZipName*.zip") -Recurse -Force
		} 
        elseif(Test-Path ($LogCollectorPath+"\ebid\Logs_Collector\$ZipName*.zip"))
		{
			Remove-Item ($LogCollectorPath+"\ebid\Logs_Collector\$ZipName*.zip") -Recurse -Force
		}
		elseif(Test-Path ($LogCollectorPath+"\NetAn_Logs\Logs_Collector\$ZipName*.zip"))
		{
			Remove-Item ($LogCollectorPath+"\NetAn_Logs\Logs_Collector\$ZipName*.zip") -Recurse -Force
		}
		 elseif(Test-Path ($LogCollectorPath+"\Codeploy_Logs\Logs_Collector\$ZipName*.zip"))
		{
			Remove-Item ($LogCollectorPath+"\Codeploy_Logs\Logs_Collector\$ZipName*.zip") -Recurse -Force
		}
	        $FolderName = $ZipName+'_'+$TimeStamp
			if($global:Server -eq 0)
			{
				$ZipPath = $LogCollectorPath+"\ebid\Logs_Collector\$FolderName.zip"
			}
			elseif(($global:Server -ge 1) -and ($global:Server -lt 4))
			{
		        $ZipPath = $LogCollectorPath+"\OCS\Logs_Collector\$FolderName.zip"
			}
        	elseif($global:Server -eq 4) 
			{
		        $ZipPath = $LogCollectorPath+"\NetAn_Logs\Logs_Collector\$FolderName.zip"
			}
			elseif($global:Server -eq 6)
			{
				$ZipPath = $LogCollectorPath+"\Codeploy_Logs\Logs_Collector\$FolderName.zip"
			}
			$ProgressPreference = "SilentlyContinue"
			#Checking if the nfs share folder is already available or not
		try
		{
			Compress-Archive -Path ($LogCollectorPath+'\Logs_Collector') -DestinationPath ($ZipPath) 
		}
		catch
		{
			    $source = $LogCollectorPath+'\Logs_Collector'
		        Add-Type -assembly "system.io.compression.filesystem"
		        [io.compression.zipfile]::CreateFromDirectory($source, $ZipPath)
		}
                
        DeleteLogsCollectorFolder
        if(Test-Path -Path $ZipPath)
        {
            Write-Host "`nCollection of log files completed and archieve file is created in $ZipPath" -ForegroundColor Green
        }
        else
        {
            Write-Host "`nUnable to create zip folder. Try re-running the script." -ForegroundColor Red
        }
	}
	catch
	{
		$_>>$global:LogFile
		Write-Host "Error occurred while zipping the log folder. "
		EXIT(1)
	}
}

#------------------------------------------------------------------------
#Deleting the logs copied folder after archive is done
#------------------------------------------------------------------------
function DeleteLogsCollectorFolder()
{
    try
	{        
		if(Test-Path ($LogCollectorPath+'\Logs_Collector'))
		{
			Remove-Item ($LogCollectorPath+'\Logs_Collector') -Force -Recurse -Confirm:$false				
		}
		else
		{
			Write-Host "'n [ERROR] Logs collector folder did not created successfully. Try running script again" -ForegroundColor Red
		}
	}
	catch
	{
		$_ >>$global:LogFile
		Write-Host "Error occurred while deleting the temporary log folder."
		EXIT(1)
	}
}

#------------------------------------------------------------------------
#Checking if any task of logs collector is exist
#------------------------------------------------------------------------
Function Check-TasksInTaskScheduler ($currentTask) 
{
    try
	{
        $schedule = new-object -com("Schedule.Service")
        $schedule.connect()
        $tasks = $schedule.getfolder("\").gettasks(0)
        foreach ($t in $tasks){
            $taskName=$t.Name
            if(($taskName -eq $currentTask)){
             return $true
            }
        }
     }
	 catch
	 {
       $errorMessage = $_.Exception.Message
	   $errorMessage >>$global:LogFile
       Write-Host "Check Tasks in task scheduler Failed"
       EXIT(1)
     }
}

#------------------------------------------------------------------------
#Checking and Adding a task into task schduler 
#------------------------------------------------------------------------
Function Add-TasksInTaskScheduler 
{
    try
    {
        PrintDateTime
        $isTaskExist = Check-TasksInTaskScheduler "Logs_Collector"
	    if (!$isTaskExist) 
        {
            "Logs_Collector task does not exist in task schduler and creating a weekly task" >>$global:LogFile
	    	schtasks /create /ru system /sc weekly /tn "Logs_Collector" /tr $Action /sd $StartDateForDataCollector /st $StartTimeForDataCollector /rl highest | Out-null
	    }
        else
        {
            "Logs_Collector task already present in task schduler" >>$global:LogFile
        }
    }
    catch
	{
		$_ >>$global:LogFile
		Write-Host "Error occurred while adding tasks in task scheduler."
		EXIT(1)
	}
}

#------------------------------------------------------------------------
#function for Checking if server is Active directory
#------------------------------------------------------------------------
function CheckAD()
{
    try
    {
        Get-ADForest
        return $true
    }
    catch
    {
        $global:ErrorMessage = $_
        return $false
    }
}

#------------------------------------------------------------------------
#function for Checking server
#------------------------------------------------------------------------
function CheckServer()
{
    $ServerFound = 0
	try
	{
        if(Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager")
        {
            if(Test-Path -Path "C:\Ericsson\NetAnServer\Server")
            {                
                $global:BiInstallDir = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir
		        $global:BiInstallDirLetter = "$BiInstallDir".split("\")
		        $global:LogCollectorPath = $BiInstallDirLetter[0]
                $global:BIFound = "True"
                $global:ZipName = "EBID_NetAn_Logs_Collector"
				$global:NetAnVer = Get-ChildItem -Path C:\Ericsson\NetAnServer\Server\
				$global:Server = 6
            }
            else
            {
                $global:BiInstallDir = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir
		        $global:BiInstallDirLetter = "$BiInstallDir".split("\")
		        $global:LogCollectorPath = $BiInstallDirLetter[0]
                $global:BIFound = "True"
                $global:ZipName = "EBID_Logs_Collector"  
                $global:Server = 0				
            }
            $ServerFound = 1
        }
        elseif(Test-Path -Path "C:\Ericsson\NetAnServer\Server")
        {
            $global:ZipName = "NetAn_Logs_Collector"
            $global:LogCollectorPath = "C:"
			$ServerFound = 1
			$global:NetAnVer = Get-ChildItem -Path C:\Ericsson\NetAnServer\Server\
			$global:Server = 4
        }
        elseif(Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora")
        {
            if(!(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent"))
            {
                if(Test-Path (Get-ItemProperty -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora" -Name path).path)
                {
                    $global:BiInstallDir = (Get-ItemProperty -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora" -Name path).path
                    $global:ZipName = "EBID_Client_Logs_Collector"
                    $global:LogCollectorPath = "C:"                    
                    $global:FetchBILogs = "True"
                    $global:Server = 0					
                }   
                else
                {
                    Write-Host "`n [ERROR]: Unable to find BI Installed path" -ForegroundColor Red
                }             
            }
            else
            {
                    $global:BiInstallDir = (Get-ItemProperty -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora" -Name path).path
                    $global:ZipName = "VDA_Logs_Collector"
                    $global:LogCollectorPath = "C:"
                    $global:VDAFound = "True"
                    $global:FetchBILogs = "True"
                    $global:Server = 3                    
            }
            $ServerFound = 1            
        }  
        elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent")
        {
		    if(Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora")
            {
              $global:BiInstallDir = (Get-ItemProperty -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora" -Name path).path
			  $global:FetchBILogs = "True"
		    }
		    else
            {
              "`n Unable to find BI Installed path" >> $global:LogFile
            }
            $global:ZipName = "VDA_Logs_Collector"
            $global:LogCollectorPath = "C:"
            $global:VDAFound = "True"
            $global:Server = 3   
            $ServerFound = 1 			  
        }
        elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Desktop Delivery Controller")
        {   
            if(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Desktop Delivery Controller' -Name InstallDir).InstallDir)
            {
                $global:ZipName = "CCS_Logs_Collector"
                $global:LogCollectorPath = "C:"
                $global:CCSFound = "True"
				$global:Server = 2
            }
            elseif(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Virtual Desktop Agent' -Name InstallDir).InstallDir)
            {
                $global:ZipName = "VDA_Logs_Collector"
                $global:LogCollectorPath = "C:"
                $global:VDAFound = "True"
				$global:Server = 3
            }    		                
            $ServerFound = 1
        }
        
        if($ServerFound -ne 1)
        {
            $CheckADServer = CheckAD
            if($CheckADServer)
            {                
                $global:ZipName = "AD_Logs_Collector"
                $global:LogCollectorPath = "C:"
                $global:ADFound = "True"
				$global:Server = 1
            }
            else
            {
                $ErrorMessage
                Write-Host "Unable recognize server" -ForegroundColor Red
                exit
            }
        }        		 
	}
	catch
	{
		$_  >>$global:LogFile
		Write-Host "Error occurred while checking for the type of server."
		EXIT(1)
	}
}

#------------------------------------------------------------------------
#Function for Checking logged user according to server
#------------------------------------------------------------------------
function CheckLoggedUser
{
try
{
	if($global:Server -eq 0)
	{
	  $user = [Environment]::UserName
	  if ($user -ne "Administrator")
      {
        "Current user is not Administrator.Log in as Administrator to execute the script!!!!">> $global:LogFile
		Write-Host "Sign out and login as administrator to continue the script."
		EXIT (1)
      }
	  else
	  {
		"Administrator has logged into the server.">> $global:LogFile
	  }
	}
	elseif(($global:Server -ge 1) -and ($global:Server -le 3))
	{
	    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	    $windowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($user)
	  if (!$windowsPrincipal.IsInRole("Domain Admins")) 
      {
        "Current user is not Domain Administrator.Log in as Domain Administrator to execute the script!!!!">> $global:LogFile
		Write-Host "Sign out and login as domain administrator to continue the script."
		EXIT (1)
      }
	  else
	  {
		"Domain Administrator has logged into the server.">> $global:LogFile
	  }
	}
	elseif($global:Server -eq 4)
	{
		
	   $user = [Environment]::UserName
	  if ($user -ne "Administrator") 
      {
        "Current user is not Administrator.Log in as Administrator to execute the script!!!!">> $global:LogFile
		Write-Host "Sign out and login as administrator to continue the script."
		EXIT (1)
      }
	  else
	  {
		"Administrator has logged into the server.">> $global:LogFile
	  }
	}
	elseif($global:Server -eq 6)
	{
	  $user = [Environment]::UserName
	  if ($user -ne "Administrator")
      {
        "Current user is not Administrator.Log in as Administrator to execute the script!!!!">> $global:LogFile
		Write-Host "Sign out and login as administrator to continue the script."
		EXIT (1)
      }
	  else
	  {
		"Administrator has logged into the server.">> $global:LogFile
	  }
	}
}
catch
{
    $_ >>$global:LogFile
	Write-Host  "Error occurred while checking for logged in user."
	EXIT(1)
}
}

#MAIN
$global:NetAnVer = $null
CheckServer
$TimeStamp=get-date -format yyyy-MM-dd_HH_mm_ss

CreateLogFolder

### Variables for creating task in task schduler
$StartDateForDataCollector = (Get-Date).AddDays(7).ToString("MM/dd/yyyy")
$StartTimeForDataCollector = (Get-Date).ToString("HH:mm")
$powershellVar = "powershell "
$Action = $powershellVar + "C:\Server_logs_collector\logs_collector.ps1"

### Checking if COnfiguration file is present or not in the C:\logs_collector
$InputFile = "C:\Server_logs_collector\logs_collector.ini"

if($args.Count -gt 1)
    {
        "`n [ERROR]: Only one argument should be given when running the script. Please use ApplicationLogs,SecurityLogs or All arguments and try running the script." >>$global:LogFile
		Write-Host "Only one argument should be given when running the script. Please use ApplicationLogs,SecurityLogs or All  arguments and try running the script."
        EXIT(1)
		
		}
    
if($args -eq "ApplicationLogs" -or $args -eq "All" -or $args -eq "SecurityLogs")
{

if(Test-Path $InputFile)
{
    "`nThe required configuration file 'Logs_Collector.iniLogs_Collector.ini' for fetching log directories is found" >>$global:LogFile
    Write-Host "`n Collection of log files started"
}
else
{
   Write-Host "`n[ ERROR ] : The required configuration file 'Logs_Collector.ini' for fetching log files is not found in C:\Logs_Collector" -ForegroundColor Red
   exit
}}

CheckLoggedUser

    #------------------------------------------------------------------------
    #Checking if user has given correct argument or not
    #------------------------------------------------------------------------
    if($args.Count -lt 1)
    {
        "`n [ERROR]: No arguments are given when running the script. Please use anyone of the following arguments to run the script ApplicationLogs,SecurityLogs or All ." >>$global:LogFile 
		Write-Host "No arguments are given when running the script. Please use anyone of the following arguments to run the script ApplicationLogs,SecurityLogs or All."
        EXIT(1)
    }
    elseif($args.Count -gt 1)
    {
        "`n [ERROR]: Only one argument should be given when running the script. Please use ApplicationLogs,SecurityLogs or All arguments and try running the script." >>$global:LogFile
		Write-Host "Only one argument should be given when running the script. Please use ApplicationLogs,SecurityLogs or All  arguments and try running the script."
        EXIT(1)
    }
	
	 if(($args -ne "ApplicationLogs") -AND ($args -ne "SecurityLogs") -AND ($args -ne "All"))
    {
        "`n [ERROR]: $args is an Invalid argument. ApplicationLogs,SecurityLogs and All are valid arguments" >>$global:LogFile
		Write-Host "$args is an Invalid argument. ApplicationLogs,SecurityLogs and All are valid arguments"
        EXIT(1)
    }
    else
    {
        "`n Script is running with $args argument" >>$global:LogFile
    }
	
	if($args -eq "ApplicationLogs")
	{
	  readParameter_application_logs
	}
	elseif($args -eq "SecurityLogs")
	{
	  readParameter_security_logs 
	  
	}
	else
	{
	  readParameter_application_logs
	  readParameter_security_logs
	}
	
if($args -eq "SecurityLogs" -or $args -eq "All")
{
AuditLogs
FirewallLogs

}
    
	if($args -eq "ApplicationLogs" -or $args -eq "All")
{CertificateExpiryLogs
HardeningLogs

}
#$LogretentionValue = 8
if($FetchBILogs -eq "True")
{  
  if($args -eq "ApplicationLogs"  -or $args -eq "All")
  {     
    CopyBiLog
    CopyInventoryFile
	
  }
}

if($BIFound -eq "True" -and $args -eq "ApplicationLogs") 
{
    CopyBiLog
    CopyInventoryFile
    CopyTomcatLogs
	CopyBIInstallDataLogs

}

if($BIFound -eq "True" -and $args -eq "All") 
{
    CopyBiLog
    CopyInventoryFile
    CopyTomcatLogs
	CopyBIInstallDataLogs
	
    
}
elseif($CCSFound -eq "True")
{
  if($args -eq "ApplicationLogs"  -or $args -eq "All")
  {
    CopyCCSinstallationLog
    CopyCCSupgradeLog 
  }
}
elseif($VDAFound -eq "True")
{
   if($args -eq "ApplicationLogs" -or $args -eq "All")
   {
      CopyVDAinstallationLog
      CopyVDAupgradeLog
   }
}
#Add-TasksInTaskScheduler
Get-IPAddress
Install-NFS
NFS-Share
ZipLogFolder 