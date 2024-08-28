# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2022 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ************************************************************************
# Name     		: CCS_LegalNotice.ps1
# Purpose  		: Automation of legal notice configuration on the Citrix StoreFront login page
# Last Updated	: 26-Nov-2021
# *************************************************************************




#------------------------------------------------
#Function for Error handling
#------------------------------------------------
function Error_handle ($usermessage) {
    Read-host $usermessage
    Exit(1)
}

#------------------------------------------------
# Function to print date and time in log file
#------------------------------------------------
function PrintDateTime()
{    
    "-----------------------------------------------" >>$Log
    Get-Date -Format "dddd [MM/dd/yyyy] [HH:mm:ss]" >>$Log
    "-----------------------------------------------" >>$Log
}

#------------------------------------------------
# Function to print date and time in log file for each entry
#------------------------------------------------
function log($logmessage) {
   $TimeStamp = Get-Date -format yyyy-MM-dd_HH_mm_ss
   $TimeStamp + " : " + $logmessage | out-file -Filepath $Log -append -Force
}

#------------------------------------------------
# Function to create folder to backup script.js and style.css files
#------------------------------------------------
function CreateFolder()
{
	try
	{
		New-Item -Path "$SourcePath" -Name "$DirectoryName" -ItemType "directory" -Force | Out-Null
	}
	catch
	{
		log "Error, Could not create $DirectoryName folder"
		Error_handle "Error, Could not create $DirectoryName folder"
	}
}

#------------------------------------------------
# Function to backup $DestinationFile1 & $DestinationFile2
#------------------------------------------------
function CopyFiles()
{
	try
	{
		Copy-Item $DestinationFile1 -Destination $SourcePath\$DirectoryName -Force
		Copy-Item $DestinationFile2 -Destination $SourcePath\$DirectoryName -Force
	}
	catch
	{
		log "Error, Could not copy files to $SourcePath"
		Error_handle "Error, Could not copy files to $SourcePath"
	}
}

#------------------------------------------------
# Function to update customized Legal Notice
#------------------------------------------------
function LegalNotice()
{
	Get-Content -Path "$SourceFile1" | Add-Content -Path "$DestinationFile1"
	Get-Content -Path "$SourceFile2" | Add-Content -Path "$DestinationFile2"
}


#************************************************
# MAIN
#************************************************
$DirectoryName = "Files_BackUp"
$DestinationFile1 = "C:\inetpub\wwwroot\Citrix\StoreNameWeb\custom\script.js"
$DestinationFile2 = "C:\inetpub\wwwroot\Citrix\StoreNameWeb\custom\style.css"
$Log = "C:\OCS\LegalNotice\CCS_LegalNotice_log.log"
$SourcePath = "C:\OCS\LegalNotice"
$SourceFile1 = "C:\OCS\LegalNotice\custom_script.ini"
$SourceFile2 = "C:\OCS\LegalNotice\custom_style.ini"


PrintDateTime

#------------------------------------------------
# Check for $SourceFile1 availability
#------------------------------------------------
if((Test-path -Path "$SourceFile1") -eq $true)
{
    log "custom_script.ini file is present in $SourcePath"
}
else
{
    Write-Host "custom_script.ini file is not copied from WINDOWS HARDENING Media. Copy custom_script.ini file from WINDOWS HARDENING Media to $SourcePath"
	log "custom_script.ini file is not copied from WINDOWS HARDENING Media. Copy custom_script.ini file from WINDOWS HARDENING Media to $SourcePath"
    Exit(1)
}

#------------------------------------------------
# Check for $SourceFile2 availability
#------------------------------------------------
if((Test-path -Path "$SourceFile2") -eq $true)
{
    log "custom_style.ini file is present in $SourcePath"
}
else
{
    Write-Host "custom_style.ini file is not copied from WINDOWS HARDENING Media. Copy custom_style.ini file from WINDOWS HARDENING Media to $SourcePath"
	log "custom_style.ini file is not copied from WINDOWS HARDENING Media. Copy custom_style.ini file from WINDOWS HARDENING Media to $SourcePath"
    Exit(1)
}

log "Creating/Updating customized Legal Notice"
$customized=(Select-String -Path $DestinationFile1 -SimpleMatch "customAuthBottom")
if($customized)
{
	log "Customized Legal Notice already applied."
	Write-Host "Customized Legal Notice already applied."
}
else
{
	CreateFolder
	CopyFiles
	LegalNotice
	$customized_js=(Select-String -Path $DestinationFile1 -SimpleMatch "customAuthBottom")
	$customized_css=(Select-String -Path $DestinationFile2 -SimpleMatch "customAuthBottom")
	if(($customized_js) -AND ($customized_css))
	{
		log "Customized Legal Notice applied successfully."
		Write-Host "Customized Legal Notice applied successfully."
	}
	else
	{
		log "Error, Could not apply customized Legal Notice."
        Error_handle "Error, Could not apply customized Legal Notice. Press enter to exit code"
	}
}


