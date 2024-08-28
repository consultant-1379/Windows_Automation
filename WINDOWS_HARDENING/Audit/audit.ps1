
#Log
function log($logmessage) {
   $TimeStamp = Get-Date -format yyyy-MM-dd_HH_mm_ss
   $TimeStamp + " : " + $logmessage | out-file -Filepath $Log -append -Force
}

#Error message
function Error_handling ($usermessage) {
    Write-host $usermessage
    log $usermessage
    Exit(1)
}

Function Get-WinEventData {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0 )]
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]
        $event
    )

    Process
    {
        
        foreach($entry in $event)
        {
            
            $XML = [xml]$entry.ToXml()
        
            
            $XMLData = $null
            if( $XMLData = @( $XML.Event.EventData.Data ) )
            {
                For( $i=0; $i -lt $XMLData.count; $i++ )
                {
                    
                    Add-Member -InputObject $entry -MemberType NoteProperty -name "EventData$($XMLData[$i].name)" -Value $XMLData[$i].'#text' -Force
                }
            }
            
            $entry
        }
    }
}

#-----------------------------------------------------
# Check if logged user is BIS Admin or Not
#-----------------------------------------------------

function CheckBISAdmin()
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
	$Value = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if($Value)
    {
        "`n Logged user is Administrator" *>> $log        
    }
    else
    {        
        "`n Logged user is not Administrator. Please logon as Administrator and run the script for firewall settings" *>> $log 
		Write-Host	"`n Logged user is not Administrator. Please logon as Administrator and run the script for firewall settings"
        exit
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
        "`n Logged on user is Domain Administrator" *>> $log
    } 
    else 
    {    
        Write-Host "`n Logged on user is not Domain Administrator and exiting from script" 
        "`n Logged on user is not Domain Administrator and exiting from script" *>> $log
        exit
    } 
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
        $global:ErrorMessage = $_
        return $false
    }
}

#----------------------------------------------------------
# Checking the server configuration 
#----------------------------------------------------------

function CheckServer()
{
	$Script:BISServer = $False
	$Script:OCSServer = $False
	$Script:NetAnServer = $False    
	$Script:OCSwithoutCitrixServer = $False							   
    if(Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4*\config Manager")
    {
		if(Test-Path -Path "HKLM:\SOFTWARE\WOW6432Node\TIBCO\Spotfire Node Manager\7.11.0")
		{
			"It's a Co-Deployed (BIS and NetAn) server" *>> $log
			CheckBISAdmin	
			$Script:NetAnServer = $True
			$Script:BISServer = $True
		}
		else
		{
			"It's a BIS server" *>> $log
			CheckBISAdmin        
			$Script:BISServer = $True
		}      		
    }
	elseif(Test-Path -Path "HKLM:\SOFTWARE\WOW6432Node\TIBCO\Spotfire Node Manager\7.11.0")
    {
		"It's a NetAn server" *>> $log
        CheckBISAdmin	
		$Script:NetAnServer = $True
    }
    elseif((Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent") -AND (Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora"))
    {
        "It's VDA server with BO Client installed" *>> $log
        CheckDomainAdministrator
        $Script:OCSServer = $True
    }
    elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Desktop Delivery Controller")
    {   
        if(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Desktop Delivery Controller' -Name InstallDir).InstallDir)
        {
            "It's CCS server" *>> $log
        }
        elseif(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Virtual Desktop Agent' -Name InstallDir).InstallDir)
        {
            "It's VDA server" *>> $log
        }    	
        CheckDomainAdministrator	                
        $Script:OCSServer = $True
    }
    elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent")
    {
        if(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Virtual Desktop Agent' -Name InstallDir).InstallDir)
        {
            "It's VDA server without BO Client installed" *>> $log
            CheckDomainAdministrator
            $Script:OCSServer = $True
        }
    }
	elseif(Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora")
	{
		"It's OCS without Citrix Server with BO Client installed" >> $log
		CheckBISAdmin
		$Script:OCSwithoutCitrixServer = $True
	}

    if(($Script:BISServer -ne $True) -AND ($Script:OCSServer -ne $True) -AND ($Script:NetAnServer -ne $True) -AND ($Script:OCSwithoutCitrixServer -ne $True))
    {
        $CheckADServer = CheckAD        
        if($CheckADServer)
        {                
            "It's An AD server" *>> $log
            $OCSServer = $True         
        }
        else
        {
            $_ *>> $log
            Write-Host "`n Unable to recognize server" -ForegroundColor Red
            exit
        }
    }
}
#Main

$script:log = "C:\Audit\temp\Audit.log"
$time_stamp=Get-Date -format yyyy-MM-dd_HH_mm_ss
$date = (Get-date).AddDays(-1)
if (!(test-path C:\Audit\temp )) {
    New-Item -ItemType directory -Path C:\Audit\temp | Out-Null
    
}
CheckServer
if (!(test-path C:\Audit\temp\System_Events )) {
    New-Item -ItemType directory -Path C:\Audit\temp\System_Events *>> $log
    if($?) {
        "Created directory System_Events" *>> $log
    } else {
        Error_handling "Error found in creating System_Events directory"
}

}

if (!(test-path C:\Audit\temp\User_Events )) {
    New-Item -ItemType directory -Path C:\Audit\temp\User_Events *>> $log
    if($?) {
        "Created directory User_Events" *>> $log
    } else {
        Error_handling "Error found in creating User_Events directory"
}

}

if (!(test-path C:\Audit\temp\systemfile_Events )) {
    New-Item -ItemType directory -Path C:\Audit\temp\systemfile_Events *>> $log
    if($?) {
        "Created directory systemfile_Events" *>> $log
    } else {
        Error_handling "Error found in creating systemfile_Events directory"
}

}
if($Script:BISServer -eq $True)
{
	if(!(test-path C:\Audit\temp\BIS_Application_Events ))
	{
		New-Item -ItemType directory -Path C:\Audit\temp\BIS_Application_Events *>> $log
		if($?)
		{
			"Created directory BIS_Application_Events" *>> $log
			powershell C:\Audit\BIS_Audit_Application.ps1
		}
		else {
        Error_handling "Error found in creating systemfile_Events directory"
		}
	}
}
if (!(test-path C:\audit\audit_log )) {
    New-Item -ItemType directory -Path C:\audit\audit_log *>> $log
    if($?) {
        "Created directory temp" *>> $log
    } else {
        Error_handling "Error found in creating systemfile_Events directory"
}

}

$loggingevent_id = 6005,6006,6008
$system_loggingevents_id = 4616,4718,4670,4906,4737,1102
$User_authentication_events_id = 4624,4625,4634,4648,4768,4771
$User_events_id = 4779
$filemanagement_events_id = 4656,4658,4660,4663
 
 Get-WinEvent -FilterHashtable @{Logname='security';id=$User_authentication_events_id;StartTime= $date} -ErrorAction SilentlyContinue | Get-WinEventData | Select TimeCreated, Id, @{Name='Message';Expression={ (($_.Message | Select -First 1) -Split "`n")[0] }}, EventDataTargetUserName, Eventdatalogontype, Eventdataipaddress | sort -Property EventDataTargetUserName,TimeCreated | Format-Table -wrap | out-file -Width 500 "C:\Audit\temp\User_Events\User_authentication_events_$time_stamp.txt"
 Get-WinEvent -FilterHashtable @{Logname='security';id=$User_events_id;StartTime= $date} -ErrorAction SilentlyContinue | Get-WinEventData | Select TimeCreated, Id, @{Name='Message';Expression={ (($_.Message | Select -First 1) -Split "`n")[0] }}, EventDataAccountName, EventdataClientAddress | Format-Table -wrap | out-file -Width 500 "C:\Audit\temp\User_Events\User_events_$time_stamp.txt"
 Get-WinEvent -FilterHashtable @{Logname='security';id=$filemanagement_events_id;StartTime= $date} -ErrorAction SilentlyContinue | Get-WinEventData | Select TimeCreated, Id, @{Name='Message';Expression={ (($_.Message | Select -First 1) -Split "`n")[0] }}, EventDataSubjectUserName, EventDataProcessName, EventdataObjectName | sort -Property EventDataSubjectUserName,TimeCreated | Format-Table -wrap | out-file -Width 500 "C:\Audit\temp\systemfile_Events\file_access_event_$time_stamp.txt"
 Get-WinEvent -FilterHashtable @{Logname='Security';id=$system_loggingevents_id;StartTime= $date} -ErrorAction SilentlyContinue | Format-Table -wrap | out-file -Width 500 "C:\Audit\temp\System_Events\loggingevents_$time_stamp.txt"

 ##Disabling network logging
    

Set-NetFirewallProfile -name domain -LogMaxSizeKilobytes 6144 -LogAllowed false -LogBlocked false -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\Pfirewall.log"
Set-NetFirewallProfile -name public -LogMaxSizeKilobytes 6144 -LogAllowed false -LogBlocked false -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\Pfirewall.log"
Set-NetFirewallProfile -name private -LogMaxSizeKilobytes 6144 -LogAllowed false -LogBlocked false -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\Pfirewall.log"
Copy-item -path C:\Audit\network_logs -Recurse -Destination "C:\audit\temp" *>> $log
Remove-Item -Path C:\Audit\network_logs\* *>> $log

if (!(test-path C:\Audit\network_logs )) {
    New-Item -ItemType directory -Path C:\Audit\network_logs *>> $log
    if($?) {
        "Created directory network_logs" *>> $log
    } else {
        Error_handling "Error found in creating System_Events directory"
}
}

##Enabling network logging
    

Set-NetFirewallProfile -name domain -LogMaxSizeKilobytes 6144 -LogAllowed true -LogBlocked true -LogFileName "C:\Audit\network_logs\domain_logs.txt"
Set-NetFirewallProfile -name public -LogMaxSizeKilobytes 6144 -LogAllowed true -LogBlocked true -LogFileName "C:\Audit\network_logs\public_logs.txt"
Set-NetFirewallProfile -name private -LogMaxSizeKilobytes 6144 -LogAllowed true -LogBlocked true -LogFileName "C:\Audit\network_logs\private_logs.txt"


 Compress-Archive -Path C:\Audit\temp\* -DestinationPath C:\Audit\audit_log\audit_log_$time_stamp.zip
 if($?) {

    Remove-item -Path "C:\Audit\temp" -Recurse
    } else {
        Write-host "Error found in zipping audit log directory"
        }

$dir_size = ((Get-ChildItem C:\Audit\audit_log -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1GB)

$size = (Get-Content "C:\Audit\audit_config.ini" | Where-Object {$_ -like "*directorysize*" }).Split("=")[1].trim()
if ($size -eq $null -or $size -eq "" -or $size -notmatch "^[\d\.]+$" -or $size -le 0) {
   "No valid value found in .ini file" *>> $log
   $size = 1
}
while (($dir_size) -gt $size) {
Get-ChildItem C:\Audit\audit_log | Sort CreationTime | Select -First 1 | Remove-Item
$dir_size = ((Get-ChildItem C:\Audit\audit_log -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1GB)


}