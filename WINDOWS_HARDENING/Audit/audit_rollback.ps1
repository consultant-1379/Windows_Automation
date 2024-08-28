function CheckAD()
{
    try
    {
        Get-ADForest
        return $true
    }
    catch
    {
        $_ >>$script:log
        return $false
    }
}

#-----------------------------------------------------
# Check if logged user is BIS Admin or Not
#-----------------------------------------------------

function CheckBISAdmin()
{
    $CheckUser = ${Env:userprofile}
    if($CheckUser -match "Administrator")
    {
		$script:AdminCheck = $true
    }
    else
    {        
        $script:AdminCheck = $false
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
        $script:AdminCheck = $true
    } 
    else 
    {    
        $script:AdminCheck = $false
    } 
}

Function Check-TasksInTaskScheduler ($currentTask) {

    try {
        $schedule = new-object -com("Schedule.Service")
        $schedule.connect()
        $tasks = $schedule.getfolder("\").gettasks(0)
        foreach ($t in $tasks){
            $taskName=$t.Name
            if(($taskName -eq $currentTask)){
             return $true
            }
        }
     } catch {
       $errorMessage = $_.Exception.Message
	   $errorMessage >> $log
       "Check Tasks in task scheduler Failed" >> $log
       return $False
     }
}



                                                            ###MAIN###
$TimeStamp = Get-Date -format yyyy-MM-dd_HH_mm_ss
$script:log = "C:\Audit\Audit_rollback_log_$TimeStamp.log"

if(Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager')
	   {
          if(Test-Path –Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir)
          {                           
             "The current server is BO server">>$log
			 CheckBISAdmin
             $folder_path = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir
          }
	      else
	      {
	        continue
	      }
       }
       elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent") {

        CheckDomainAdministrator
        "The current server is OCS-VDA server">>$log
        $folder_path = "C:\Program Files (x86)\Citrix"

        } elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Desktop Delivery Controller") {
        CheckDomainAdministrator
        "The current server is OCS-CCS server">>$log
        $folder_path = "C:\Program Files (x86)\Citrix"

        } 
		elseif(Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora")
	   {
			if(Test-Path –Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora' -Name path).path)
			{                           
             "The current server is OCS without Citrix server with BO Client installed">>$log
			 CheckBISAdmin
             $folder_path = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora' -Name path).path
          }
	      else
	      {
	        continue
	      }
	   }
		elseif(CheckAD) {
		CheckDomainAdministrator
        "The current server is OCS-ADDS server">>$log
        $folder_path = ""

        } 
		
		else {
            Write-host "Server type not found."
             "Server type not found." >> $log
             Exit(1)


        }

if($script:AdminCheck){
	"Logged User is Administrator" >> $log
}
else{
	Write-Host "Logged user is Not Administrator and exiting from script" -ForegroundColor Red
	"Logged user is Not Administrator and exiting from script" >> $log
	Exit
}

try {

$script:User = "Everyone"
$script:Rules = "FullControl"
$script:InheritType = "ContainerInherit,ObjectInherit"
$script:AuditType = "Success,Failure"
auditpol /set /category:"Logon/Logoff" /failure:disable /success:disable >> $log
auditpol /set /subcategory:"Security State Change","Authentication Policy Change","User Account Management","Computer Account Management","Security Group Management" /success:disable /failure:disable *>> $log
##Enabling network logging
    

Set-NetFirewallProfile -name domain -LogMaxSizeKilobytes 6144 -LogAllowed false -LogBlocked false -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\Pfirewall.log" *>> $log
Set-NetFirewallProfile -name public -LogMaxSizeKilobytes 6144 -LogAllowed false -LogBlocked false -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\Pfirewall.log" *>> $log
Set-NetFirewallProfile -name private -LogMaxSizeKilobytes 6144 -LogAllowed false -LogBlocked false -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\Pfirewall.log" *>> $log
$isTaskExistOld = Check-TasksInTaskScheduler "Audit_logs"
if ($isTaskExistOld) {
	"Old Audit_logs task exist, hence deleting it." >> $log	
	schtasks /delete /tn "Audit_logs" /f >> $log
}
if($folder_path) {
$acl = Get-Acl $folder_path

$AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($user,$Rules,$InheritType,"None",$AuditType)
$acl.RemoveAuditRule($AccessRule) *>> $log

$acl | Set-Acl $folder_path


###Audit policy rollback###

auditpol /set /subcategory:"File Share","File System","Certification Services","Application Generated" /success:disable /failure:disable >> $log

}

Write-Host "Disabling of audit log is successful"

} catch {

     $_ >> $log
        Exit(1)

}

