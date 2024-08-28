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


#Logging message in log file
function log($logmessage) {
   $TimeStamp = Get-Date -format yyyy-MM-dd_HH_mm_ss
   $TimeStamp + " : " + $logmessage | out-file -Filepath $log -append -Force
}



################ MAIN ###################
$TimeStamp = Get-Date -format yyyy-MM-dd_HH_mm_ss
$script:log = "C:\Audit\Audit_log_$TimeStamp.log"

$size = (Get-Content "C:\Audit\audit_config.ini" | Where-Object {$_ -like "*directorysize*" }).Split("=")[1].trim()
if ($size -eq $null -or $size -eq "" -or $size -notmatch "^[\d\.]+$" -or $size -le 0) {
   Write-host "Enter valid value for variable directorysize in C:\Audit\audit_config.ini and execute script again"
   Exit(1)
}


if (!(test-path C:\Audit\network_logs )) {
    New-Item -ItemType directory -Path C:\Audit\network_logs *>> $log
    if($?) {
        "Created directory network_logs" *>> $log
    } else {
        Error_handling "Error found in creating System_Events directory"
}
}

##Enabling auditpolicy
try {auditpol /set /category:"Logon/Logoff" /failure:enable /success:enable >> $log


auditpol /set /subcategory:"File Share","File System","Certification Services","Application Generated" /success:enable /failure:enable *>> $log

auditpol /set /subcategory:"Security State Change","Authentication Policy Change","User Account Management","Computer Account Management","Security Group Management" /failure:disable /success:enable >> $log
    log "Audit policy updated successfully"
    } catch {
    log "Updating Audit policy failed."
    Exit(1)
      }

##Enabling network logging
    

Set-NetFirewallProfile -name domain -LogMaxSizeKilobytes 6144 -LogAllowed true -LogBlocked true -LogFileName "C:\Audit\network_logs\domain_logs.txt"
Set-NetFirewallProfile -name public -LogMaxSizeKilobytes 6144 -LogAllowed true -LogBlocked true -LogFileName "C:\Audit\network_logs\public_logs.txt"
Set-NetFirewallProfile -name private -LogMaxSizeKilobytes 6144 -LogAllowed true -LogBlocked true -LogFileName "C:\Audit\network_logs\private_logs.txt"



if(Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager')
	   {
          if(Test-Path –Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir)
          {  
             
             
             "The current server is BO server">>$log
             $folder_path = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir
          }
	      else
	      {
	        continue
	      }
       }
       elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent") {

        
        "The current server is OCS-VDA server">>$log
        $folder_path = @("C:\Program Files (x86)\Citrix","C:\Program Files\Citrix")

        } elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Desktop Delivery Controller") {
        
        "The current server is OCS-CCS server">>$log
        $folder_path = @("C:\Program Files (x86)\Citrix","C:\Program Files\Citrix")

        } 
		elseif(Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora')
		{
			if(Test-Path -Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora' -Name path).path)
			{
				"The current server is OCS without Citrix server with BO Client Installed" >>$log
				$folder_path = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora' -Name path).path
			}
			else
			{
				continue
			}	
		}
		elseif(CheckAD) {
        "The current server is OCS-ADDS server">>$log
        $folder_path = ""

        } 
		
		else {
            Write-host "Server type not found."
             "Server type not found." >> $log
             Exit(1)


        }

if($folder_path) {
foreach ($folder in $folder_path) {
$script:User = "Everyone"
$script:Rules = "FullControl"
$script:InheritType = "ContainerInherit,ObjectInherit"
$script:AuditType = "Success,Failure"

try
    {   log "Setting Audit Rules on $folder"
        write-host "Setting Audit Rules on $folder"
        $ACL = $folder | Get-Acl -Audit -ErrorAction Stop
            if((Get-Item $folder) -is [System.IO.DirectoryInfo]) {
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($user,$Rules,$InheritType,"None",$AuditType)
            } else {
                $AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($user,$Rules,$AuditType)
               }
        $ACL.SetAuditRule($AccessRule)
        $ACL | Set-Acl $Folder -ErrorAction Stop
        
        log " Audit Rules set on $folder"

        
    }
    catch
    {
        $errorMessage = $_.Exception.Message
			$errorMessage >> $log
        Exit(1)
    }
}

}
#Creating task in task scheduler

       try
       { 
                 
       $oldtask = Get-ScheduledTask
        if ($oldtask.taskname -contains "Audit_logs") { 
			"Old Audit_logs task exists." >> $log
		} else {			
		    schtasks /create /ru system /sc daily /tn "Audit_logs" /tr "powershell C:\Audit\audit.ps1" /st 00:04 /rl highest *>>$log
            "Audit_logs task created." >> $log
		}
       }
    catch
    {
        $errorMessage = $_.Exception.Message
			$errorMessage >> $log
        Exit(1)
    }

    Write-host "Audit policy updated successfully."

