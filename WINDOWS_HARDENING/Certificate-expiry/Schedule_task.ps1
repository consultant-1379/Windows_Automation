
#   (c) Ericsson Radio Systems AB 2020 - All rights reserved.
#   The copyright to the computer program(s) herein is the property
#   The copyright to the computer program(s) herein is the property
# 	and/or copied only with the written permission from Ericsson Radio
# 	Systems AB or in accordance with the terms and conditions stipulated
# 	in the agreement/contract under which the program(s) have been
# 	supplied.
#
# ********************************************************************
#	Name    : Schedule_task.ps1
# 	Date    : 04/06/2020
# 	Purpose : This script is used to create a scheduled task for 
#             the certificate expiry script and makes it run in            
#             the background when user logs in.   	
#
# 	Usage   : Schedule_task.ps1- creates the certificate expiry script into a scheduled task

# ********************************************************************************************************************************************
# ------------------------------------------------------   SUB  FUNCTIONS   ---------------------------------------------------------------
# ********************************************************************************************************************************************


# ********************************************************************
# Configure the task to run script whenever the user logs in
# ********************************************************************

function configure_TaskScheduler
{
try
{
		$statusUpdate = add_Tasks_In_TaskScheduler 
        if ($statusUpdate) {
            $timestamp+"  Certificate expiry notification and Certificate expiry check tasks have been scheduled successfully." >> $logfile
            Write-Host "Certificate expiry notification and certificate expiry check tasks have been scheduled successfully."
			if($server_Type -ge 1 -OR $NetAn_Server -eq 1)
			{
				return "success"
			}
        }
        else
         {
            $timestamp+"  Certificate expiry notification and Certificate expiry check tasks couldn't be scheduled" >> $logfile
            Write-Host "Certificate expiry notification and Certificate expiry check tasks couldn't be scheduled.For more details check logs in C:\Certificate-expiry\log\Schedule_Task.log" 
         }
         EXIT(1)
    }
   catch
   {
       $errorMessage = $_.Exception.Message
	   $errorMessage >> $logfile
       $timestamp+"  Configuring Tasks in task scheduler Failed" >> $logfile
        Write-Host "Configuring the tasks in Task scheduler failed..For more details check logs in C:\Certificate-expiry\log\Schedule_Task.log"
        }   
}

# ********************************************************************
# Check if task is already present in task scheduler
# ********************************************************************

function check_Tasks_In_TaskScheduler ($currentTask) 
{
    try 
    {
        $isTaskFound=$false
        $schedule = new-object -com("Schedule.Service")
        $schedule.connect()
        $tasks = $schedule.getfolder("\").gettasks(0)
        foreach ($t in $tasks)
       	{
            $taskName=$t.Name
            if(($taskName -eq $currentTask)){
             return $true
            }
        }
       return $isTaskFound
     } 
     catch 
     {
       $errorMessage = $_.Exception.Message
	   $errorMessage >> $logfile
       $timestamp+"  Check Tasks in task scheduler Failed" >> $logfile
        Write-Host "Certificate expiry notification and Certificate expiry check tasks couldn't be scheduled.For more details check logs in C:\Certificate-expiry\log\Schedule_Task.log" 
		return $False
       EXIT(1)
     }
}

# ********************************************************************
# Add task in task scheduler
# ********************************************************************

function add_Tasks_In_TaskScheduler
{
    try 
    {
			$isTaskExistOld = check_Tasks_In_TaskScheduler $login_task			
			if(!$isTaskExistOld){			
			schtasks /create /sc ONLOGON  /tn 'Certificate_Expiry_Notification' /tr 'powershell -windowstyle hidden C:\Certificate-expiry\Certificate_expiry_notifier.ps1' /rl highest >> $LogFile
			}			
			$isTaskExist = check_Tasks_In_TaskScheduler $dailytask
			if(!$isTaskExist -AND ($server_Type -ge 0)){
			     $testActionNew = New-ScheduledTaskAction -Execute 'powershell.exe'  -Argument 'C:\Certificate-expiry\Certificate_expiry_check.ps1' 
                 $testTriggerNew = New-ScheduledTaskTrigger -At 11:30PM -Daily
				 $testTriggerNew.StartBoundary = [DateTime]::Parse($testTriggerNew.StartBoundary).ToLocalTime().ToString("s")
                 $testSettingsNew = New-ScheduledTaskSettingsSet -Compatibility Win8
                 $userSystem="NT AUTHORITY\SYSTEM"
			     Register-ScheduledTask -TaskName 'Certificate_Expiry_Check' -Action $testActionNew -Trigger $testTriggerNew -Settings $testSettingsNew -User $userSystem -RunLevel Highest
			}
			$isTaskExist_NetAn = check_Tasks_In_TaskScheduler $netAnCheckTask
			if(!$isTaskExist_NetAn -AND ($NetAn_Server -eq 1 -OR $server_Type -eq 2)){
			     $testActionNew_Net = New-ScheduledTaskAction -Execute 'powershell.exe'  -Argument 'C:\Certificate-expiry\Certificate_expiry_check_NetAn.ps1' 
                 $testTriggerNew_Net = New-ScheduledTaskTrigger -At 11:32PM -Daily
				 $testTriggerNew_Net.StartBoundary = [DateTime]::Parse($testTriggerNew_Net.StartBoundary).ToLocalTime().ToString("s")
                 $testSettingsNew_Net = New-ScheduledTaskSettingsSet -Compatibility Win8
                 $userSystem="NT AUTHORITY\SYSTEM"
			     Register-ScheduledTask -TaskName 'Certificate_Expiry_Check_NetAn' -Action $testActionNew_Net -Trigger $testTriggerNew_Net -Settings $testSettingsNew_Net -User $userSystem -RunLevel Highest
			}
		return $true
    }
    catch 
    {
        $errorMessage = $_.Exception.Message
		$errorMessage >> $logfile
        $timestamp+"  Error Adding Tasks in task scheduler" >> $logfile
        return $False
    }
}

 function check_ServerType()
 {
       if(Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager')
       {
		   $bi_install_dir=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir
           if(Test-Path –Path "$bi_install_dir")
           {  
             $server_Type=1
           }
		   if(Test-Path -Path "C:\Ericsson\NetAnServer\Server")
		   {
			 $server_Type=2
		   }
           
        }
		elseif(Test-Path -Path "C:\Ericsson\NetAnServer\Server"){
			$NetAn_Server=1
		}
		elseif((Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora') -AND (!(Test-Path -Path 'HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent')))
		{
			if(Test-Path -Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora' -Name path).path)
			{
				$server_Type=1
			}
		}																					
        else
        {
          $server_Type=0
        }
   return $server_Type,$NetAn_Server
 }
   

# **************************************************************************************************************************************
# ------------------------------------------------------- MAIN  FUNCTION ---------------------------------------------------------------
# **************************************************************************************************************************************

     New-Item -ItemType Directory -Path C:\Certificate-expiry\log -erroraction 'silentlycontinue' | out-null
	 $login_task = "Certificate_Expiry_Notification"
	 $dailytask = "Certificate_Expiry_Check"
	 $netAnCheckTask = "Certificate_Expiry_Check_NetAn"
    $server_Type,$NetAn_Server = check_ServerType
    if($server_Type -ge 1 -OR $NetAn_Server -eq 1)
    {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent();	    
	    $permission = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        if($permission)
        {
         $acl= New-Object System.Security.AccessControl.DirectorySecurity
         $acl.SetAccessRuleProtection($True, $True)
         $rule1=New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
         $rule2=New-Object System.Security.AccessControl.FileSystemAccessRule("System","FullControl","ContainerInherit,ObjectInherit","None","Allow")
         $acl.SetAccessRule($rule1)
         $acl.AddAccessRule($rule2)
         $acl | Set-Acl -Path C:\Certificate-expiry\config_file.ini
        }
        else
        {
            [void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")
	        [Microsoft.VisualBasic.Interaction]::MsgBox("Log in as Administrator to run the script.", "OKOnly,SystemModal,Information", "Information")
		    EXIT (1)  
        }
     }
     else
     {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	    $windowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($user)
	    $permission=$windowsPrincipal.IsInRole("Domain Admins")
        if($permission)
        {
          $acl= New-Object System.Security.AccessControl.DirectorySecurity
          $acl.SetAccessRuleProtection($True, $True)
          $rule1=New-Object System.Security.AccessControl.FileSystemAccessRule("$(whoami)","FullControl","ContainerInherit,ObjectInherit","None","Allow")
          $rule2=New-Object System.Security.AccessControl.FileSystemAccessRule("System","FullControl","ContainerInherit,ObjectInherit","None","Allow")
          $acl.SetAccessRule($rule1)
          $acl.AddAccessRule($rule2)
	      $acl | Set-Acl -Path C:\Certificate-expiry\config_file.ini
        }
        else
        {
           [void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")
	       [Microsoft.VisualBasic.Interaction]::MsgBox("Log in as Domain Administrator to run the script.", "OKOnly,SystemModal,Information", "Information")
		   EXIT (1)  
        }
      }
      $timestamp = Get-date -Format yyyy-MM-dd_HH_mm_ss
      $acl | Set-Acl -Path C:\Certificate-expiry\log
      try
      {
            if(!(Test-Path C:\Certificate-expiry\log\schedule_Task.log -PathType Leaf))
	        {
	            New-Item -ItemType File -Path C:\Certificate-expiry\log -Name schedule_Task.log 
	        }
            else
            {
             "Log file for scheduling the task is created already">>$logfile
            }
        }
         catch
       {
        Write-Host "Error occured while creating the log file"
        EXIT(1)
       }
     $logfile="C:\Certificate-expiry\log\schedule_Task.log"
     configure_TaskScheduler
 
