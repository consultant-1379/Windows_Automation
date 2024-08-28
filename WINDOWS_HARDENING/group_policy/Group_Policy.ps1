#*************************************************************************
#	Ericsson Radio Systems AB                                     SCRIPT
#*************************************************************************
#
#  	(c) Ericsson Radio Systems AB 2020 - All rights reserved.
#  	The copyright to the computer program(s) herein is the property
#	of Ericsson Radio Systems AB, Sweden. The programs may be used
#	and/or copied only with the written permission from Ericsson Radio
#	Systems AB or in accordance with the terms and conditions stipulated
#	in the agreement/contract under which the program(s) have been
#	supplied.
#
#*************************************************************************
#	Name    : 	Group_Policy.ps1
#	Date    : 	15/09/2020
#	Revision: 	A.1
#	Purpose : 	This powershell file is used to Enable/Disable/Re_Enable 
#               group_policy in AD server and BIS/Client/NetAn server using
#               group_policy_configuration file.  	
#
#	Usage   : 	Group_Policy.ps1
#
#*************************************************************************

#------------------------------------------------------------------------
#Print date and time in the log file
#------------------------------------------------------------------------
function PrintDateTime()
{    
    "----------------------------------------------- " >>$global:GPLogFile 
    Get-Date -Format "dddd [MM/dd/yyyy] [HH:mm:ss]" >>$global:GPLogFile
    "----------------------------------------------- " >>$global:GPLogFile      
}

#-----------------------------------------------------------------------------------
#Fetching values from configuration file and exits script if there are any errors
#-----------------------------------------------------------------------------------
function FetchValue($Arg1)
{
    try
    {
        $ParameterFound = "False"
        foreach($SourceFolder in Get-Content  $InputFile)
        {            
            If($SourceFolder -match $Arg1)
            {                                
          	   	$line_split = "$SourceFolder".split("=",2)
                $Value = $line_split[1].Trim()
                $ParameterFound = "True"
            }
        }
        if($ParameterFound -eq "True")
        {
            if($Value -eq '')
            {
                Write-Host "`n [ERROR]: $Arg1 Value is null. Please provide value as per documentation and run script again" -ForegroundColor Red
                $global:ErrorCount = $global:ErrorCount + 1
            }
            else
            {
                return $Value
            }            
        }
        else
        {
            Write-Host "`n [ERROR]: $Arg1 Parameter is missing from input file. Please add the paramater, value and run the script again" -ForegroundColor Red
            $global:ErrorCount = $global:ErrorCount + 1
        }
        
    }
    catch
    {
        $_ >>$global:GPLogFile
    }

}

#------------------------------------------------------------------------
#Function for checking whether value is integer or not
#------------------------------------------------------------------------

function IntegerCheck($arg1, $arg2)
{
    $global:IntegerCount = 0
    try
    {
        $IntegerCheck = [int]$arg1
        $global:IntegerCount = 1
    }
    catch
    {
        Write-Host "`n [ERROR]: OCS_$arg2 is not an integer value. Please make sure the value is a number" -ForegroundColor Red 
        $global:ErrorCount = $ErrorCount + 1                      
    }        
}

#------------------------------------------------------------------------
#function for reading OCS parameters
#------------------------------------------------------------------------

function readParameter()
{
    PrintDateTime
    "Read parameters from configuration file" >>$global:GPLogFile
    $global:GroupPolicyName = FetchValue "Group_Policy_Name"    
    if(($Argument -ne "Disable") -AND ($Argument -ne "Re_Enable"))
    {
        $global:PrecedenceValue1 = FetchValue "Precedence"
        
        IntegerCheck $PrecedenceValue1 "Precedence"
        if($global:IntegerCount -eq 1)
        {
            $global:PrecedenceValue = [int]$global:PrecedenceValue1
        }    

        $global:PolicyDescription = FetchValue "Description"

        $global:InputLockoutDurationValue = FetchValue "LockoutDuration"    
        IntegerCheck $InputLockoutDurationValue "LockoutDuration"    
        if($global:IntegerCount -eq 1)
        {
            $LockDurationVal = [int]$global:InputLockoutDurationValue
            if($LockDurationVal -lt 0)
            {
                Write-Host "`n [ERROR]: OCS_LockoutDuration Value should be between [0-(10675199*24*60)]" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }
            try
            {
                $global:InputLockoutDurationValue1 = [timespan]::fromminutes($global:InputLockoutDurationValue)               
            }
            catch
            {
                Write-Host "`n [ERROR]: OCS_LockoutDuration Value should be between [0-(10675199*24*60)]" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }
            $global:LockoutDurationValue = $global:InputLockoutDurationValue1.ToString("d\.hh\:mm\:ss")            
        }        
        
        $global:InputLockoutObservationWindow = FetchValue "LockoutObservationWindow"    
        IntegerCheck $InputLockoutObservationWindow "LockoutObservationWindow"
        if($global:IntegerCount -eq 1)
        {
            $LockWindowVal = [int]$global:InputLockoutObservationWindow
            if($LockWindowVal -lt 0)
            {
                Write-Host "`n [ERROR]: OCS_LockoutObservationWindow Value should be between [0-(10675199*24*60)]" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }
            try
            {
                $global:InputLockoutObservationWindow1 = [timespan]::fromminutes($global:InputLockoutObservationWindow)
            }
            catch
            {
                Write-Host "`n [ERROR]: OCS_LockoutObservationWindow Value should be between [0-(10675199*24*60)]" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }        
            $global:LockoutObservationWindow = $global:InputLockoutObservationWindow1.ToString("d\.hh\:mm\:ss")            
            if($LockWindowVal -gt $LockDurationVal)
            {
                Write-Host "`n [ERROR]: OCS_LockoutObservationWindow Value should be lessthan or equals to OCS_LockoutDuration value" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }
        }     
        
        $global:LockoutThresholdValue1 = FetchValue "LockoutThreshold"

        IntegerCheck $LockoutThresholdValue1 "LockoutThreshold"
        if($global:IntegerCount -eq 1)
        {
            $global:LockoutThresholdValue = [int]$global:LockoutThresholdValue1
            if(($global:LockoutThresholdValue -lt 0) -OR ($global:LockoutThresholdValue -gt 30))
            {
                Write-Host "`n [ERROR]: OCS_LockoutThreshold Value should be between (0-30)" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }
        }

        $global:InputMinPasswordAgeValue = FetchValue "MinPasswordAge"
        
        IntegerCheck $InputMinPasswordAgeValue "MinPasswordAge"
        if($global:IntegerCount -eq 1)
        {
            $MinAge = [int]$global:InputMinPasswordAgeValue
            if($MinAge -lt 0)
            {
                Write-Host "`n [ERROR]: OCS_MinPasswordAge Value should be between (0-10675199)" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }
            try
            {
                $global:InputMinPasswordAgeValue1 = [timespan]::fromdays($global:InputMinPasswordAgeValue)
            }
            catch
            {
                Write-Host "`n [ERROR]: OCS_MinPasswordAge Value should be between (0-10675199)" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }
            $global:MinPasswordAgeValue = $global:InputMinPasswordAgeValue1.ToString("d\.hh\:mm\:ss")            
        }
        

        $global:InputMaxPasswordAgeValue = Fetchvalue "MaxPasswordAge"
        IntegerCheck $InputMaxPasswordAgeValue "MaxPasswordAge"
        if($global:IntegerCount -eq 1)
        {
            $MaxAge = [int]$global:InputMaxPasswordAgeValue
            if($MaxAge -lt 0)
            {
                Write-Host "`n [ERROR]: OCS_MaxPasswordAge Value should be between (0-10675199)" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }
            try
            {
                $global:InputMaxPasswordAgeValue1 = [timespan]::fromdays($global:InputMaxPasswordAgeValue)
            }
            catch
            {
                Write-Host "`n [ERROR]: OCS_MaxPasswordAge Value should be between (0-10675199)" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }
            $global:MaxPasswordAgeValue = $global:InputMaxPasswordAgeValue1.ToString("d\.hh\:mm\:ss")            
        }    

        if(($MinAge) -ge ($MaxAge))
        {
            Write-Host "`n [ERROR]: OCS_MinPasswordAge Value should be less than OCS_MaxPasswordAge" -ForegroundColor Red
            $global:ErrorCount = $ErrorCount + 1
        }
        
        $global:MinPasswordLengthValue1 = FetchValue "MinPasswordLength"

        IntegerCheck $MinPasswordLengthValue1 "MinPasswordLength"
        if($global:IntegerCount -eq 1)
        {
            $global:MinPasswordLengthValue = [int]$global:MinPasswordLengthValue1
            if(($global:MinPasswordLengthValue -lt 0) -OR ($global:MinPasswordLengthValue -gt 14))
            {
                Write-Host "`n [ERROR]: OCS_MinPasswordLength Value should be between (0-14)" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }
        }

        $global:PasswordHistoryCountValue1 = FetchValue "PasswordHistoryCount"

        IntegerCheck $PasswordHistoryCountValue1 "PasswordHistoryCount"
        if($global:IntegerCount -eq 1)
        {
            $global:PasswordHistoryCountValue = [int]$global:PasswordHistoryCountValue1
            if(($global:PasswordHistoryCountValue -lt 0) -OR ($global:PasswordHistoryCountValue -gt 24))
            {
                Write-Host "`n [ERROR]: OCS_PasswordHistoryCount Value should be between (0-24)" -ForegroundColor Red
                $global:ErrorCount = $ErrorCount + 1
            }
        }
    }
    if($global:ErrorCount -gt 0)
    {
        #Write-Host "$global:ErrorCount Errors"
        Write-Host "`n [ERROR]: There are error/errors in the configuration file and please make above mentioned correction" -ForegroundColor Red
		return "Failed"        
    }
    else
    {
        Write-Host "`n Fetching all parameters from file is successful"
        "`n Fetching all parameters from file is successful" >>$global:GPLogFile
    }
}

#------------------------------------------------------------------------
#function for reading BIS/NetAn parameters 
#------------------------------------------------------------------------

function readBISParameter()
{    
    $global:BISLockoutThreshold1 = FetchValue "BIS_Lockout_Threshold"

    IntegerCheck $global:BISLockoutThreshold1 "BIS_Lockout_Threshold" 
    if($global:IntegerCount -eq 1)
    {
        $global:BISLockoutThreshold = [int]$global:BISLockoutThreshold1
        if(($global:BISLockoutThreshold -lt 0) -OR ($global:BISLockoutThreshold -gt 30))
        {
            Write-Host "`n [ERROR]: BIS_Lockout_Threshold value should be between (0-30)" -ForegroundColor Red
            $global:ErrorCount = $ErrorCount + 1
        }
    }
    
    $global:BISLockoutWindows1 = FetchValue "BIS_Lockout_Window"  
       
    IntegerCheck $global:BISLockoutWindows1 "BIS_Lockout_Window"
    if($global:IntegerCount -eq 1)
    {
        $global:BISLockoutWindows = [int]($global:BISLockoutWindows1)
        if(($global:BISLockoutWindows -lt 0) -OR ($global:BISLockoutWindows -gt 59))
        {
            Write-Host "`n [ERROR]: BIS_Lockout_Window value should be between (0-59)" -ForegroundColor Red
            $global:ErrorCount = $ErrorCount + 1
        }        
    }    

    $global:BISLockoutDuration1 = FetchValue "BIS_Lockout_Duration"

    IntegerCheck $global:BISLockoutDuration1 "BIS_Lockout_Duration"
    if($global:IntegerCount -eq 1)
    {
        $global:BISLockoutDuration = [int]($global:BISLockoutDuration1)
        if(($global:BISLockoutDuration -lt 0) -OR ($global:BISLockoutDuration -gt 59))
        {
            Write-Host "`n [ERROR]: BIS_Lockout_Duration value should be between (0-59)" -ForegroundColor Red
            $global:ErrorCount = $ErrorCount + 1
        }

        if($global:BISLockoutWindows -gt $global:BISLockoutDuration)
        {
            Write-Host "`n [ERROR]: BIS_Lockout_Window value should be lessthan or equals to BIS_Lockout_Duration" -ForegroundColor Red
            $global:ErrorCount = $ErrorCount + 1
        }
    }

    $global:BISMinPasswordAge1 = FetchValue "BIS_Minimum_Password_Age"

    IntegerCheck $global:BISMinPasswordAge1 "BIS_Minimum_Password_Age"
    if($global:IntegerCount -eq 1)
    {
        $global:BISMinPasswordAge = [int]($global:BISMinPasswordAge1)
        if(($global:BISMinPasswordAge -lt 0) -OR ($global:BISMinPasswordAge -gt 999))
        {
            Write-Host "`n [ERROR]: BIS_Minimum_Password_Age value should be between (0-999)" -ForegroundColor Red
            $global:ErrorCount = $ErrorCount + 1
        }
    }

    $global:BISMaxpasswordAge1 = FetchValue "BIS_Maximum_Password_Age"

    IntegerCheck $global:BISMaxpasswordAge1 "BIS_Maximum_Password_Age"
    if($global:IntegerCount -eq 1)
    {
        $global:BISMaxpasswordAge = [int]($global:BISMaxpasswordAge1)
        if(($global:BISMaxpasswordAge -lt 1) -OR ($global:BISMaxpasswordAge -gt 999))
        {
            Write-Host "`n [ERROR]: BIS_Maximum_Password_Age value should be between (1-999)" -ForegroundColor Red
            $global:ErrorCount = $ErrorCount + 1
        }
    }

    $global:BISMinPasswordLength1 = FetchValue "BIS_Minimum_Password_Length"

    IntegerCheck $global:BISMinPasswordLength1 "BIS_Minimum_Password_Length"
    if($global:IntegerCount -eq 1)
    {
        $global:BISMinPasswordLength = [int]($global:BISMinPasswordLength1)
        if(($global:BISMinPasswordLength -lt 0) -OR ($global:BISMinPasswordLength -gt 14))
        {
            Write-Host "`n [ERROR]: BIS_Minimum_Password_Length value should be between (0-14)" -ForegroundColor Red
            $global:ErrorCount = $ErrorCount + 1
        }
    }

    $global:BISPasswordHistoryCount1 = FetchValue "BIS_Password_History_Count"

    IntegerCheck $global:BISPasswordHistoryCount1 "BIS_Password_History_Count"
    if($global:IntegerCount -eq 1)
    {
        $global:BISPasswordHistoryCount = [int]($global:BISPasswordHistoryCount1)
        if(($global:BISPasswordHistoryCount -lt 0) -OR ($global:BISPasswordHistoryCount -gt 24))
        {
            Write-Host "`n [ERROR]: BIS_Password_History_Count value should be between (0-24)" -ForegroundColor Red
            $global:ErrorCount = $ErrorCount + 1
        }
    }

    if($BISMinPasswordAge -ge $BISMaxpasswordAge)
    {
        Write-Host "`n [ERROR]: BIS_Minimum_Password_Age value should be less than BIS_Maximum_Password_Age and exiting from the script" -ForegroundColor Red
        $global:ErrorCount = $ErrorCount + 1  
    }

    if($global:ErrorCount -gt 0)
    {        
        Write-Host "`n [ERROR]: There are errors in the configuration file and please make above mentioned correction and try executing the script" -ForegroundColor Red
        return "Failed"
    }
    else
    {
        Write-Host "`n Fetching all parameters from file is successfull"
        "`n Fetching all parameters from file is successfull" >>$global:GPLogFile
    }
}

#------------------------------------------------------------------------
#function for reading Default BIS/NetAn parameters from Default_Value_Configuration file
#------------------------------------------------------------------------

function FetchBISDefaultValues($Arg1)
{
    foreach($SourceFolder in Get-Content  $DefaultValuesFile)
    {            
        If($SourceFolder -match $Arg1)
        {                                
      	   	$line_split = "$SourceFolder".split(":",2)
            $Value = $line_split[1].Trim()
            if(($Value -eq "None") -OR ($Value -eq "Never"))
            {
                $Value = 0
            }                                     
        }
    }
    return $Value
}

#------------------------------------------------------------------------
#function for reading Default BIS/NetAn parameters
#------------------------------------------------------------------------

function ReadBISDefaultParamter()
{
    $global:DefaultMinPasswordAge = FetchBISDefaultValues "Minimum password age"

    $global:DefaultMaxPasswordAge = FetchBISDefaultValues "Maximum password age"

    $global:DefaultMinPasswordLength = FetchBISDefaultValues "Minimum password length"

    $global:DefaultPasswordHistory = FetchBISDefaultValues "Length of password history"

    $global:DefaultLockoutThreshold = FetchBISDefaultValues "Lockout threshold"  

    $global:DefaultLockoutDuration = FetchBISDefaultValues "Lockout duration"

    $global:DefaultLockoutWindow = FetchBISDefaultValues "Lockout observation window"
}

#------------------------------------------------------------------------
#function for Adding NON-SSO users to policy
#------------------------------------------------------------------------

function AddUserToPolicy($Argument)
{
    try
    {
        PrintDateTime
        "`n Adding users to policy " >>$global:GPLogFile
        $ADGroups = new-object Collections.Generic.List[string]
        <#foreach($SourceFolder in Get-Content  $InputFile)
        {            
            If($SourceFolder -match "SSOGroupName")
            {                                
  	   	        $line_split = "$SourceFolder".split("=",2)
                $Value = $line_split[1].Trim()
                if([bool](Get-ADGroup -Filter 'Name -like $Value'))
                {                    
                    $ADGroups.Add($Value)
                }
                else
                {
                    Write-Host "$Value is not a AD Group"
                }                
            }
        }#>
        $TotalGroups = new-object Collections.Generic.List[string]        
        $TotalGroups = @('bo-admin-access','bo-universe-access','bo-report-operator-access','netan-consumer-access','netan-business-author-access','netan-business-analyst-access','netan-server-admin-access')
        foreach($GroupCheck in $TotalGroups)
        {
            if([bool](Get-ADGroup -Filter 'Name -like $GroupCheck'))
            {    
                "$GroupCheck is a valid AD group" >>$global:GPLogFile             
                $ADGroups.Add($GroupCheck)
            }
            else
            {
                "$GroupCheck is not a valid AD Group" >>$global:GPLogFile       
            }    
        }
        $LengthOfGroup = $ADGroups.Count
        if($Argument -eq "Enable")
        {
            $users = Get-ADUser -Filter 'Name -like "*"' | Select-Object -Property 'Name'    
        }
        elseif($Argument -eq "Re_Enable")
        {
            $users = Get-ADUser -filter {(whencreated -ge $lastday)} | Select-Object -Property 'Name' 
            $UsersLength = $users.Name.Count
            "$UsersLength users are created in last 24 hours and them to policy" >>$global:GPLogFile
        }
        
        foreach ($user in $users.Name) 
        {
            $UserFound = 0
            $UserNotFound = 0
            foreach ($group in $ADGroups)
            {
                #Write-Host "Group "$group
                $SamAccountGroup = Get-ADGroup -Filter 'Name -like $group' | Select-Object -Property "SamAccountName"
                #Write-Host "SAM Group "$SamAccountGroup
                $members = Get-ADGroupMember -Identity $SamAccountGroup.SamAccountName -Recursive | Select -ExpandProperty SamAccountName
                If($members -contains $user)
                {
                    $UserFound = $UserFound + 1                       
                }
                Else
                {
                    $UserNotFound = $UserNotFound + 1                      
                }        
            }  
            if($UserNotFound -eq $LengthOfGroup)
            {
                #$user
                "$user is not present in any one of SSO group and hence adding to Normal group policy" >>$global:GPLogFile 
                $AddUser = "True"                   
                $LDAPUser = Get-ADUser -Filter 'Description -like "ENM LDAP User"' | Select-Object -Property Name
                if($LDAPUser.Name -eq $user)
                {
                    "$user is LDAP user and not adding to group policy" >>$global:GPLogFile
                    $AddUser = "False"
                }
                try
                {
                    $Check = setspn -l $user 2>&1
                }
                catch
                {
                    $_ >>$global:GPLogFile
                }
                if($Check -match "HTTP")
                {
                    "$user is a service account and not adding to policy" >>$global:GPLogFile
                    $AddUser = "False"
                }
                elseif($AddUser -eq "True")
                {                           
                    try
                    {
                        $SamAccountName =  Get-ADUser -Filter 'Name -like $user'| Select-Object -Property "SamAccountName"
                        Add-ADFineGrainedPasswordPolicySubject -Identity $GroupPolicyName -Subjects $SamAccountName
                    }
                    catch
                    {
                        $_ >>$global:GPLogFile
                    }
                }
            }
            else
            {        
                "$user is present in $UserFound SSO groups and hence not adding to Normal group policy" >>$global:GPLogFile
            }  
        }
        
    }
    catch
    {
        $_ >>$global:GPLogFile
    }
}

#------------------------------------------------------------------------
#function for Adding policy in AD server
#------------------------------------------------------------------------

function AddPolicy()
{
    try
    {
        PrintDateTime
        "`n Creating policy using the values given in configuration file " >>$global:GPLogFile
        New-ADFineGrainedPasswordPolicy -Name $GroupPolicyName -Precedence $PrecedenceValue -ComplexityEnabled $true -Description $PolicyDescription -LockoutDuration $LockoutDurationValue -LockoutObservationWindow $LockoutObservationWindow -LockoutThreshold $LockoutThresholdValue -MaxPasswordAge $MaxPasswordAgeValue -MinPasswordAge  $MinPasswordAgeValue -MinPasswordLength $MinPasswordLengthValue -PasswordHistoryCount $PasswordHistoryCountValue -ProtectedFromAccidentalDeletion $False -ReversibleEncryptionEnabled $false            
        AddUserToPolicy "Enable"
        Invoke-GPUpdate -Force
    }
    catch
    {
        $_ >>$global:GPLogFile
        Write-Host "Error while creating $GroupPolicyName and exiting from the script"
        "Error while creating $GroupPolicyName and exiting from the script" >>$global:GPLogFile
		return "Failed"
        exit
    }
}

#------------------------------------------------------------------------
#function for checking if policy exists or not
#------------------------------------------------------------------------

function CheckPolicyExist($PolicyName)
{
    try
    {
        Get-ADFineGrainedPasswordPolicy $PolicyName | Out-Null        
        return $True
    }
    catch
    {      
        return $False          
    }
}

#------------------------------------------------------------------------
#function for Changing default policy values to BIS/NetAn 
#------------------------------------------------------------------------

function ModifyDefaultPolicy()
{
    try
    {
        Net Accounts /lockoutthreshold:$BISLockoutThreshold /lockoutwindow:$BISLockoutWindows /lockoutduration:$BISLockoutDuration /MINPWLEN:$BISMinPasswordLength /MINPWAGE:$BISMinPasswordAge /MAXPWAGE:$BISMaxpasswordAge /UNIQUEPW:$BISPasswordHistoryCount | Out-Null
        Write-Host "`n Enabling of policy on the server is successful" -ForegroundColor Green
		return "Success"
    }
    catch
    {
        Write-Host "`n Error while enabling the policy on the server" -ForegroundColor Red
        $_ >>$global:GPLogFile
		return "Failed"
        exit
    }
    
}

#------------------------------------------------------------------------
#function for Checking if task is present in task-schduler
#------------------------------------------------------------------------

Function Check-TasksInTaskScheduler ($currentTask) 
{
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
	   $errorMessage >>$global:GPLogFile
       "Check Tasks in task scheduler Failed" >>$global:GPLogFile
       return $False
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
        $isTaskExist = Check-TasksInTaskScheduler "Checking_Users"
	    if (!$isTaskExist) 
        {
            "Checking_Users task does not exist in task schduler and creating a daily task" >>$global:GPLogFile
	    	schtasks /create /ru system /sc daily /tn "Checking_Users" /tr $Action /sd $StartDateForDataCollector /st $StartTimeForDataCollector /rl highest | Out-null
	    }
        else
        {
            "Logs_Collector task already present in task schduler" >>$global:GPLogFile
        }
    }
    catch
	{
		$_ >>$global:GPLogFile
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
        $_ >>$global:GPLogFile
        return $false
    }
}

#------------------------------------------------------------------------
#function for Changing BIS/NetAn policy to default values
#------------------------------------------------------------------------

function RollBackBISDefaultPolicy()
{
    try
    {
        Net Accounts /lockoutthreshold:$DefaultLockoutThreshold /lockoutwindow:$DefaultLockoutWindow /lockoutduration:$DefaultLockoutDuration /MINPWLEN:$DefaultMinPasswordLength /MINPWAGE:$DefaultMinPasswordAge /MAXPWAGE:$DefaultMaxPasswordAge /UNIQUEPW:$DefaultPasswordHistory | Out-Null
        Write-Host "`n Disabling of policy on the server is successful" -ForegroundColor Green
		"Disabling of policy on the server is successful" >>$global:GPLogFile
		return "Success"
    }
    catch
    {
        Write-Host "`n Error while Rollback of the policy" -ForegroundColor Red        
        $_ >>$global:GPLogFile
		return "Failed"
        exit
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
        PrintDateTime
		if(!(Test-Path -Path 'HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent'))
		{
			if((Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4*\config Manager') -OR (Test-path -Path "C:\Ericsson\NetAnServer\Server") -OR (Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4*\Installer\Aurora'))
			{        
				if(Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4*\config Manager')
				{
					if(Test-path -Path "C:\Ericsson\NetAnServer\Server")
					{
						"It's a Co-Deployed (BIS and NetAn) server" >>$global:GPLogFile
					}
					else
					{
						"It's BIS Server" >>$global:GPLogFile
					}
				}				
				elseif(Test-path -Path "C:\Ericsson\NetAnServer\Server")
				{
					"It's NetAn Server" >>$global:GPLogFile
				}
				elseif((Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4*\Installer\Aurora'))
				{
					"It's a OCS without Citrix server with BO Client installed" >>$global:GPLogFile
				}
				
				$user = [Security.Principal.WindowsIdentity]::GetCurrent();
				$CheckUser  = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
				if($CheckUser)
				{
					"`n Logged user is Administrator" >>$global:GPLogFile
					Write-Host "`n Logged user is Administrator"
				}
				else
				{        
					"`n Logged user is not Administrator. Please logon as Administrator and run the script for creation of password policy" >>$global:GPLogFile        
					exit
				}
				$ServerFound = 1
				if($Argument -eq "Enable")
				{
					$DefaultValuesFile = "C:\group_policy\Default_Value_Configuration.ini"
					if(Test-Path $DefaultValuesFile)
					{
						"Default policy configuration file is already present in C:\group_policy folder" >>$global:GPLogFile
					}
					else
					{
						"Default policy configuration file is not present and creating it in C:\group_policy folder\Default_Value_Configuration.ini" >>$global:GPLogFile
						$global:DefaultValuesFile = New-Item C:\group_policy\Default_Value_Configuration.ini -ItemType File
						$Value = Net Accounts
						Add-Content -Path $global:DefaultValuesFile -Value $Value    
					}
					readBISParameter          
					ModifyDefaultPolicy
				}
				elseif($Argument -eq "Disable")
				{
					"Rollback of default policy in BIS/NetAn server is started" >>$global:GPLogFile
					$global:DefaultValuesFile = "C:\group_policy\Default_Value_Configuration.ini"
					ReadBISDefaultParamter
					RollBackBISDefaultPolicy                
					
				}  
				else
				{
					Write-Host "`n [ERROR]: $Argument is an invalid argument in BIS/NetAn server" -ForegroundColor Red
					exit
				}                               
			}   
		}	
        
        if($ServerFound -ne 1)
        {
            $CheckADServer = CheckAD
            if($CheckADServer)
            {
                "It's AD Server" >>$global:GPLogFile                
                readParameter
                $PolicyFound = CheckPolicyExist $GroupPolicyName
                if($PolicyFound)
                {
                    "Group policy already exists with name $GroupPolicyName" >>$global:GPLogFile
                    if($Argument -eq "Re_Enable")
                    {
                        "Adding new user to the $GroupPolicyName" >>$global:GPLogFile
                        $lastday = ((Get-Date).AddDays(-1))
                        $NewUsers = Get-ADUser -filter {(whencreated -ge $lastday)} | Select-Object -Property SamAccountName
                        if($NewUsers.SamAccountName.count -gt 0)
                        {
                            AddUserToPolicy "Re_Enable"   
                            Invoke-GPUpdate -Force   
                            Write-Host "`n Adding new users to $GroupPolicyName is successful on the server" -ForegroundColor Green                    
                        }
                        else
                        {
                            "No new users are created in last 24 hours" >>$global:GPLogFile
                            exit
                        }                        
                    }
                    elseif($Argument -eq "Disable")
                    {                
                        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent() 
                        $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)  
                        if($WindowsPrincipal.IsInRole("Domain Admins")) 
                        {     
                            Write-Host "`n Logged on user is Domain Administrator" 
                            "`n Logged on user is Domain Administrator" >>$global:GPLogFile
                        } 
                        else 
                        {    
                            Write-Host "`n Logged on user is not Domain Administrator and exiting from script" 
                            "`n Logged on user is not Domain Administrator and exiting from script" >>$global:GPLogFile
                            exit
                        }                                
                        "`n Deleting $GroupPolicyName that is created" >>$global:GPLogFile
						try
						{
							Remove-ADFineGrainedPasswordPolicy $GroupPolicyName -Confirm:$false
							Write-Host "`n Disabling of policy on the server is successful " -ForegroundColor Green
							return "Success"
						}
                        catch
						{
							"Unable to disable group policy" >>$global:GPLogFile
							return "Failed"
						}
                        Invoke-GPUpdate -Force
                        $isTaskExist = Check-TasksInTaskScheduler "Checking_Users"
                        if ($isTaskExist) 
                        {	
                        	schtasks /delete /tn "Checking_Users" /f | Out-Null
                        }                                                 
                    }
                    elseif($Argument -eq "Enable")    
                    {
                        Write-Host "`n $GroupPolicyName policy already exists. Please try with another Group Policy Name and lower precedence value and exiting from script"
						return "Success"                        
                    }
                    else
                    {
                        exit
                    }            
                }
                else
                {                                        
                    if($Argument -eq "Enable")
                    {
                        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent() 
                        $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)  
                        if($WindowsPrincipal.IsInRole("Domain Admins")) 
                        {     
                            Write-Host "`n Logged on user is Domain Administrator" 
                            "`n Logged on user is Domain Administrator" >>$global:GPLogFile
                        } 
                        else 
                        {    
                            Write-Host "`n Logged on user is not Domain Administrator and exiting from script" 
                            "`n Logged on user is not Domain Administrator and exiting from script" >>$global:GPLogFile
                            exit
                        }
                        "Group policy doesn't exists with name $GroupPolicyName and hence creating group policy" >>$global:GPLogFile
                        AddPolicy
                        #Write-Host "Adding New policy"
                        Add-TasksInTaskScheduler
                        Write-Host "`n Enabling of policy on the server is successful " -ForegroundColor Green
						return "Success"
                    }    
                    else
                    {
                        "Group policy doesn't exists with name $GroupPolicyName and hence exiting from script" >>$global:GPLogFile
                        Write-Host "Group policy doesn't exists with name $GroupPolicyName and hence exiting from script" -ForegroundColor Red
                        exit
                    }                                    
                }                                          
            }
            else
            {
                $ErrorMessage
                Write-Host "`n Unable recognize server" -ForegroundColor Red
                "Unable recognize server" >>$global:GPLogFile
                exit
            }
        }        		 
	}
	catch
	{
		$_ >>$global:GPLogFile
	}
}

#MAIN
$global:ErrorCount = 0

$StartDateForDataCollector = (Get-Date).AddDays(1).ToString("MM/dd/yyyy")
$StartTimeForDataCollector = (Get-Date).ToString("HH:mm")
$powershellVar = "powershell "
$Action = $powershellVar + '-command &{C:\group_policy\Group_Policy.ps1 Re_Enable}'

$global:LogDirectory = "C:\group_policy\log"
$global:time_stamp=get-date -format yyyy-MM-dd_HH_mm_ss

#------------------------------------------------------------------------
#Checking if user has given correct argument or not
#------------------------------------------------------------------------
if($args.Count -lt 1)
{
    Write-Host "`n [ERROR]: No arguments are given when running the script. Please use Enable or Disable argument and try running the script." -ForegroundColor Red
    exit
}
elseif($args.Count -gt 1)
{
    Write-Host "`n [ERROR]: Only one argument should be given when running the script. Please use Enable or Disable argument and try running the script." -ForegroundColor Red
    exit
}

if(($args -ne "Enable") -AND ($args -ne "Disable") -AND ($args -ne "Re_Enable"))
{
    Write-Host "`n [ERROR]: $args is an Invalid argument. Enable, Disable, Re_Enable are valid arguments" -ForegroundColor Red
    exit
}
else
{
    Write-Host "`n Script is running with $args argument"
}

#------------------------------------------------------------------------
#Checking if Log directory is present and creating log file
#------------------------------------------------------------------------

if(Test-Path $LogDirectory)
{     
    $global:GPLogFile = New-Item C:\group_policy\log\Group_Policy_"$args"-"$global:time_stamp".txt -ItemType File
    PrintDateTime
    "New log file created in C:\group_policy\log directory" >>$global:GPLogFile
}
else
{    
    New-Item -Path $LogDirectory -ItemType Directory | Out-Null
	$global:GPLogFile = New-Item C:\group_policy\log\Group_Policy_"$args"-"$global:time_stamp".txt -ItemType File
    PrintDateTime
    "New log file created in C:\group_policy\log directory" >>$global:GPLogFile
}

#------------------------------------------------------------------------
#Checking if group_policy_configuration file is exists or not 
#------------------------------------------------------------------------

$InputFile = "C:\group_policy\group_policy_configuration.ini"
if(Test-Path $InputFile)
{
    "`nThe required configuration file 'group_policy_configuration.ini' for creating group policy found" >>$global:GPLogFile
    Write-Host "`n $args of group policy started"
}
else
{
   Write-Host "`n[ ERROR ] : The required configuration file 'group_policy_configuration.ini' for creating group policy is not found in C:\group_policy" -ForegroundColor Red
   exit
}

#------------------------------------------------------------------------
#Checking if argument is "Enable/Disable/Re_Enable" and proceeding further
#------------------------------------------------------------------------

if($args -eq "Enable")
{    
    $global:Argument = "Enable"            
    CheckServer
	try
    {
        $RegistryCheck = [bool](Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name SecurityLayer -ErrorAction SilentlyContinue)
        if($RegistryCheck)
        {
            "RDP registry key is already present" >>$global:GPLogFile
            $RegistryValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name SecurityLayer).SecurityLayer
            if($RegistryValue -eq 0)
            {
                "Security layer is set to RDP" >>$global:GPLogFile
            }
            else
            {
                "Security layer is not set to RDP and changing it to RDP" >>$global:GPLogFile
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name SecurityLayer -Value 0 | Out-Null
            }        
        }
        else
        {
            "RDP registry key is not present and creating the registry key" >>$global:GPLogFile
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name SecurityLayer -PropertyType DWord -Value 0 | Out-Null
        }
    }
    catch
    {
        "Error while checking registry key for RDP" >>$global:GPLogFile
        $_ >>$global:GPLogFile
    }    
}
elseif($args -eq "Disable")
{	
    $global:Argument = "Disable"     
    CheckServer
    try
    {
        $RegistryCheck = [bool](Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name SecurityLayer -ErrorAction SilentlyContinue)
        if($RegistryCheck)
        {
            "RDP registry key is already present" >>$global:GPLogFile
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name SecurityLayer                    
        }
        else
        {
            "RDP registry key is not present in the system" >>$global:GPLogFile            
        }
    }
    catch
    {
        "Error while checking registry key for RDP" >>$global:GPLogFile
        $_ >>$global:GPLogFile
    }
              
}
elseif($args -eq "Re_Enable")
{
    $global:Argument = "Re_Enable"    
    CheckServer            
}