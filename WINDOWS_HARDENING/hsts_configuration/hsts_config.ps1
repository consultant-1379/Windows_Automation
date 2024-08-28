# **************************************************
# Name        :   hsts_config.ps1
# Date        :   22/05/2023
# Revision    :   A
# Purpose     :   This PowerShell script is used to Enable or Disable HSTS Configuration on BI Web Applications (CMC and BI Launch Pad)
# Usage       :   hsts_config.ps1 Enable | Disable
# **************************************************


# ============================================================
# Function: Print Date & Time
# ============================================================
function PrintDateTime()
{  
    "-----------------------------------------------" >> $log
    Get-Date -Format "dddd [MM/dd/yyyy] [HH:mm:ss]" >> $log
    "-----------------------------------------------" >> $log
}


# ============================================================
# Function: Stop "Apache Tomcat for BI 4" Service
# ============================================================
function Stop_Tomcat()
{
    PrintDateTime

    $service = "Apache Tomcat for BI 4"
    $arrService = Get-Service -Name $service

	"Trying to Stop Service:  $service" >> $log
	
    if ($arrService.Status -eq "Stopped")
    {
        "'$service' Service Status:  Stopped" >> $log
        "'$service' Service is already Stopped" >> $log

        Write-Host "-----------------------------------------------" -ForegroundColor Green
        Write-Host "'$service' Service Status:  Stopped" -ForegroundColor Green
        Write-Host "-----------------------------------------------" -ForegroundColor Green
    }
    else
    {
        "Stopping '$service' Service:  In-Progress" >> $log

        Write-Host "-----------------------------------------------" -ForegroundColor Green
        Write-Host "Stopping '$service' Service:  In-Progress" -ForegroundColor Green

        "net stop '$service' is executed" >> $log
		net stop $service >> $log

        "Checking if '$service' is Stopped" >> $log
        
        $number_of_checks = 0
        while (($arrService.Status -ne "Stopped") -AND ($number_of_checks -lt 60))
        {            
            "Service is not Stopped, checking again.." >> $log
            Start-Sleep -seconds 30
            
            $arrService = Get-Service -Name $service
            $number_of_checks = $number_of_checks + 1
            
            "Waiting for Apache Tomcat to Stop..." >> $log
        }
        
        if ($arrService.Status -eq "Stopped")
        {
            "'$service' Service Status:  Stopped" >> $log
            "'$service' Service has been successfully Stopped" >> $log

            Write-Host "'$service' Service Status:  Stopped" -ForegroundColor Green
            Write-Host "-----------------------------------------------" -ForegroundColor Green
        }
        else
        {
            "'$service' Service couldn't be Stopped" >> $log
            "Stop '$service' Service manually, and execute the script again.." >> $log

            Write-Host "'$service' Service couldn't be Stopped" -ForegroundColor Yellow
            Write-Host "Stop '$service' Service manually, and execute the script again.." -ForegroundColor Yellow
            Write-Host "-----------------------------------------------" -ForegroundColor Green

            exit
        }
    }

	$Tomcat_Status = Get-Service -Name "Apache Tomcat for BI 4"
}


# ============================================================
# Function: HSTS Configuration
# ============================================================
function Update_HSTS()
{
	PrintDateTime

    "Updating HSTS Configuration files" >> $log
	
	$warfiles_keystore = $bi_install_dir + "SAP BusinessObjects Enterprise XI 4.0\warfiles\webapps\BOE\WEB-INF\"
	$warfiles_default_properties = $bi_install_dir + "SAP BusinessObjects Enterprise XI 4.0\warfiles\webapps\BOE\WEB-INF\config\default\"

	if ((Test-Path -Path "$warfiles_keystore\sampletestKeystore.jks") -AND (Test-Path -Path "$warfiles_default_properties\global.properties"))
	{
        "HSTS Configuration files for warfiles are present" >> $log
		
		$warfiles_custom_properties = $bi_install_dir + "SAP BusinessObjects Enterprise XI 4.0\warfiles\webapps\BOE\WEB-INF\config\custom\"

        if (Test-Path -Path "$warfiles_custom_properties\global.properties")
        {
            "'global.properties' is already present under $warfiles_custom_properties directory" >> $log
        }
        else
        {
            "Copying 'global.properties' file from 'default' to 'custom' directory" >> $log
            Copy-Item "$warfiles_default_properties\global.properties" -Destination $warfiles_custom_properties -Force
            "'global.properties' is successfully copied to $warfiles_custom_properties directory" >> $log
        }

        $hsts_parameters = Get-Content -Path "$warfiles_custom_properties\global.properties"

		$hsts_enabled = 0
		$hsts_SubDomain = 0
		
        PrintDateTime

		foreach ($line in $hsts_parameters)
		{
            if ($line -match "hsts.enabled=")
            {
                "'hsts.enabled' parameter is found" >> $log

                if ($line -match "hsts.enabled=true")
                {
                    "'hsts.enabled=true' parameter is found" >> $log

                    $hsts_enabled = 200
                    break
                }
                elseif ($line -match "hsts.enabled=false")
                {
                    "'hsts.enabled=false' parameter is found" >> $log

                    $new_config = (Get-Content -Path "$warfiles_custom_properties\global.properties" -raw) -replace "hsts.enabled=false","hsts.enabled=true"
                    Set-Content -Path "$warfiles_custom_properties\global.properties" -value $new_config
                    
                    $hsts_enabled = 100
                    break
                }
                else
                {
                    "Unexpected parameter for 'hsts.enabled' is found" >> $log
                    "Unexpected parameter Value: $line" >> $log

                    $hsts_enabled = $hsts_enabled + 1
                    break
                }
            }
		}

		foreach ($line in $hsts_parameters)
		{
            if ($line -match "hsts.Include.SubDomains=")
            {
                "'hsts.Include.SubDomains' parameter is found" >> $log

                if ($line -match "hsts.Include.SubDomains=true")
                {
                    "'hsts.Include.SubDomains=true' parameter is found" >> $log

                    $hsts_SubDomain = 200
                    break
                }
                elseif ($line -match "hsts.Include.SubDomains=false")
                {
                    "'hsts.Include.SubDomains=false' parameter is found" >> $log

                    $new_config = (Get-Content -Path "$warfiles_custom_properties\global.properties" -raw) -replace "hsts.Include.SubDomains=false","hsts.Include.SubDomains=true"
                    Set-Content -Path "$warfiles_custom_properties\global.properties" -value $new_config
                    
                    $hsts_SubDomain = 100
                    break
                }
                else
                {
                    "Unexpected parameter for 'hsts.Include.SubDomains' is found" >> $log
                    "Unexpected parameter Value: $line" >> $log

                    $hsts_SubDomain = $hsts_SubDomain + 1
                    break
                }
            }
		}
		
        "Value of 'hsts.enabled': $hsts_enabled" >> $log
        "Value of 'hsts.Include.SubDomains': $hsts_SubDomain" >> $log

		if ((($hsts_enabled -eq 100) -AND ($hsts_SubDomain -eq 100)) -OR (($hsts_enabled -eq 100) -AND ($hsts_SubDomain -eq 200)) -OR (($hsts_enabled -eq 200) -AND ($hsts_SubDomain -eq 100)))
		{
			"Value of 'hsts.enabled' & 'hsts.Include.SubDomains' are set to True" >> $log
            $global:hsts_config_enabled = 100
		}
        elseif (($hsts_enabled -eq 200) -AND ($hsts_SubDomain -eq 200))
		{
			"Value of 'hsts.enabled' & 'hsts.Include.SubDomains' are already set to True" >> $log

            $tomcat_keystore = Test-Path -Path "$bi_install_dir\tomcat\webapps\BOE\WEB-INF\sampletestKeystore.jks"
	        $tomcat_properties = Test-Path -Path "$bi_install_dir\tomcat\webapps\BOE\WEB-INF\config\custom\global.properties"

            if ($tomcat_keystore -AND $tomcat_properties)
            {
                "HSTS Configuration files for Apache Tomcat are found" >> $log
                $global:hsts_config_enabled = 200
            }
            else
            {
                "HSTS Configuration files for Apache Tomcat are not found" >> $log
                $global:hsts_config_enabled = 100
            }
		}
		else
		{
			"Value of hsts.enabled & hsts.Include.SubDomains couldn't be set to True" >> $log
            $global:hsts_config_enabled = $global:hsts_config_enabled + 1
		}
	}
	else
	{
		"HSTS Configuration files are not found" >> $log
        $media_keystore = "C:\ebid\hsts_configuration\sampletestKeystore.jks"

        if (Test-Path -Path $media_keystore)
        {
            "'$media_keystore' is found" >> $log

            "Copying 'sampletestKeystore.jks' file from '$media_keystore' to '$warfiles_keystore' directory" >> $log
            Copy-Item $media_keystore -Destination $warfiles_keystore -Force
            "'sampletestKeystore.jks' is successfully copied to $warfiles_custom_properties directory" >> $log

            Update_HSTS
        }
        else
        {
            "'$media_keystore' is not found" >> $log
            $global:hsts_config_enabled = $global:hsts_config_enabled + 1

            "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" >> $log

            Write-Host "Check 'hsts_config-$timestamp.log' for more details" -ForegroundColor Yellow
            Write-Host "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" -ForegroundColor Yellow

            exit
        }
    }
}


# ============================================================
# Function: Use wDeploy to Undeploy BOE jar Files
# ============================================================
function BOE_Undeploy()
{
    PrintDateTime

    "Undeploy of BOE jar Files:  In-Progress" >> $log

    Write-Host "-----------------------------------------------" -ForegroundColor Green
	Write-Host "Undeploy of BOE jar Files:  In-Progress" -ForegroundColor Green
	
	cd "$bi_install_dir\SAP BusinessObjects Enterprise XI 4.0\wdeploy"
	Start-Process -FilePath "cmd.exe" -ArgumentList '/c "wdeploy tomcat9 -DAPP=BOE undeploy"' -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
	cd "C:\Users\Administrator\"
	
    $tomcat_BOE = $bi_install_dir + "\tomcat\webapps\BOE\"

    if (Test-Path -Path $tomcat_BOE)
    {
        "Undeploy of BOE jar Files:  Failed" >> $log

        Write-Host "Undeploy of BOE jar Files:  Failed" -ForegroundColor Yellow
        Write-Host "-----------------------------------------------" -ForegroundColor Green

        "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" >> $log

        Write-Host "Check 'hsts_config-$timestamp.log' for more details" -ForegroundColor Yellow
        Write-Host "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" -ForegroundColor Yellow

        exit
    }
    else
    {
        "Undeploy of BOE jar Files:  Successful" >> $log

        Write-Host "Undeploy of BOE jar Files:  Successful" -ForegroundColor Green
        Write-Host "-----------------------------------------------" -ForegroundColor Green
    }
}		


# ============================================================
# Function: Use wDeploy to Deploy BOE jar Files
# ============================================================
function BOE_Deploy()
{
    PrintDateTime

    "Deploy of BOE jar Files:  In-Progress" >> $log

    Write-Host "-----------------------------------------------" -ForegroundColor Green
	Write-Host "Deploy of BOE jar Files:  In-Progress" -ForegroundColor Green
	
	cd "$bi_install_dir\SAP BusinessObjects Enterprise XI 4.0\wdeploy"
	Start-Process -FilePath "cmd.exe" -ArgumentList '/c "wdeploy tomcat9 -DAPP=BOE deploy"' -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
	cd "C:\Users\Administrator\"
	
    $tomcat_BOE = $bi_install_dir + "\tomcat\webapps\BOE\"

    if (Test-Path -Path $tomcat_BOE)
    {
        "Deploy of BOE jar Files:  Completed" >> $log

        Write-Host "Deploy of BOE jar Files:  Successful" -ForegroundColor Green
        Write-Host "-----------------------------------------------" -ForegroundColor Green
    }
    else
    {
        "Deploy of BOE jar Files:  Failed" >> $log

        Write-Host "Deploy of BOE jar Files:  Failed" -ForegroundColor Yellow
        Write-Host "-----------------------------------------------" -ForegroundColor Green

        "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" >> $log

        Write-Host "Check 'hsts_config-$timestamp.log' for more details" -ForegroundColor Yellow
        Write-Host "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" -ForegroundColor Yellow

        exit
    }
}


# ============================================================
# Function: Clear Remaining Tomcat Cache
# ============================================================
function Tomcat_Clear_Cache()
{
    PrintDateTime  

    "Clear Tomcat Cache - 'localhost' directory:  In-Progress" >> $log

    Write-Host "-----------------------------------------------" -ForegroundColor Green
    Write-Host "Clear Tomcat Cache:  In-Progress" -ForegroundColor Green

	Remove-Item -Path "$bi_install_dir\tomcat\work\Catalina\localhost\" -Recurse -Force

    $tomcat_cache = $bi_install_dir + "\tomcat\work\Catalina\localhost\"
    if (Test-Path -Path $tomcat_cache)
    {
	    "Clear Tomcat Cache:  Failed" >> $log

        Write-Host "Clear Tomcat Cache:  Failed" -ForegroundColor Yellow
        Write-Host "-----------------------------------------------" -ForegroundColor Green

        "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" >> $log

        Write-Host "Check 'hsts_config-$timestamp.log' for more details" -ForegroundColor Yellow
        Write-Host "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" -ForegroundColor Yellow

        exit
    }
    else
    {
        "Clear Tomcat Cache:  Successful" >> $log

        Write-Host "Clear Tomcat Cache:  Successful" -ForegroundColor Green
        Write-Host "-----------------------------------------------" -ForegroundColor Green
    }
}


# ============================================================
# Function: Remove Tomcat 'stderr' Log File
# ============================================================
function Tomcat_Clear_Log()
{
    PrintDateTime  

	"Deleting Tomcat 'stderr' log file:  In-Progress" >> $log

    Write-Host "-----------------------------------------------" -ForegroundColor Green
    Write-Host "Deleting Tomcat 'stderr' Log:  In-Progress" -ForegroundColor Green

    $tomcat_log = $bi_install_dir + "\tomcat\logs\stderr.log"
	Remove-Item -Path $tomcat_log -Force

    if (Test-Path -Path $tomcat_log)
    {
	    "Deleting Tomcat 'stderr' Log:  Failed" >> $log

        Write-Host "Deleting Tomcat 'stderr' Log:  Failed" -ForegroundColor Yellow
        Write-Host "-----------------------------------------------" -ForegroundColor Green

        "Delete '$tomcat_log' file manually" >> $log
        "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" >> $log

        Write-Host "Check 'hsts_config-$timestamp.log' for more details" -ForegroundColor Yellow
        Write-Host "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" -ForegroundColor Yellow

        exit
    }
    else
    {
        "Deleting Tomcat 'stderr' Log:  Successful" >> $log

        Write-Host "Deleting Tomcat 'stderr' Log:  Successful" -ForegroundColor Green
        Write-Host "-----------------------------------------------" -ForegroundColor Green
    }
}


# ============================================================
# Function: Start "Apache Tomcat for BI 4" Service
# ============================================================
function Start_Tomcat()
{
    PrintDateTime

    $service = "Apache Tomcat for BI 4"
    $arrService = Get-Service -Name $service

    "Trying to Start Service:  $service" >> $log
	
    if ($arrService.Status -eq "Running")
    {
        "'$service' Service Status:  Running" >> $log
        "'$service' Service is already Running" >> $log

        Write-Host "-----------------------------------------------" -ForegroundColor Green
        Write-Host "'$service' Service Status:  Running" -ForegroundColor Green
        Write-Host "-----------------------------------------------" -ForegroundColor Green
    }
    else
    {
        Write-Host "-----------------------------------------------" -ForegroundColor Green
		Write-Host "Starting '$service' Service:  In-Progress" -ForegroundColor Green

		"Starting Service: $service" >> $log

        "'net start $service' is executed" >> $log
		net start $service >> $log

        "Checking if 'Apache Tomcat' is Running" >> $log 
        
        $number_of_checks = 0
        while (($arrService.Status -ne "Running") -AND ($number_of_checks -lt 60))
        {
            "Service is not Running, checking again.." >> $log
            Start-Sleep -seconds 30
            
            $arrService = Get-Service -Name $service
            $number_of_checks = $number_of_checks + 1
            
            "Waiting for Apache Tomcat to Start..." >> $log
        }
        
        if ($arrService.Status -eq "Running")
        {
            "Apache Tomcat Service has been successfully Started" >> $log

            Write-Host "'$service' Service Status:  Running" -ForegroundColor Green
            Write-Host "-----------------------------------------------" -ForegroundColor Green
        }
        else
        {
            "'$service' Service couldn't be Started" >> $log
            "Start '$service' Service manually" >> $log

            Write-Host "'$service' Service couldn't be Started" -ForegroundColor Yellow
            Write-Host "Start '$service' Service manually" -ForegroundColor Yellow
            Write-Host "-----------------------------------------------" -ForegroundColor Green

            "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" >> $log
            
            Write-Host "Check 'hsts_config-$timestamp.log' for more details" -ForegroundColor Yellow
            Write-Host "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" -ForegroundColor Yellow

            exit
        }
    }

	$Tomcat_Status = Get-Service -Name "Apache Tomcat for BI 4"
}


# ============================================================
# Function: Check for Cache Re-build
# ============================================================
function Tomcat_Cache_Rebuild()
{
    PrintDateTime
    
    "Tomcat Cache Rebuild:  In-Progress" >> $log

    Write-Host "-----------------------------------------------" -ForegroundColor Green
    Write-Host "Tomcat Cache Rebuild:  In-Progress" -ForegroundColor Green

    $tomcat_check = 0
    $tomcat_exit = $false

    while ($tomcat_check -lt 50)
    {
        $tomcat_log = Get-Content -Path "$bi_install_dir\tomcat\logs\stderr.log"

        "Cache Rebuild is not Completed, checking again.." >> $log
        
        foreach ($line in $tomcat_log)
        {
            if ($line -match "INFO: Server startup in")
            {
                "Updates in 'stderr' is Completed" >> $log

                $tomcat_exit = $true
                break
            }
        }

        if ($tomcat_exit -eq $true)
        {
            $line >> $log
            "Tomcat Cache Rebuild:  Successful" >> $log

            Write-Host "Tomcat Cache Rebuild:  Successful" -ForegroundColor Green
            Write-Host "-----------------------------------------------" -ForegroundColor Green

            break
        }
        else
        {
            "Waiting for Tomcat Cache to Rebuild..." >> $log
            
            Start-Sleep -seconds 30
            $tomcat_check = $tomcat_check + 1
        }
    }

    if ($tomcat_check -ge 50)
    {
        $line >> $log
        "Tomcat Cache Rebuild:  Failed" >> $log

        Write-Host "Tomcat Cache Rebuild:  Failed" -ForegroundColor Yellow
        Write-Host "-----------------------------------------------" -ForegroundColor Green

        "Wait for Tomcat Cache to Rebuild" >> $log
        "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" >> $log
            
        Write-Host "Check 'hsts_config-$timestamp.log' for more details" -ForegroundColor Yellow
        Write-Host "For corrective actions, see section 'HSTS Configuration for BI Server' in 'Node Hardening for BIS, OCS and Network Analytics Server' document" -ForegroundColor Yellow

        exit
    }
    else
    {
        "Value of 'tomcat_check': $tomcat_check" >> $log
    }
}


# ============================================================
# Main Script Execution
# ============================================================
$timestamp = Get-Date -format yyyy-MM-dd-HH_mm_ss
New-Item -ItemType directory -Path "C:\ebid\hsts_configuration\log\" -erroraction 'silentlycontinue' | out-null
$log = "C:\ebid\hsts_configuration\log\hsts_config-$timestamp.log"
$bi_install_dir = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir


# ============================================================
# Argument Checks: Enable / Disable
# ============================================================
if ($args.Count -gt 1)
{
    PrintDateTime

    "Multiple Arguments are not supported" >> $log
    "'Enable' and 'Disable' are the only supported arguments" >> $log

    Write-Host "-----------------------------------------------" -ForegroundColor Green
    Write-Host "Multiple Arguments are not supported" -ForegroundColor Yellow

    Write-Host "'Enable' and 'Disable' are the only supported arguments" -ForegroundColor Yellow
    Write-Host "-----------------------------------------------" -ForegroundColor Green

    exit
}
elseif ($args.Count -eq 0)
{
    PrintDateTime

    "No Argument is provided" >> $log
    "'Enable' and 'Disable' are the only supported arguments" >> $log

    Write-Host "-----------------------------------------------" -ForegroundColor Green
    Write-Host "No Argument is provided" -ForegroundColor Yellow

    Write-Host "'Enable' and 'Disable' are the only supported arguments" -ForegroundColor Yellow
    Write-Host "-----------------------------------------------" -ForegroundColor Green

    exit
}
else
{
    PrintDateTime

    $argument = $args[0]
    if ($Argument -eq "Enable")
    {
        "'$Argument' argument is provided" >> $log

        "Enabling HSTS Configuration:  In-Progress" >> $log

        Write-Host "-----------------------------------------------" -ForegroundColor Green
        Write-Host "Enabling HSTS Configuration:  In-Progress" -ForegroundColor Green

        $global:hsts_config_enabled = 0

        "Initial Value of hsts_config_enabled: $global:hsts_config_enabled" >> $log
        Update_HSTS
        "Final Value of hsts_config_enabled: $global:hsts_config_enabled" >> $log

        PrintDateTime

        if ($global:hsts_config_enabled -eq 100)
        {
            "Proceeding with HSTS Configuration.." >> $log

            Write-Host "Proceeding with HSTS Configuration.." -ForegroundColor Green
            
            Stop_Tomcat

            BOE_Undeploy
            BOE_Deploy

            Tomcat_Clear_Cache
            Tomcat_Clear_Log

            Start_Tomcat

            Tomcat_Cache_Rebuild

            "Enabling HSTS Configuration:  Successful" >> $log

            Write-Host "Enabling HSTS Configuration:  Successful" -ForegroundColor Green
            Write-Host "-----------------------------------------------" -ForegroundColor Green

            exit
        }
        elseif ($global:hsts_config_enabled -eq 200)
        {
            "HSTS Configuration is already Enabled" >> $log

            Write-Host "HSTS Configuration is already Enabled" -ForegroundColor Green
            Write-Host "-----------------------------------------------" -ForegroundColor Green

            exit
        }
        else
        {
            "HSTS Configuration can't be Enabled" >> $log

            Write-Host "HSTS Configuration can't be Enabled" -ForegroundColor Yellow
            Write-Host "-----------------------------------------------" -ForegroundColor Green

            exit
        }
    }
    elseif ($Argument -eq "Disable")
    {
        "'$Argument' argument is provided" >> $log

        "Disabling HSTS Configuration:  In-Progress" >> $log

        Write-Host "-----------------------------------------------" -ForegroundColor Green
        Write-Host "Disabling HSTS Configuration:  In-Progress" -ForegroundColor Green      

        $warfiles_custom_properties = $bi_install_dir + "\SAP BusinessObjects Enterprise XI 4.0\warfiles\webapps\BOE\WEB-INF\config\custom\"

        if (Test-Path -Path "$warfiles_custom_properties\global.properties")
        {
            "'global.properties' file file is found under $warfiles_custom_properties directory" >> $log
            "Deleting 'global.properties' file from $warfiles_custom_properties directory" >> $log

            Remove-Item -Path "$warfiles_custom_properties\global.properties" -Force

            "'global.properties' file has been successfully removed from $warfiles_custom_properties directory" >> $log

            Stop_Tomcat

            BOE_Undeploy
            BOE_Deploy

            Tomcat_Clear_Cache
            Tomcat_Clear_Log

            Start_Tomcat

            Tomcat_Cache_Rebuild

            "Disabling HSTS Configuration:  Successful" >> $log

            Write-Host "Disabling HSTS Configuration:  Successful" -ForegroundColor Green
            Write-Host "-----------------------------------------------" -ForegroundColor Green

            exit
        }
        else
        {
            "'global.properties' file file is not found under $warfiles_custom_properties directory" >> $log

            "HSTS Configuration is not Enabled" >> $log

            Write-Host "HSTS Configuration is not Enabled" -ForegroundColor Green
            Write-Host "-----------------------------------------------" -ForegroundColor Green

            exit
        }
    }
    else
    {    
        "'$Argument' is an Invalid Argument" >> $log
        "'Enable' and 'Disable' are the only supported arguments" >> $log

        Write-Host "-----------------------------------------------" -ForegroundColor Green
        Write-Host "'$Argument' is an Invalid Argument" -ForegroundColor Yellow

        Write-Host "'Enable' and 'Disable' are the only supported arguments" -ForegroundColor Yellow
        Write-Host "-----------------------------------------------" -ForegroundColor Green

        exit
    }
}