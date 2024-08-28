#*************************************************************************
# 	Ericsson Radio Systems AB                                     SCRIPT
# *************************************************************************
# 
#   (c) Ericsson Radio Systems AB 2019 - All rights reserved.
#   The copyright to the computer program(s) herein is the property
# 	and/or copied only with the written permission from Ericsson Radio
# 	Systems AB or in accordance with the terms and conditions stipulated
# 	in the agreement/contract under which the program(s) have been
# 	supplied.
#
# ********************************************************************
# 	Name    : bis_rollback_nodehardening.ps1
# 	Date    : 07/01/2020
# 	Revision: A
# 	Purpose : This PowerShell script is used to perform the rollback procedure  
#			  for Node Hardening on BIS.  	
#
# 	Usage   : bis_rollback_nodehardening.ps1
#
# ********************************************************************

#----------------------------------------------------------------------------------------------------------------------------------------------------
#                                         		Setting log and configuration file path
#----------------------------------------------------------------------------------------------------------------------------------------------------	

$time_stamp=Get-Date -format yyyy-MM-dd_HH_mm_ss
New-Item -ItemType directory -Path C:\SECURITY_CONFIGURATION\bis_rollback_nodehardening\log -erroraction 'silentlycontinue' | out-null
$log="C:\SECURITY_CONFIGURATION\bis_rollback_nodehardening\log\bis_rollback_nodehardening_log-$time_stamp.log"
	
##Stopping Apache Tomcat for BI 4
"------------------------" >> $log
	Get-Date -format g >> $log
"------------------------" >> $log
stop-service BOEXI40Tomcat -WarningAction SilentlyContinue
"`r`nStopping Tomcat" >> $log

if ($?) {

    if ( (get-service -name BOEXI40Tomcat).status -eq "Stopped") {
        "BOEXI40Tomcat service stopped successfully" >> $log
    } else {
        "Unable to stop BOEXI40Tomcat service" >> $log
        Write-host "Unable to stop Tomcat service."
        Exit(1)
      }
} else {
    "Unable to stop BOEXI40Tomcat service." >> $log
    Write-host "Unable to stop Tomcat service."
    Exit(1)
  }
  
"Action successful" >> $log

try {
##Setting BI install directory
$bi_install_dir = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir

##Setting server.xml file directory
$serverXmlPath = $bi_install_dir + "tomcat\conf\server.xml"
[xml]$serverXml = Get-Content $serverXmlPath
$xdNS = $serverXml.DocumentElement.NamespaceURI
"`r`n------------------------" >> $log
"Updating server.xml file" >> $log
"------------------------" >> $log

##Updating sslEnabledProtocols attribute
$serverXml.Server.Service.Connector[1].SetAttribute('sslEnabledProtocols', $xdNS, 'TLSv1.2,TLSv1.1,TLSv1') >> $log
"sslEnabledProtocols attribute has been updated." >> $log

##Deleting ciphers attribute
$serverXml.'Server'.'Service'.'Connector'.RemoveAttribute('ciphers') >> $log
"ciphers attribute has been deleted." >> $log

##Updating port attribute
$serverXml.'Server'.SetAttribute('port', $xdNS, '8005') >> $log
"port attribute has been updated." >> $log

##Updating host attribute
$serverXml.'Server'.'Service'.'Engine'.'Host'.SetAttribute('autoDeploy', $xdNS, 'true') >> $log
"host attribute has been updated." >> $log
$serverXml.save($serverXmlPath)

##Setting web.xml file directory
$webXmlPath = $bi_install_dir + "tomcat\conf\web.xml"
"`r`n------------------------" >> $log
"Updating web.xml file" >> $log
"------------------------" >> $log

##Deleting <cookie-config> element
Set-Content -Path $webXmlPath -Value (get-content -Path $webXmlPath | Select-String -Pattern "<cookie-config>|<secure>true</secure>|<http-only>true</http-only>|</cookie-config>" -NotMatch)
"web.xml has been updated." >> $log
"Action successful" >> $log
} catch {
    $errorMessage = $_
	$errorMessage >> $log
            "BIS node hardening rollback FAILED.`r`n" >> $log
            Write-host "BIS node hardening rollback failed, check log for further details.`r`n"
			Exit(1)

}
##Starting Apache Tomcat for BI 4
start-service BOEXI40Tomcat -WarningAction SilentlyContinue
"`r`nStarting Tomcat" >> $log

if ($?) {

    if ( (get-service -name BOEXI40Tomcat).status -eq "Running") {
        "BOEXI40Tomcat service started successfully" >> $log
    } else {
        "Unable to start BOEXI40Tomcat service" >> $log
        Write-host "Unable to start Tomcat service"
        Exit(1)
      }
} else {
    "Unable to start BOEXI40Tomcat service." >> $log
    Write-host "Unable to start Tomcat service"
    Exit(1)
  }
  
"Action successful" >> $log
Write-Host "BIS Node Hardening has been rolled back successfully."