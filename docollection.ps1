<#
    A PowerShell script design to extract artifacts and turn them into JSON for use in threat hunting and incident
    response. Everything here is able to run in PowerShell 2.0 and above, therefore it should work in Windows 7+.

	Usage example: docollection.ps1 -All

	This will get all of the artifacts collected by the script

	Required binaries:
	Sysinsternals
		- autorunsc.exe
		- autorunsc64.exe
		- Tcpvon.exe
		- logonsessions.exe
		- logonsessions64.exe
		
	Nirsoft
		- BrowsingHistoryView.exe (Both 32 and 64-bit)
#>
param([switch]$All,[switch]$Autoruns,[switch]$Connections,[switch]$FileHashes,[switch]$LogonSessions,
      [switch]$Processes,[switch]$Details,[switch]$EventLogs,[switch]$Hotfixes,[switch]$Services,
      [switch]$Drives,[switch]$DNS,[switch]$BrowserHistory,[switch]$ScheduledJobs,[switch]$SystemDrivers)

Add-Type -Assembly System.Web.Extensions
function ConvertToJSON([object] $object)
{
  #http://mobilemancer.com/2014/03/31/powershell-working-with-json/
  $serializer = New-Object System.Web.Script.Serialization.JavascriptSerializer
  $serializer.MaxJsonLength = [int32]::MaxValue
  return $serializer.Serialize($object)
}

#Metadata for all JSON records
$dateCollected = (Get-Date).ToUniversalTime().GetDateTimeFormats('s')
$case =  Read-Host 'Case name: '
$machine = Get-WmiObject  Win32_ComputerSystem | Select-Object Name
#Used to determine which version of SysInternals clients to use
$architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
$outdir = Read-Host 'Output Path: '
if(!$(Test-Path $outdir))
{
	New-Item -ItemType Directory -Path $outdir
}
<#
https://technet.microsoft.com/en-ca/sysinternals/bb963902.aspx
This grabs all the information from autorunsc.exe including the following
	- Boot execute.
   	- Appinit DLLs.
   	- Explorer addons.
   	- Sidebar gadgets (Vista and higher)
   	- Image hijacks.
   	- Internet Explorer addons.
   	- Known DLLs.
   	- Logon startups (this is the default).
   	- WMI entries.
   	- Winsock protocol and network providers.
   	- Codecs.
   	- Printer monitor DLLs.
   	- LSA security providers.
   	- Autostart services and non-disabled drivers.
   	- Scheduled tasks.
   	- Winlogon entries.
#>
function GetAutoruns
{
	$autoruns = @()
	#Check if 64-bit
	if($architecture -eq "64-bit")
	{
		$autorun = .\autorunsc64.exe /accepteula -nobanner -c -h -t -a *
	}
	else
	{
		$autorun = .\autorunsc.exe /accepteula -nobanner -c -h -t -a *
	}
	#Convert output from autorunsc into a CSV to be parsed into JSON
	$autorun -replace "`0","" | 
	ConvertFrom-CSV -Header Time,EntryLocation,Entry,Enabled,Category,Profile,Description,Company,ImagePath,Version,LaunchString,MD5,SHA1,PESHA1,PESHA256,SHA256,IMP | 
	Select-Object -skip 1 | 
	ForEach-Object{
		$time = if($_.Time){([datetime]::ParseExact($_.Time,"yyyyMMdd-HHmmss",$null)).ToUniversalTime().GetDateTimeFormats('s')}else{$date_collected}
		$startupCommand = @{
			"timestamp"="$time";
			"entry_location"=$_.EntryLocation;
			"entry"="$($_.Entry)";
			"enabled"=$_.Enabled;
			"category"=$_.Category;
			"profile"=$_.Profile;
			"description"=$_.Description;
			"company"=$_.Company;
			"image_path"="$($_.ImagePath)";
        	"version"=$_.Version;
			"launch_string"="$($_.LaunchString)";
			"md5"=$_.MD5;
			"sha-1"=$_.SHA1;
			"pesha-1"=$_.PESHA1;
        	"pesha-256"=$_.PESHA256;
			"sha-256"=$_.SHA256;
			"imp"=$_.IMP;
			"_type"="autorun";
        	"date_collected"="$dateCollected";
			"machine"=$machine.Name;
			"case"="$case"
		}
		$autoruns += ConvertToJSON($startupCommand)
	}
	$outpath = "$outdir\\{0}_{1}_Autoruns.json" -f $case,$machine.Name
	$autoruns | Set-Content "$outpath"
}

#This gets a list of all the services from the system
function GetServices
{
	$md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
	$services = @()
 
	#Iterate through all of the service objects
	Get-WmiObject Win32_Service | 
	ForEach-Object{
		#If a path exists, try and hash it
        if($_.PathName)
		{
			$serviceMD5 = $None
			$serviceSHA1 = $None
			#Attempt to do some splitting based on switches with preceeding -'s, may not be the best way to do it
			if($_.PathName.contains("`"")){
				$path = $_.PathName.Split("`"")[1]
			}else{
				$path = $_.PathName.Split(" ")[0]
			}
			#Attempt to hash the files at the given path
            try
            {
				<#
					Use filestream for better performance and open the stream with read sharing 
					to try and prevent issues with opening files that may be in use.
				#>
    			$file = [System.IO.File]::Open($path,[System.IO.Filemode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
				#Get MD5 of file
                $serviceMD5 = [System.BitConverter]::ToString($md5.ComputeHash($file)) -replace "-",""
				#Get SHA-1 of file
    			$serviceSHA1 = [System.BitConverter]::ToString($sha1.ComputeHash($file)) -replace "-",""
				#Get rid of file
                $file.Dispose()
            }
            catch
            {
				#If the file could not be hashed set the hash to Unable to hash
				if(!$serviceMD5)
				{
					$serviceMD5 = "Unable to hash"
				}
                if(!$serviceSHA1)
				{
					$serviceSHA1 =  "Unable to hash"
				}
            }
            finally
            {
				#Make sure the file closed
                if($file)
                {
                    $file.Dispose()
                }
            }
			#Get signature object from the path, may be mostly empty on Windows 7
            $signature = Get-AuthenticodeSignature $path
		}
		#Convert service install date to UTC
        $installDate = if($_.InstallDate){$_.InstallDate.ToUniversalTime().GetDateTimeFormats('s')}else{$dateCollected}
		#Build dictionary
		$service = @{
			"caption"="$($_.Caption)";
			"description"="$($_.Description)";
			"display_name"="$($_.DisplayName)";
        	"error_control"="$($_.ErrorControl)";
			"exit_code"=$_.ExitCode;
			"timestamp"="$installDate";
			"install_date"="$installDate";
			"name"="$($_.Name)";
        	"path_name"="$($_.PathName)";
			"pid"="$($_.processId)";
			"service_type"="$($_.ServiceType)";
			"started"=$_.Started;
        	"start_mode"="$($_.StartMode)";
			"start_name"="$($_.StartName)";
			"state"="$($_.State)";
			"status"="$($_.Status)";
        	"system_name"="$($_.SystemName)";
			"md5"=$serviceMD5;
			"sha-1"=$serviceSHA1;
			"signature"="$($signature.SignerCertificate.Thumbprint)";
        	"signature_status"="$($signature.Status)";
			"is_os_binary"=$signature.IsOSBinary;
			"_type"="ps_service";
        	"date_collected"="$dateCollected";
			"machine"=$machine.Name;
			"case"="$case"}
		#Convert dictionary to JSON object
		$services += ConvertToJSON($service) 
	}
	$outpath = "$outdir\\{0}_{1}_Services.json" -f $case,$machine.Name
	$services | Set-Content "$outpath"
}

#Get the system drivers, includes hardware drivers from driverquery and a bunch of other stuff
function GetSystemDrivers
{
	$md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
	$drivers = @()
	#Iterate through system drivers
	Get-WmiObject Win32_SystemDriver | 
	ForEach-Object{
        if($_.PathName)
		{
			if($_.PathName.contains("?")){
				$path = $_.PathName.SubString(4)
			}else{
				$path = $_.PathName
			}
            try
            {
    			$file = [System.IO.File]::Open($path,[System.IO.Filemode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
                $driverMD5 = [System.BitConverter]::ToString($md5.ComputeHash($file)) -replace "-",""
    			$driverSHA1 = [System.BitConverter]::ToString($sha1.ComputeHash($file)) -replace "-",""
                $file.Dispose()
            }
            catch
            {
                $driverMD5 = "Unable to hash"
                $driverSHA1 =  "Unable to hash"
            }
            finally
            {
                if($file)
                {
                    $file.Dispose()
                }
            }
            $signature = Get-AuthenticodeSignature $path    
		}
        $installDate = if($_.InstallDate){$_.InstallDate.ToUniversalTime().GetDateTimeFormats('s')}else{$dateCollected}
		$driver = @{
			"caption"="$($_.Caption)";
			"description"="$($_.Description)";
			"display_name"="$($_.DisplayName)";
        	"error_control"="$($_.ErrorControl)";
			"exit_code"=$_.ExitCode;
			"timestamp"="$installDate";
			"install_date"="$installDate";
			"name"="$($_.Name)";
        	"path_name"="$($_.PathName)";
			"service_type"="$($_.ServiceType)";
			"started"=$_.Started;
        	"start_mode"="$($_.StartMode)";
			"start_name"="$($_.StartName)";
			"state"="$($_.State)";
			"status"="$($_.Status)";
        	"signature"="$($signature.SignerCertificate.Thumbprint)";
			"signature_status"="$($signature.Status)";
        	"is_os_binary"=$signature.IsOSBinary;
			"system_name"="$($_.SystemName)";
			"md5"=$driverMD5;
			"sha-1"=$driverSHA1;
			"_type"="systemdriver";
			"date_collected"="$dateCollected";
			"machine"=$machine.Name;
        	"case"="$case"
		}
		$drivers += ConvertToJSON($driver) 
	}
	$outpath = "$outdir\\{0}_{1}_Drivers.json" -f $case,$machine.Name
	$drivers | Set-Content "$outpath"
}

#Get the running processes
function GetProcesses
{
	$md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
	$processes = @()
	Get-Process |
	ForEach-Object{
		#Turn start time into UTC in ISO format
		$startTime = if($_.StartTime){$_.StartTime.ToUniversalTime().GetDateTimeFormats('s')}
		if($_.Path)
		{
			#Try to hash file path
            try
            {
    			$file = [System.IO.File]::Open($_.Path,[System.IO.Filemode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
                $processMD5 = [System.BitConverter]::ToString($md5.ComputeHash($file)) -replace "-",""
    			$processSHA1 = [System.BitConverter]::ToString($sha1.ComputeHash($file)) -replace "-",""
                $file.Dispose()
            }
            catch
            {
                $processMD5 = "Unable to hash"
                $processSHA1 =  "Unable to hash"
            }
            finally
            {
                if($file)
                {
                    $file.Dispose()
                }
            }
            $signature = Get-AuthenticodeSignature $_.Path
		}
		#Get dll information for each process
        $modules = @()
        foreach($module in $_.Modules)
        {
			#Hash and get signature of dll
            if($module.FileName)
            {
                try
                {
        			$file = [System.IO.File]::Open($module.FileName,[System.IO.Filemode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
                    $moduleMD5 = [System.BitConverter]::ToString($md5.ComputeHash($file)) -replace "-",""
        			$moduleSHA1 = [System.BitConverter]::ToString($sha1.ComputeHash($file)) -replace "-",""
                }
                catch
                {
                    $moduleMD5 = "Unable to hash"
                    $moduleSHA1 =  "Unable to hash"
                }
                finally
                {
                    if($file)
                    {
                        $file.Dispose()
                    }
                }
                $moduleSignature = Get-AuthenticodeSignature $module.FileName

            }
            #add dll and its info to dlls
            $modules+=@{
				"name"="$($module.ModuleName)";
				"sha1"=$moduleSHA1;"md5"=$moduleMD5;
				"company"="$($module.FileVersionInfo.CompanyName)";
           		"coments"="$($module.FileVersionInfo.Comments)";
				"version"="$($module.FileVersionInfo.FileVersion)";
            	"signature"="$($moduleSignature.SignerCertificate.Thumbprint)";
				"path"="$($module.FileName)"
         		"product_name"="$($module.FileVersionInfo.ProductName)";
				"signature_status"="$($moduleSignature.Status)";
            	"is_os_binary"=$moduleSignature.IsOSBinary
			}
        }
		$process = @{
			"name"=$_.ProcessName.Trim();
			"path"="$($_.Path)";
			"sha-1"=$processSHA1;
			"md5"=$processMD5;
       		"timestamp"="$startTime";
			"start_time"="$startTime";
			"id"=$_.Id.ToString();
        	"_type"="ps_process";
			"modules"=$modules;
			"signature"="$($signature.SignerCertificate.Thumbprint)";
        	"signature_status"="$($signature.Status)";
			"is_os_binary"=$signature.IsOSBinary;
			"date_collected"="$dateCollected";
        	"machine"=$machine.Name;"case"="$case"
		}
        
		$processes += ConvertToJSON($process)
	}
	$outpath = "$outdir\\{0}_{1}_Processes.json" -f $case,$machine.Name
	$processes | Set-Content "$outpath"
}

#Get the system hotfixes
function GetHotfixes
{
	$hotfixes = @()
	Get-Hotfix |
	ForEach-Object{
		$installedOn = if($_.InstalledOn){$_.InstalledOn.ToUniversalTime().GetDateTimeFormats('s')}
		
		$hotfix = @{
			"hotfixId"=$_.HotFixID;
			"source"="$($_.Source)";
			"description"=$_.Description;
        	"installed_by"="$($_.InstalledBy)";
			"timestamp"="$installedOn";
			"installed_on"="$installedOn";
			"caption"=$_.Caption;
        	"name"=$_.Name;
			"status"=$_.Status;
			"cs_name"=$_.CSName;
			"fix_comments"=$_.FixComments;
        	"service_pack_in_effect"=$_.ServicePackInEffect;
			"_type"="hotfix";
			"date_collected"="$dateCollected";
			"machine"=$machine.Name;
			"case"="$case"
		}
					
		$hotfixes += ConvertToJSON($hotfix)
	}
	$outpath = "$outdir\\{0}_{1}_Hotfixes.json" -f $case,$machine.Name
	$hotfixes | Set-Content "$outpath"
}

#Get all the evtx, evt, and etl logs on the system
function GetEventLogs{
    <#
	Look for IDs 4728, 4732, 4756 to check for privilege escaltation
	Iterate through each log and start from the oldest so evt and etl can be read
	If something's wrong keep going
	
	Windows Security logs, specifically:

	Successful Logon (ID 4624)
	Failed Logon (ID 4625)
	Kerberos Authentication (ID 4768)
	Kerberos Service Ticket (ID 4776)
	Assignment of Administrator Rights (ID 4672)
	Unknown username or password (ID 529)
	Account logon time restriction violation (ID 530)
	Account currently disabled (ID 531)
	User account has expired (ID 532)
	User not allowed to logon to the computer (ID 533)
	User has not been granted the requested logon type (ID 534)
	The account's password has expired (ID 535)
	The NetLogon component is not active (ID 536)
	The logon attempt failed for other reasons (ID 537)
	Account lockout (ID 539)

	#>
	$events = @()
	$logs = Get-WinEvent -ListLog * | Where-Object {$_.RecordCount} | Select-Object -ExpandProperty LogName
	Get-WinEvent -LogName $logs -Oldest -ErrorAction SilentlyContinue | 
	ForEach-Object{
		$timeCreated = if($_.TimeCreated){$_.TimeCreated.ToUniversalTime().GetDateTimeFormats('s')}
        $keywords = @()
        foreach($keyword in $_.KeywordsDisplayName)
        {
            $keywords+=$keyword
        }
		$event = @{
			"log_name"="$($_.LogName)";
			"timestamp"="$timeCreated";
			"time_created"="$timeCreated";
			"machine_mame"="$($_.MachineName)";
        	"user_id"="$($_.UserId)";
			"version"=$_.Version;
			"message"=$_.Message;
			"process_id"="$($_.ProcessId)";
        	"level"=$_.Level;
			"level_display_name"="$($_.LevelDisplayName)";
			"related_activity_id"="$($_.RelatedActivityId)";
			"id"="$($_.Id)";
        	"container_log"="$($_.ContainerLog)";
			"provider_id"="$($_.ProviderId)";
			"provider_name"="$($_.ProviderName)";
        	"record_id"=$_.RecordId;
			"thread_id"=$_.ThreadId;
			"keywords"=$keywords;
			"task"=$_.Task;
			"task_display_name"="$($_.TaskDisplayName)";
        	"opcode"=$_.Opcode;
			"opcode_display_name"="$($_.OpcodeDisplayName)";
			"qualifiers"=$_.Qualifiers;
			"date_collected"="$dateCollected";
        	"machine"=$machine.Name;
			"case"="$case";
			"_type"="event";
		}
		$events += ConvertToJSON($event)
	}
	$outpath = "$outdir\\{0}_{1}_EventLogs.json" -f $case,$machine.Name
	$events | Set-Content "$outpath"
}

#Get the mounted drives, including hives 
function GetDrives
{	
	$drives = @()
	Get-PSDrive | 
	ForEach-Object{
		$free = ([Math]::truncate(($_.Free / 1GB) * 100)) / 100
		$used = ([Math]::truncate(($_.Used / 1GB) * 100)) / 100
		$drive = @{
			"name"="$($_.Name)";
			"description"="$($_.Description)";
			"root"="$($_.Root)";
			"free"=$free;
			"used"=$used;
			"provider"="$($_.Provider)";
			"_type"="drive";
			"date_collected"="$dateCollected";
			"case"="$case";
			"machine"=$machine.Name
		}
		$drives += ConvertToJSON($drive)
	}
	$outpath = "$outdir\\{0}_{1}_Drives.json" -f $case,$machine.Name
	$drives | Set-Content "$outpath"	
}

#Get the DNS cachwe from the system. This information can be very volatile if the TTL is set to a low value for the record
function GetDNSCache
{
	$dnsRecords = @()
	#https://gallery.technet.microsoft.com/scriptcenter/ad12dc1c-b0c7-44d6-97c7-1a537b0b4fef
	Invoke-Expression "ipconfig /displaydns" |
	Select-String -Pattern "Record Name" -Context 0,5 |
	ForEach-Object{
		$recordName = ($_.Line -Split ":",2)[1] -replace " ",""
		$recordType = ($_.Context.PostContext[0] -Split ":",2)[1] -replace " ",""
		$ttl = ($_.Context.PostContext[1] -Split ":",2)[1] -replace " ",""
		$length = ($_.Context.PostContext[2] -Split ":",2)[1] -replace " ",""
		$section = ($_.Context.PostContext[3] -Split ":",2)[1] -replace " ",""
		$aaaaRecord = ($_.Context.PostContext[4] -Split ":",2)[1] -replace " ",""
		$record = @{
			"record_name"=$recordName;
			"record_type"=$recordType; 
			"ttl"=$ttl; 
			"data_length"=$length;
			"section"=$section;
			"aaaa_record"=$aaaaRecord;
			"_type"="dnsrecord";
			"date_collected"="$dateCollected";
			"machine"=$machine.Name;
			"case"="$case"
		}
		$dnsRecords += ConvertToJSON($record)
	}
	$outpath = "$outdir\\{0}_{1}_DNSRecords.json" -f $case,$machine.Name
	$dnsRecords | Set-Content "$outpath"
}

#Get a bunch of system information for the machine
function GetSystemDetails
{
	$systemInformation = @{}
	$biosInfo = Get-WmiObject Win32_Bios
	$systemInformation["serialnumber"] =  $biosInfo.SerialNumber

	$processorInfo = Get-WmiObject Win32_Processor
	$systemInformation["processor"] = $processorInfo.Name
	$systemInformation["cores"] = $processorInfo.NumberOfCores
	$systemInformation["logical_processors"] = $processorInfo.NumberOfLogicalProcessors

	$computerInfo = Get-WmiObject Win32_ComputerSystem
	$systemInformation["manufacturer"] = $computerInfo.Manufacturer
	$systemInformation["model"] = $computerInfo.Model
	$systemInformation["machine_name"] = $computerInfo.Name
	$systemInformation["memory"] = $computerInfo.TotalPhysicalMemory
	$systemInformation["username"] = $computerInfo.Username
	$systemInformation["domain"] = $computerInfo.Domain

	$osInfo = Get-WmiObject  Win32_OperatingSystem 
	$systemInformation["encryption_level"] = $osInfo.EncryptionLevel
	$systemInformation["os"] = $osInfo.Name 
	$systemInformation["service_pack_major"] = $osInfo.ServicePackMajorVersion
	$systemInformation["service_pack_minor"] = $osInfo.ServicePackMinorVersion
	$systemInformation["os_version"] = $osInfo.Version
	$installDate = ([WMI]'').ConvertToDateTime($osInfo.InstallDate).ToUniversalTime().GetDateTimeFormats('s')
	$systemInformation["timestamp"] = "$installDate"
	$systemInformation["install_date"] = "$installDate"
	$systemInformation["architecture"] = $osInfo.OSArchitecture
	$systemInformation["description"] = $osInfo.Description
    $lastBoot = ([WMI]'').ConvertToDateTime($osInfo.LastBootupTime).ToUniversalTime().GetDateTimeFormats('s')
	$systemInformation["last_boot"] = "$lastBoot" 
	$systemInformation["organization"] = $osInfo.Organization
	$systemInformation["system_drive"] = $osInfo.SystemDrive  	
	
	#Get all interfaces including virtual and otherwise
	$interfaces = @()
	Get-WmiObject Win32_NetworkAdapterConfiguration |
	ForEach-Object{
		$dhcpLeaseExpires = if($_.DHCPLeaseExpires){([WMI]'').ConvertToDateTime($_.DHCPLeaseExpires).ToUniversalTime().GetDateTimeFormats('s')}
		$dhcpLeaseObtained = if($_.DHCPLeaseObtained){([WMI]'').ConvertToDateTime($_.DHCPLeaseObtained).ToUniversalTime().GetDateTimeFormats('s')} #Date
		
		$interface = @{
			"caption"=$_.Caption;
			"description"=$_.Description;
			"default_ip_gateway"="$($_.DefaultIPGateway)";
			"dhcp_enabled"=$_.DHCPEnabled ;
			"dhcp_lease_expires"="$dhcpLeaseExpires";
			"dhcp_lease_obtained"="$dhcpLeaseObtained";
			"dhcp_server"="$($_.DHCPServer)";
			"dns_domain"="$($_.DNSDomain)";
			"dns_hostname"="$($_.DNSHostName)";
			"ip_enabled"=$_.IPEnabled;
			"ip_subnet"="$($_.IPSubnet)";
			"ip_address"="$($_.IPAddress)";
			"mac_address$_.MACAddress"="$()";
			"mtu"="$($_.MTU)";
			"tcp_window_size"="$($_.TCPWindowSize)";
			"service_name"=$_.ServiceName; 
			"index"=$_.Index;
		}
                        
		$interfaces += $interface
	}
	
	$systemInformation["interfaces"] = $interfaces
	$systemInformation["_type"] = "systemdetails"
	$systemInformation["date_collected"] = "$dateCollected"
	$systemInformation["machine"] = $machine.Name
	$systemInformation["case"] = "$case"
	$outpath = "$outdir\\{0}_{1}_SystemInformation.json" -f $case,$machine.Name
	ConvertToJSON($systemInformation) | Set-Content $outpath
}

#Get all active connections on the machine
function GetConnections
{
	$connections = @()
    .\Tcpvcon.exe /accepteula -a -c -n | Select-Object -skip 5 | ConvertFrom-Csv -Header Protocol,Process,PID,State,Local,Remote |
	ForEach-Object{
		if($_.Remote -and ($_.Remote -ne "0.0.0.0" -and $_.Remote -ne "[0:0:0:0:0:0:0:0]" -and $_.Remote -ne "*"))
		{
            Try
            {
                $remoteHostname = [System.Net.Dns]::GetHostEntry($_.Remote).HostName
            }
            Catch
            {
                $remoteHostname = "Unknown"
            }
		}
		
		$connection = @{
			"protocol"=$_.Protocol;
			"process"=$_.Process;
			"pid"=$_.PID;
			"state"=$_.State;
			"local"=$_.Local;
			"remote_ip"=$_.Remote;
			"remote_hostname"="$remoteHostname";
			"date_collected"="$dateCollected";
			"_type"="ps_connection";
			"case"="$case";
			"machine"=$machine.Name
		}
		$connections += ConvertToJSON($connection) 
	}
	$outpath = "$outdir\\{0}_{1}_Connections.json" -f $case,$machine.Name
	$connections | Set-Content $outpath
}

#Get the logon sessions
function GetLogonSessions() {
	$logonSessions = @()
	if($architecture -eq "64-bit")
	{
		$sessions = .\logonsessions64.exe /accepteula -p -c -nobanner
	}
	else
	{
		$sessions = .\logonsessions.exe /accepteula -p -c -nobanner
	}
    
	#Iterate through the sessions
	$sessions | Select-Object -skip 1 |
	ConvertFrom-CSV -Header LogonSession,UserName,AuthPackage,LogonType,Session,Sid,LogonTime,LogonServer,DNSDomain,UPN,Processes |
	ForEach-Object{
		$processes = @()
		#Iterate through the logon processes
		if($_.Processes){
			foreach ($process in $_.Processes.split(";"))
			{
				$proc = $process.split(":")
				if($proc){
					$processes += @{
						"pid"=$proc[0].Trim();
						"name"=$proc[1].Trim()
					}
				}
			}
		}
		$logonTime = if($_.LogonTime){([datetime]::ParseExact($_.LogonTime,"G",$null)).ToUniversalTime().GetDateTimeFormats('s')}
        
		$session = @{
			"logon_session"="$($_.LogonSession)";
			"username"="$($_.UserName)";
			"auth_package"="$($_.AuthPackage)";
			"logon_type"="$($_.LogonType)";
			"session"="$($_.Session)";
			"sid"="$($_.Sid)";
			"timestamp"="$logonTime";
			"logon_time"="$logonTime";
			"logon_server"="$($_.LogonServer)";
			"dns_domain"="$($_.DNSDomain)";
			"upn"="$($_.UPN)";
			"processes"=$processes;
			"_type"="logonsession";
			"date_collected"="$dateCollected";
			"case"="$case";
			"machine"="$($machine.Name)"
		}
		$logonSessions += ConvertToJSON($session)
	}
	$outpath = "$outdir\\{0}_{1}_LogonSessions.json" -f $case,$machine.Name
	$logonSessions | Set-Content "$outpath"
}

#Get browsing history of all major browsers
function GetBrowserHistory
{
	
	.\BrowsingHistoryView /HistorySource 1 /VisitTimeFilterType 1 /SComma .\history_temp.csv | Out-Null
	$history = @()
	Get-Content .\history_temp.csv | Select-Object -skip 1 | 
	ConvertFrom-CSV -Header URL,Title,VisitTime,VisitCount,VisitedFrom,WebBrowser,UserProfile,BrowserProfile,URLLength,TypedCount |
	ForEach-Object{
		$visitTime = if($_.VisitTime){([datetime]::ParseExact($_.VisitTime,"G",$null)).ToUniversalTime().GetDateTimeFormats('s')}
		
		$record = @{
			"url"=$_.URL;"title"=$_.Title;
			"timestamp"="$visitTime";
			"visit_time"="$visitTime";
			"visit_count"=$_.VisitCount;
			"visited_from"=$_.VisitedFrom;
			"web_browser"=$_.WebBrowser;
			"user_profile"=$_.UserProfile;
			"browser_profile"=$_.BrowserProfile;
			"url_length"=$_.URLLength;
			"typed_count"=$_.TypedCount;
			"_type"="browserhistory";
			"case"="$case";
			"machine"=$machine.Name;
			"date_collected"="$dateCollected"
		}
		$history += ConvertToJSON($record)
	}
	$outpath = "$outdir\\{0}_{1}_BrowserHistory.json" -f $case,$machine.Name
	$history | Set-Content "$outpath"
	Remove-Item .\history_temp.csv
}

#Get the scheduled jobs
function GetScheduledJobs
{
	$jobs = @()
    Get-WmiObject Win32_ScheduledJob |
    ForEach-Object{
        $installDate = if($_.InstallDate){$_.InstallDate.ToUniversalTime().GetDateTimeFormats('s')}
        $timeSubmitted = if($_.TimeSubmitted){$_.InstallDate.ToUniversalTime().GetDateTimeFormats('s')}
        $untilTime = if($_.UntilTime){$_.InstallDate.ToUniversalTime().GetDateTimeFormats('s')}
        $startTime = if($_.StartTime){$_.InstallDate.ToUniversalTime().GetDateTimeFormats('s')}
        scheduledJob = @{
			"caption"="$($_.Caption)";
			"description"="$($_.Description)";
			"timestamp"="$installDate";
			"install_date"="$installDate";
        	"name"="$($_.Name)";
			"status"="$($_.Status)";
			"elapsed_time"="$($_.ElapsedTime)";
			"notify"="$($_.Notify)";
        	"owner"="$($_.Owner)";
			"priority"=$_.Priority;
			"time_submitted"="$timeSubmitted";
			"until_time"="$untilTime";
        	"command"="$($_.Command)";
			"days_of_month"=$_.DaysOfMonth;
			"days_of_week"=$_.DaysOfWeek;
        	"interact_with_desktop"=$_.InteractWithDesktop;
			"job_id"=$_.JobId;
			"job_status"="$($_.JobStatus)";
        	"run_repeatedly"=$_.RunRepeatedly;
			"start_time"="$startTime";
			"_type"="scheduledjob";
			"case"="$case";
        	"machine"=$machine.Name;
			"date_collected"="$dateCollected"
		}
        $jobs += ConvertToJSON($scheduledJob)
    }
	$outpath = "$outdir\\{0}_{1}_ScheduledJobs.json" -f $case,$machine.Name
	$jobs | Set-Content "$outpath"
}

#Get the file hashes for the machine, may be problematic as even with the read sharing some files cant be hashed.
function GetFileHashes
{ 
	$md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
	$path = Convert-Path -Path {Read-Host 'Enter the location to hash:'} 
	Get-ChildItem $path -Recurse | 
	ForEach-Object{
		if (! $_.PSIsContainer) 
		{
			try
            {
    			$file = [System.IO.File]::Open($_.FullName,[System.IO.Filemode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
                $fileMD5 = [System.BitConverter]::ToString($md5.ComputeHash($file)) -replace "-",""
    			$fileSHA1 = [System.BitConverter]::ToString($sha1.ComputeHash($file)) -replace "-",""
                $file.Dispose()
            }
            catch
            {
                $fileMD5 = "Unable to hash"
                $fileSHA1 =  "Unable to hash"
            }
            finally
            {
                if($file)
                {
                    $file.Dispose()
                }
            }
			$creationTime = if($_.CreationTimeUtc){$_.CreationTimeUtc.GetDateTimeFormats("s")}
			$lastAccessTime = if($_.LastAccessTimeUtc){$_.LastAccessTimeUtc.GetDateTimeFormats("s")}
			$lastWriteTime = if($_.LastWriteTimeUtc){$_.LastWriteTimeUtc.GetDateTimeFormats("s")}
			
			$_.Name + "," + $_.FullName + ",$fileMD5,$fileSHA1,$creationTime,$lastAccessTime,$lastWriteTime," + $_.Length
		}
	}
}

function GetMFT
{
	.\RawCopy.exe "/FileNamePath:$($env:SYSTEMDRIVE)0" /OutputPath:ExtractedFiles
}

function GetHives
{
	$hives = @("COMPONENTS","SAM","SECURITY","SOFTWARE","DEFAULT","SYSTEM")
	foreach ($hive in $hives)
	{
		.\RawCopy.exe /FileNamePath:"$($env:SYSTEMROOT)\System32\config\$hive" /OutputPath:ExtractedFiles
	}
	Get-ChildItem "$($env:SYSTEMDRIVE)\Users" | 
	ForEach-Object{
		if(!$(Test-Path "ExtracedFiles\$($_.Name)"))
		{
			New-Item -ItemType directory "ExtracedFiles\$($_.Name)"
		}
		.\RawCopy.exe /FileNamePath:"$($_.FullName)\Ntuser.dat" /OutputPath:"ExtracedFiles\$($_.Name)"
	}
}

function GetRam
{
	 .\winpmem-2.1.post4.exe --format raw -o ExtractedFiles\memdump.raw
}

if($All)
{
	GetProcesses
	GetConnections
	GetHotfixes
	GetProcesses
	GetDrives
	GetDNSCache
	GetAutoruns
	GetServices
	GetSystemDetails
    GetLogonSessions
	GetBrowserHistory
    GetSystemDrivers
    GetScheduledJobs
	GetEventLogs
}

if($Autoruns)
{
	GetAutoruns
}

if($Connections)
{
	GetConnections
}

if($FileHashes)
{
	GetFileHashes
}

if($LogonSessions)
{
	GetLogonSessions
}

if($Processes)
{
	GetProcesses
}

if($Details)
{
	GetSystemDetails
}

if($EventLogs)
{
	GetEventLogs
}

if($Hotfixes)
{
	GetHotfixes
}

if($Services)
{
	GetServices
}

if($Drives)
{
	GetDrives
}

if($DNS)
{
	GetDNSCache
}

if($BrowserHistory)
{
	GetBrowserHistory
}

if($SystemDrivers)
{
	GetSystemDrivers
}