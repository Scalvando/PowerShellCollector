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
	  [switch]$Drives,[switch]$DNS,[switch]$BrowserHistory,[switch]$ScheduledJobs,[switch]$SystemDrivers,
	  [switch]$Hives,[switch]$MFT)

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
$outputPath = Resolve-Path $(Read-Host 'Output Path: ')
if(!$(Test-Path $outputPath))
{
	New-Item -ItemType Directory -Path $outputPath
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
			"time"="$time";
			"entry_location"=$_.EntryLocation;
			"entry"="$($_.Entry)";
			"enabled"=$_.Enabled;
			"category"=$_.Category;
			"profile"=$_.Profile;
			"description"=$_.Description;
			"company"=$_.Company;
			"path"="$($_.ImagePath)";
        	"version"=$_.Version;
			"launch_string"="$($_.LaunchString)";
			"md5"=$_.MD5;
			"sha1"=$_.SHA1;
			"pesha1"=$_.PESHA1;
        	"pesha256"=$_.PESHA256;
			"sha256"=$_.SHA256;
			"imp"=$_.IMP;
			"_type"="autorun";
        	"date_collected"="$dateCollected";
			"machine"=$machine.Name;
			"case"="$case"
		}
		$autoruns += ConvertToJSON($startupCommand)
	}
	$outputFile = "{0}_{1}_Autoruns.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $autoruns)
	
}

#This gets a list of all the services from the system
function GetServices
{
	$md5 = [System.Security.Cryptography.HashAlgorithm]::Create("MD5")#New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$sha1 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1")#New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
	$sha256 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")#New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider

	$services = @()
 
	#Iterate through all of the service objects
	Get-WmiObject Win32_Service | 
	ForEach-Object{
		#If a path exists, try and hash it
        if($_.PathName)
		{
			#Attempt to do some splitting based on switches with preceeding -'s, may not be the best way to do it
			if($_.PathName.contains("`"")){
				$path = $_.PathName.Split("`"")[1]
			}else{
				$path = $_.PathName.Split(" ")[0]
			}
			#Attempt to hash the files at the given path
            $stream = $None
			try{
				$stream = New-Object System.IO.FileStream($_.PathName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$md5_hash = [System.BitConverter]::ToString($md5.ComputeHash($stream)) -replace "-",""
			}catch{
				$md5_hash = $None
			}finally{
				if($stream){
					$stream.Dispose()		
				}
			}
			
			try{
				$stream = New-Object System.IO.FileStream($_.PathName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$sha1_hash = [System.BitConverter]::ToString($sha1.ComputeHash($stream)) -replace "-",""
			}catch{
				$sha1_hash = $None
			}finally{
				if($stream){
					$stream.Dispose()		
				}
			}

			try{
				$stream = New-Object System.IO.FileStream($_.PathName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$sha256_hash = [System.BitConverter]::ToString($sha256.ComputeHash($stream)) -replace "-",""
			}catch{
				$sha256_hash = $None
			}finally{
				if($stream){
					$stream.Dispose()		
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
			"md5"=$md5_hash;
			"sha1"=$sha1_hash;
			"sha256"=$sha256_hash;
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
	$outputFile = "{0}_{1}_Services.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $services)
}

#Get the system drivers, includes hardware drivers from driverquery and a bunch of other stuff
function GetSystemDrivers
{
	$md5 = [System.Security.Cryptography.HashAlgorithm]::Create("MD5")#New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$sha1 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1")#New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
	$sha256 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")#New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider
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
            $stream = $None
			try{
				$stream = New-Object System.IO.FileStream($_.PathName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$md5_hash = [System.BitConverter]::ToString($md5.ComputeHash($stream)) -replace "-",""
			}catch{
				$md5_hash = $None
			}finally{
				if($stream){
					$stream.Dispose()		
				}
			}
			
			try{
				$stream = New-Object System.IO.FileStream($_.PathName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$sha1_hash = [System.BitConverter]::ToString($sha1.ComputeHash($stream)) -replace "-",""
			}catch{
				$sha1_hash = $None
			}finally{
				if($stream){
					$stream.Dispose()		
				}
			}

			try{
				$stream = New-Object System.IO.FileStream($_.PathName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$sha256_hash = [System.BitConverter]::ToString($sha256.ComputeHash($stream)) -replace "-",""
			}catch{
				$sha256_hash = $None
			}finally{
				if($stream){
					$stream.Dispose()		
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
			"md5"=$md5_hash;
			"sha1"=$sha1_hash;
			"sha256"=$sha256_hash;
			"_type"="systemdriver";
			"date_collected"="$dateCollected";
			"machine"=$machine.Name;
        	"case"="$case"
		}
		$drivers += ConvertToJSON($driver) 
	}
	$outputFile = "{0}_{1}_Drivers.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $drivers)
}

#Get the running processes
function GetProcesses
{
	$md5 = [System.Security.Cryptography.HashAlgorithm]::Create("MD5")#New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$sha1 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1")#New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
	$sha256 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")#New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider

	$processes = @()
	Get-Process |
	ForEach-Object{
		#Turn start time into UTC in ISO format
		$startTime = if($_.StartTime){$_.StartTime.ToUniversalTime().GetDateTimeFormats('s')}
		if($_.Path)
		{
			$stream = $None
			try{
				$stream = New-Object System.IO.FileStream($_.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$md5_hash = [System.BitConverter]::ToString($md5.ComputeHash($stream)) -replace "-",""
			}catch{
				$md5_hash = $None
			}finally{
				if($stream){
					$stream.Dispose()		
				}
			}
			
			try{
				$stream = New-Object System.IO.FileStream($_.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$sha1_hash = [System.BitConverter]::ToString($sha1.ComputeHash($stream)) -replace "-",""
			}catch{
				$sha1_hash = $None
			}finally{
				if($stream){
					$stream.Dispose()		
				}
			}

			try{
				$stream = New-Object System.IO.FileStream($_.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$sha256_hash = [System.BitConverter]::ToString($sha256.ComputeHash($stream)) -replace "-",""
			}catch{
				$sha256_hash = $None
			}finally{
				if($stream){
					$stream.Dispose()		
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
               $stream = $None
				try{
					$stream = New-Object System.IO.FileStream($module.FileName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
					$module_md5_hash = [System.BitConverter]::ToString($md5.ComputeHash($stream)) -replace "-",""
				}catch{
					$module_md5_hash = $None
				}finally{
					if($stream){
						$stream.Dispose()		
					}
				}
				
				try{
					$stream = New-Object System.IO.FileStream($module.FileName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
					$module_sha1_hash = [System.BitConverter]::ToString($sha1.ComputeHash($stream)) -replace "-",""
				}catch{
					$module_sha1_hash = $None
				}finally{
					if($stream){
						$stream.Dispose()		
					}
				}

				try{
					$stream = New-Object System.IO.FileStream($module.FileName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
					$module_sha256_hash = [System.BitConverter]::ToString($sha256.ComputeHash($stream)) -replace "-",""
				}catch{
					$module_sha256_hash = $None
				}finally{
					if($stream){
						$stream.Dispose()		
					}
				}
                $moduleSignature = Get-AuthenticodeSignature $module.FileName

            }
            #add dll and its info to dlls
            $modules+=@{
				"name"="$($module.ModuleName)";
				"md5"=$module_md5_hash;
				"sha1"=$module_sha1_hash;
				"sha256"=$module_sha256_hash;
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
			"md5"=$md5_hash;
			"sha1"=$sha1_hash;
			"sha256"=$sha256_hash;
       		"timestamp"="$startTime";
			"start_time"="$startTime";
			"pid"=[int]$_.Id;
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
	$outputFile = "{0}_{1}_Processes.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $processes)
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
	$outputFile = "{0}_{1}_Hotfixes.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $hotfixes)
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
	
	$logs = Get-WinEvent -ListLog * | Where-Object {$_.RecordCount} | Select-Object -ExpandProperty LogName
	$logs | ForEach-Object {
		$events = @()
		Get-WinEvent -LogName $_ -Oldest | 
		ForEach-Object{
			$logName = $_  -replace "/","_" -replace " ","-"
			$outputFile = "{0}_{1}_{2}_EventLog.json" -f $case,$machine.Name,$logName
			if(Test-Path $outputFile){
				Continue
			}
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
				"uid"="$($_.UserId)";
				"version"=$_.Version;
				"message"=$_.Message;
				"pid"=[int]$_.ProcessId;
				"level"=$_.Level;
				"level_display_name"="$($_.LevelDisplayName)";
				"related_activity_id"="$($_.RelatedActivityId)";
				"event_id"=[int]$_.Id;
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
		[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $events)
	}
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
			"drive_root"="$($_.Root)";
			"free_space"=$free;
			"used_space"=$used;
			"provider"="$($_.Provider)";
			"_type"="drive";
			"date_collected"="$dateCollected";
			"case"="$case";
			"machine"=$machine.Name
		}
		$drives += ConvertToJSON($drive)
	}
	$outputFile = "{0}_{1}_Drives.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $drives)
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
		$ttl = [int]($_.Context.PostContext[1] -Split ":",2)[1] -replace " ",""
		$length = [int]($_.Context.PostContext[2] -Split ":",2)[1] -replace " ",""
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
	$outputFile = "{0}_{1}_DNSRecords.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $dnsRecords)
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
			"mtu"=[int]$_.MTU;
			"tcp_window_size"=[int]$_.TCPWindowSize;
			"service_name"=$_.ServiceName; 
			"index"=[int]$_.Index;
		}       
		$interfaces += $interface
	}
	
	$systemInformation["interfaces"] = $interfaces
	$systemInformation["_type"] = "systemdetails"
	$systemInformation["date_collected"] = "$dateCollected"
	$systemInformation["machine"] = $machine.Name
	$systemInformation["case"] = "$case"
	$systemDetails = ConvertToJSON($systemInformation)
	$outputFile = "{0}_{1}_SystemInformation.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $systemDetails)
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
			"pid"=[int]$_.PID;
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
	$outputFile = "{0}_{1}_Connections.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $connections)
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
						"pid"=[int]$proc[0].Trim();
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
			"session_id"="$($_.Sid)";
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
	$outputFile = "{0}_{1}_LogonSessions.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $logonSessions)
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
		#https://stackoverflow.com/questions/14363214/get-domain-from-url-in-powershell
		$record = @{
			"url"=$_.URL;
			"domain"=([System.Uri]$_.URL).Host -replace '^www\.';
			"title"=$_.Title;
			"timestamp"="$visitTime";
			"visit_time"="$visitTime";
			"visit_count"=[int]$_.VisitCount;
			"visited_from"=$_.VisitedFrom;
			"web_browser"=$_.WebBrowser;
			"user_profile"=$_.UserProfile;
			"browser_profile"=$_.BrowserProfile;
			"url_length"=[int]$_.URLLength;
			"typed_count"=[int]$_.TypedCount;
			"_type"="browserhistory";
			"case"="$case";
			"machine"=$machine.Name;
			"date_collected"="$dateCollected"
		}
		$history += ConvertToJSON($record)
	}
	Remove-Item .\history_temp.csv
	$outputFile = "{0}_{1}_BrowserHistory.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $history)
	
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
			"job_id"=[int]$_.JobId;
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
	$outputFile = "{0}_{1}_ScheduledJobs.json" -f $case,$machine.Name
	[System.IO.File]::WriteAllLines("$outputPath\\$outputFile", $jobs)
}

#Get the file hashes for the machine, may be problematic as even with the read sharing some files cant be hashed.
function GetFileHashes
{ 
	#http://blog.brianhartsock.com/2008/12/13/using-powershell-for-md5-checksums/
	$md5 = [System.Security.Cryptography.HashAlgorithm]::Create("MD5")#New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$sha1 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1")#New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
	$sha256 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")#New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider
	$pathname = Read-Host 'Enter the location to recursively hash'
	$path = Convert-Path -Path $pathname
	$outpath = "$outputPath\\{0}_{1}_Files.json" -f $case,$machine.Name
	Get-ChildItem $path -Recurse | 
	ForEach-Object{
		if (!$_.PSIsContainer) 
		{
			$stream = $None
			try{
				$stream = New-Object System.IO.FileStream($_.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$fileMD5 = [System.BitConverter]::ToString($md5.ComputeHash($stream)) -replace "-",""
			}catch{
				$fileMD5 = $None
			}finally{
				if($stream){
					$stream.Dispose()		
				}
			}
			
			try{
				$stream = New-Object System.IO.FileStream($_.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$fileSHA1 = [System.BitConverter]::ToString($sha1.ComputeHash($stream)) -replace "-",""
			}catch{
				$fileSHA1 = $None
			}finally{
				if($stream){
					$stream.Dispose()		
				}
			}

			try{
				$stream = New-Object System.IO.FileStream($_.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$fileSHA256 = [System.BitConverter]::ToString($sha256.ComputeHash($stream)) -replace "-",""
			}catch{
				$fileSHA256 = $None
			}finally{
				if($stream){
					$stream.Dispose()		
				}
			}

			$creationTime = if($_.CreationTimeUtc){$_.CreationTimeUtc.GetDateTimeFormats("s")}
			$lastAccessTime = if($_.LastAccessTimeUtc){$_.LastAccessTimeUtc.GetDateTimeFormats("s")}
			$lastWriteTime = if($_.LastWriteTimeUtc){$_.LastWriteTimeUtc.GetDateTimeFormats("s")}
			$file_info = @{
				"timestamp"="$lastWriteTime";
				"file_name"=$_.Name;
				"path"=$_.FullName;
				"md5"=$fileMD5;
				"sha1"=$fileSHA1;
				"sha256"=$fileSHA256;
				"creation_time"="$creationTime";
				"last_access_time"="$lastAccessTime";
				"last_write_time"="$lastWriteTime";
				"file_size"=$_.Length
			}
			$jsonFile = ConvertToJSON($file_info)
			Add-Content "$outpath" "$jsonFile`n"
		}	
	}
}

function GetMFT
{
	if(!$(Test-Path "$outputPath\MFT"))
	{
		New-Item -ItemType directory "$outputPath\MFT"
	}
	
	if($architecture -eq "64-bit")
	{
		.\RawCopy64.exe /FileNamePath:"$($env:SYSTEMDRIVE)0" /OutputPath:"$outputPath\MFT"
	}
	else
	{
		.\RawCopy.exe /FileNamePath:"$($env:SYSTEMDRIVE)0" /OutputPath:"$outputPath\MFT"
	}
}

function GetHives
{
	if(!$(Test-Path "$outputPath\Hives\$($_.Name)"))
	{
		New-Item -ItemType directory "$outputPath\Hives"
	}
	
	#$hives = @("COMPONENTS","SAM","SECURITY","SOFTWARE","DEFAULT","SYSTEM")
	Get-ChildItem "$($env:SYSTEMROOT)\System32\config\" | where { ! $_.PSIsContainer -and ![System.IO.Path]::hasExtension($_)} | 
	ForEach-Object {
		$_.Name
		if($architecture -eq "64-bit")
		{
			.\RawCopy64.exe /FileNamePath:"$($_.FullName)" /OutputPath:"$outputPath\Hives"
		}
		else
		{
			.\RawCopy.exe /FileNamePath:"$($_.FullName)" /OutputPath:"$outputPath\Hives"
		}
	}
	Get-ChildItem "$($env:SYSTEMDRIVE)\Users" | 
	ForEach-Object{
		$_.FullName
		if(!$(Test-Path "$outputPath\Hives\$($_.Name)"))
		{
			New-Item -ItemType directory "$outputPath\Hives\$($_.Name)"
		}
		if(Test-Path "$($_.FullName)\Ntuser.dat")
		{
			if($architecture -eq "64-bit")
			{
				.\RawCopy64.exe /FileNamePath:"$($_.FullName)\Ntuser.dat" /OutputPath:"$outputPath\Hives\$($_.Name)"
			}
			else
			{
				.\RawCopy.exe /FileNamePath:"$($_.FullName)\Ntuser.dat" /OutputPath:"$outputPath\Hives\$($_.Name)"
			}
		}
	}
}

function GetRam
{
	 .\winpmem-2.1.post4.exe -o RAMCapture\memdump.raw
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
if($Hives)
{
	GetHives
}

if($MFT)
{
	GetMFT
}