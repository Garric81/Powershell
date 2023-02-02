#Demos - Performance Management

#region - View performance data
    #Counter commands
    Get-command *-counter
    
    #Start Remote-Registry service for monitoring
    get-service -ComputerName DC1 -Name RemoteRegistry | Start-Service

    #Viewing commond Data
    Get-counter -ListSet * -ComputerName DC1 | select CounterSetName,Description

    get-counter -ListSet *memory* -ComputerName DC1 | 
        Where CounterSetName -EQ 'Memory'
          
    get-counter -ListSet *memory* -ComputerName DC1|
        Where CounterSetName -EQ 'Memory'|
            select -expand Counter
    
    #View Memory\Available MBytes sampled every 2 seconds w/ 3 total samples
    Get-Counter `
        -ComputerName DC1 `
        -Counter "Memory\Available MBytes" `
        -SampleInterval 2 `
        -MaxSamples 3
 
    #View Common information for Server
    $Counters = 'Processor(_Total)\% Processor Time', `
                "Memory\Available MBytes", `
                "PhysicalDisk(0 c:)\Current Disk Queue Length", `
        "Network Interface(intel[r] 82574l gigabit network connection)\Output Queue Length"

    Get-Counter `
        -ComputerName dc1 `
        -Counter $counters `
        -SampleInterval 2 `
        -MaxSamples 3

    #Export data to file 
    New-Item -Path \\dc1\demos\demos-performance -ItemType Directory
    Invoke-Command -ComputerName DC1 {

        $Counters = '\Processor(_Total)\% Processor Time', `
                        "Memory\Available MBytes", `
                        "PhysicalDisk(0 c:)\Current Disk Queue Length", `
        "Network Interface(intel[r] 82574l gigabit network connection)\Output Queue Length"

            Get-Counter `
            -ComputerName dc1 `
            -Counter $Counters `
            -SampleInterval 5 `
            -MaxSamples 3  |
                Export-Counter -Path \\dc1\demos\demos-performance\Counters.csv -Force   
        }
    import-counter -Path \\dc1\demos\demos-performance\Counters.csv |Out-GridView

    $import = import-counter -Path \\dc1\demos\demos-performance\Counters.csv
    
    $samples = $import.countersamples
    
    $Samples|fl
    
    $memory = $samples | where path -like *memory*
    
    $memory

    $memory.cookedvalue|measure -Average
#endregion

#region - Gathering Information with WMI & CIM
Get-CimClass -ClassName CIM*

Get-CimClass -ClassName *disk* -ComputerName DC1

Get-WmiObject -class Win32_logicaldisk -ComputerName DC1

Get-CimInstance -ClassName CIM_LogicalDisk -ComputerName DC1 |fl

#Viewing freespace
((Get-CimInstance -ClassName Win32_logicaldisk -ComputerName DC1|
     where DeviceID -EQ 'C:').FreeSpace)/1GB

#Last Reboot
(Get-CIMInstance -ClassName Win32_OperatingSystem –ComputerName DC1).LastBootUpTime

#endregion

#region - Event Logs
    #Reviewing Event Logs
    help Get-EventLog -Examples
    
    #Information about event logs on system
    Get-EventLog -list -ComputerName DC1

    #View Warning and Error events in System on DC1
    Get-EventLog -ComputerName DC1 `
        -LogName System `
        -Newest 50 `
        -EntryType Error,Warning | ft -AutoSize
    
    #View Details of specific event
    Get-EventLog -ComputerName DC1 `
        -LogName System `
        -Index 9988 | ft Index,ErrorType,Message -AutoSize -Wrap
             

    #Check on the last time DC1 was reboot
    Get-EventLog -log system –newest 1000 -ComputerName DC1|
        where-object {$_.eventid –eq '1074'} |
            format-table machinename, username, timegenerated, message –autosize -Wrap
    
    #Export System for last 14 days for support call
    $now=get-date
    $startdate=$now.adddays(-14)
    
    Get-Eventlog -Log system -ComputerName DC1 -After $startdate|
        export-csv -Path \\dc1\demos\demos-performance\Export.csv
    
    notepad \\dc1\demos\demos-performance\Export.csv
#endregion

#region - Troubleshooting a Website
#Test Network and DNS
    start iexplore.exe http://www.moarcoffee.com
    
    Test-NetConnection www.moarcoffee.com

    Test-NetConnection 192.168.95.40

    Test-NetConnection www.moarcoffee.com -CommonTCPPort HTTP

    #Test another Website on server
    Test-NetConnection www.wiredbrain.priv

    Test-NetConnection 192.168.95.90

    Test-NetConnection www.wiredbrain.priv -CommonTCPPort HTTP

    #Check services on server
    Invoke-Command -ComputerName Server1 {get-service -Name w3svc}

    Invoke-Command -ComputerName Server1 {start-service -Name w3svc}

    Test-NetConnection www.moarcoffee.com -CommonTCPPort HTTP

    start iexplore.exe http://www.moarcoffee.com



    #To Recreate, simply stop the w3svc service on Server1
    #Invoke-Command -ComputerName Server1 {stop-service -Name w3svc}
#endregion