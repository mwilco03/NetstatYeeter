using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;

public class NetStatEntry
{
    public string ProcessName { get; set; }
    public string Path { get; set; }
    public string CommandLine { get; set; }
    public string ExecutablePath { get; set; }
    public int Handle { get; set; }
    public int ProcessId { get; set; }
    public int ParentProcessID { get; set; }
    public int ThreadCount { get; set; }
    public string User { get; set; }
    public string Domain { get; set; }
}

public class NetStatResult
{
    public DateTime CreationTime { get; set; }
    public string Protocol { get; set; }
    public string LocalAddress { get; set; }
    public int LocalPort { get; set; }
    public int OwningProcess { get; set; }
    public string RemoteAddress { get; set; }
    public int RemotePort { get; set; }
    public string PSComputerName { get; set; }
    public string ProcessName { get; set; }
    public string Path { get; set; }
    public string CommandLine { get; set; }
    public string ExecutablePath { get; set; }
    public int Handle { get; set; }
    public int ProcessId { get; set; }
    public int ParentProcessID { get; set; }
    public int ThreadCount { get; set; }
    public string Domain { get; set; }
    public string User { get; set; }
    public string ExecutableHash { get; set; }
    public DateTime Timestamp { get; set; }
}
public class NetStatUtility
{
    public static List<NetStatResult> GetNetStat()
    {
        var netStatList = new List<NetStatResult>();

        var processObject = new Dictionary<int, NetStatEntry>();
        var networkObject = new Dictionary<int, NetStatResult>();

        var processQuery = new SelectQuery("Win32_Process", "Name,Path,CommandLine,ExecutablePath,Handle,ProcessId,ParentProcessId,ThreadCount");
        using (var processSearcher = new ManagementObjectSearcher(processQuery))
        {
            foreach (var processObj in processSearcher.Get())
            {
                var processEntry = new NetStatEntry
                {
                    ProcessName = processObj["Name"]?.ToString(),
                    Path = processObj["Path"]?.ToString(),
                    CommandLine = processObj["CommandLine"]?.ToString(),
                    ExecutablePath = processObj["ExecutablePath"]?.ToString(),
                    Handle = Convert.ToInt32(processObj["Handle"]),
                    ProcessId = Convert.ToInt32(processObj["ProcessId"]),
                    ParentProcessID = Convert.ToInt32(processObj["ParentProcessId"]),
                    ThreadCount = Convert.ToInt32(processObj["ThreadCount"]),
                    User = GetProcessOwner(processObj, "User"),
                    Domain = GetProcessOwner(processObj, "Domain")
                };

                processObject[processEntry.Handle] = processEntry;
            }
        }

        var tcpQuery = new SelectQuery("MSFT_NetTCPConnection", "CreationTime,LocalAddress,LocalPort,OwningProcess,RemoteAddress,RemotePort,PSComputerName");
        using (var tcpSearcher = new ManagementObjectSearcher(tcpQuery))
        {
            foreach (var tcpObj in tcpSearcher.Get())
            {
                var owningProcess = Convert.ToInt32(tcpObj["OwningProcess"]);

                var netStatEntry = new NetStatResult
                {
                    CreationTime = ManagementDateTimeConverter.ToDateTime(tcpObj["Creation Time"].ToString()),
                    Protocol = "TCP",
                    LocalAddress = tcpObj["LocalAddress"]?.ToString(),
                    LocalPort = Convert.ToInt32(tcpObj["LocalPort"]),
                    OwningProcess = owningProcess,
                    RemoteAddress = tcpObj["RemoteAddress"]?.ToString(),
                    RemotePort = Convert.ToInt32(tcpObj["RemotePort"]),
                    PSComputerName = tcpObj["PSComputerName"]?.ToString()
                };

                networkObject[owningProcess] = netStatEntry;
            }
        }

        var udpQuery = new SelectQuery("MSFT_NetUDPEndpoint", "CreationTime,LocalAddress,LocalPort,OwningProcess,RemoteAddress,RemotePort,PSComputerName");
        using (var udpSearcher = new ManagementObjectSearcher(udpQuery))
        {
            foreach (var udpObj in udpSearcher.Get())
            {
                var owningProcess = Convert.ToInt32(udpObj["OwningProcess"]);

                var netStatEntry = new NetStatResult
                {
                    CreationTime = ManagementDateTimeConverter.ToDateTime(udpObj["CreationTime"].ToString()),
                    Protocol = "UDP",
                    LocalAddress = udpObj["LocalAddress"]?.ToString(),
                    LocalPort = Convert.ToInt32(udpObj["LocalPort"]),
                    OwningProcess = owningProcess,
                    RemoteAddress = udpObj["RemoteAddress"]?.ToString(),
                    RemotePort = Convert.ToInt32(udpObj["RemotePort"]),
                    PSComputerName = udpObj["PSComputerName"]?.ToString()
                };

                networkObject[owningProcess] = netStatEntry;
            }
        }

        foreach (var owningProcess in networkObject.Keys)
        {
            if (processObject.TryGetValue(owningProcess, out var processEntry))
            {
                var netStatEntry = networkObject[owningProcess];
                var executablePath = processEntry.ExecutablePath;

                var fileHash = GetFileHash(executablePath);

                var result = new NetStatResult
                {
                    CreationTime = netStatEntry.CreationTime,
                    Protocol = netStatEntry.Protocol,
                    LocalAddress = netStatEntry.LocalAddress,
                    LocalPort = netStatEntry.LocalPort,
                    OwningProcess = netStatEntry.OwningProcess,
                    RemoteAddress = netStatEntry.RemoteAddress,
                    RemotePort = netStatEntry.RemotePort,
                    PSComputerName = netStatEntry.PSComputerName,
                    ProcessName = processEntry.ProcessName,
                    Path = processEntry.Path,
                    CommandLine = processEntry.CommandLine,
                    ExecutablePath = processEntry.ExecutablePath,
                    Handle = processEntry.Handle,
                    ProcessId = processEntry.ProcessId,
                    ParentProcessID = processEntry.ParentProcessID,
                    ThreadCount = processEntry.ThreadCount,
                    Domain = processEntry.Domain,
                    User = processEntry.User,
                    ExecutableHash = fileHash,
                    Timestamp = DateTime.Now
                };

                netStatList.Add(result);
            }
        }

        return netStatList;
    }

    private static string GetProcessOwner(ManagementBaseObject processObj, string property)
    {
        var ownerObj = (ManagementBaseObject)processObj.InvokeMethod("GetOwner", null, null);
        return ownerObj?[property]?.ToString();
    }

    private static string GetFileHash(string filePath)
    {
        using (var md5 = System.Security.Cryptography.MD5.Create())
        {
            using (var stream = System.IO.File.OpenRead(filePath))
            {
                var hashBytes = md5.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", string.Empty);
            }
        }
    }
}
class Program
{
    static void Main(string[] args)
    {
        List<NetStatResult> netStatResults = NetStatUtility.GetNetStat();

        foreach (var result in netStatResults)
        {
            Console.WriteLine($"Process Name: {result.ProcessName}");
            Console.WriteLine($"Path: {result.Path}");
            Console.WriteLine($"Command Line: {result.CommandLine}");
            Console.WriteLine($"Executable Path: {result.ExecutablePath}");
            Console.WriteLine($"Handle: {result.Handle}");
            Console.WriteLine($"Process ID: {result.ProcessId}");
            Console.WriteLine($"Parent Process ID: {result.ParentProcessID}");
            Console.WriteLine($"Thread Count: {result.ThreadCount}");
            Console.WriteLine($"User: {result.User}");
            Console.WriteLine($"Domain: {result.Domain}");
            Console.WriteLine($"Creation Time: {result.CreationTime}");
            Console.WriteLine($"Protocol: {result.Protocol}");
            Console.WriteLine($"Local Address: {result.LocalAddress}");
            Console.WriteLine($"Local Port: {result.LocalPort}");
            Console.WriteLine($"Owning Process: {result.OwningProcess}");
            Console.WriteLine($"Remote Address: {result.RemoteAddress}");
            Console.WriteLine($"Remote Port: {result.RemotePort}");
            Console.WriteLine($"PSComputerName: {result.PSComputerName}");
            Console.WriteLine($"Executable Hash: {result.ExecutableHash}");
            Console.WriteLine($"Timestamp: {result.Timestamp}");
            Console.WriteLine();
        }

        Console.ReadLine();
    }
}
