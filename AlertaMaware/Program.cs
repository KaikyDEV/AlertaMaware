using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;

class MalwareProtection
{
    static string directoryPath = @"C:\Caminho\Para\Seu\Diretório";

    static void Main(string[] args)
    {
        Console.WriteLine("Iniciando monitoramento de proteção contra malware...");

        CheckFilesForMalware(directoryPath);

        MonitorProcesses();
    }

    static void CheckFilesForMalware(string path)
    {
        if (Directory.Exists(path))
        {
            string[] files = Directory.GetFiles(path);
            foreach (var file in files)
            {
                try
                {
                    FileSecurity fileSecurity = File.GetAccessControl(file);
                    AuthorizationRuleCollection rules = fileSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

                    foreach (FileSystemAccessRule rule in rules)
                    {
                        if (rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights.HasFlag(FileSystemRights.Write))
                        {
                            Console.WriteLine($"Alerta: O arquivo '{file}' tem permissões de escrita públicas.");
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine($"Erro ao acessar as permissões do arquivo {file}. Permissão negada.");
                }
            }
        }
        else
        {
            Console.WriteLine("O diretório especificado não existe.");
        }
    }
    static void MonitorProcesses()
    {
        Process[] processes = Process.GetProcesses();
        foreach (Process process in processes)
        {
            try
            {
                if (process.ProcessName.ToLower().Contains("malware") || process.ProcessName.ToLower().Contains("trojan"))
                {
                    Console.WriteLine($"Alerta: O processo suspeito '{process.ProcessName}' está em execução.");
               
                }
            }
            catch (AccessDeniedException)
            {
                Console.WriteLine("Acesso negado ao processo. Não foi possível verificar o processo.");
            }
        }
    }
}