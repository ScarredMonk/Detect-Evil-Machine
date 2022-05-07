using System;
using System.Timers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;


namespace Detect_AddComputer
{
    internal class Program
    {
        static List<KeyValuePair<string, string>> origGroupMembersList = new List<KeyValuePair<string, string>>();

        static void Main()
        {
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("______     _            _          _____      _ ____  ___           _     _         ");
            Console.WriteLine("|  _  \\   | |          | |        |  ___|    (_) |  \\/  |          | |   (_)            ");
            Console.WriteLine("| | | |___| |_ ___  ___| |_ ______| |____   ___| | .  . | __ _  ___| |__  _ _ __   ___  ");
            Console.WriteLine("| | | / _ \\ __/ _ \\/ __| __|______|  __\\ \\ / / | | |\\/| |/ _` |/ __| '_ \\| | '_ \\ / _ \\ ");
            Console.WriteLine("| |/ /  __/ ||  __/ (__| |_       | |___\\ V /| | | |  | | (_| | (__| | | | | | | |  __/ ");
            Console.WriteLine("|___/ \\___|\\__\\___|\\___|\\__|      \\____/ \\_/ |_|_\\_|  |_/\\__,_|\\___|_| |_|_|_| |_|\\___| ");
            Console.WriteLine("                                                                                 ");
            Console.WriteLine("                                                                       by @ScarredMonk");
            Console.ForegroundColor = ConsoleColor.Gray;

            try
            {
                Domain.GetCurrentDomain().ToString();
            }
            catch (Exception ex)
            { 
                Console.ForegroundColor = ConsoleColor.Red; 
                Console.WriteLine(ex.Message + "\n\nPlease run it inside the domain joined machine \n\n");
                Console.ForegroundColor = ConsoleColor.Gray;
                return;
            }

                PrincipalContext context = new PrincipalContext(ContextType.Domain, Domain.GetCurrentDomain().ToString());
                GroupPrincipal group = new GroupPrincipal(context);
                group.IsSecurityGroup = true;
                PrincipalSearcher search = new PrincipalSearcher(group);
                var allGroups = search.FindAll();

            //Saving all the members into the list
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] Computer accounts already added into security groups\n");
            Console.ForegroundColor = ConsoleColor.Gray;
            foreach (var found in allGroups)
            {
                SaveGroupMembers(found.Name);
            }

            //Checking for new machine account addition into the security groups
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[+] Monitoring the addition of new computer accounts into security groups\n");
            Console.ForegroundColor = ConsoleColor.Gray;
            while (true)
            {
                foreach (var found in allGroups)
                {
                    GetGroupMembers(found.Name);
                }
                Thread.Sleep(5000);
            }
        }

        static void SaveGroupMembers(string groupname)
        {
            PrincipalContext context = new PrincipalContext(ContextType.Domain, Domain.GetCurrentDomain().ToString());
            GroupPrincipal group = GroupPrincipal.FindByIdentity(context, IdentityType.Name, groupname);
            if (group != null && group.Name != "Domain Computers" && group.Name != "Domain Controllers")
            {

                foreach (Principal p in group.GetMembers(true))
                {
                    origGroupMembersList.Add(new KeyValuePair<string, string>(group.Name, p.Name));
                    if (p.StructuralObjectClass == "computer")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[Old] - A machine account " + p.Name + " was added in the security group " + group.Name);
                        Console.ForegroundColor = ConsoleColor.Gray;
                    }
                }
                group.Dispose();
            }
        }
        static void GetGroupMembers(string groupname)
        {
            PrincipalContext ctx = new PrincipalContext(ContextType.Domain, Domain.GetCurrentDomain().ToString());
            GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, IdentityType.Name, groupname);

            if (group != null && group.Name != "Domain Computers" && group.Name != "Domain Controllers")
            {
                foreach (Principal p in group.GetMembers(true))
                {                    
                    if (p.StructuralObjectClass == "computer")
                    {
                        var compareList = origGroupMembersList.Where(x => x.Key == group.Name && x.Value == p.Name);
                        if (!compareList.Any())
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("[New] - A machine account " + p.Name + " is added into the security group " + group.Name);
                            Console.ForegroundColor = ConsoleColor.Gray;

                            origGroupMembersList.Add(new KeyValuePair<string, string>(group.Name, p.Name));
                        }
                    }
                }
                group.Dispose();
            }
        }
    }
}