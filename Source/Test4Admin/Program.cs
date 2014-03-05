using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace Test4Admin
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Test For Admin\n");

            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            Console.WriteLine(String.Format("Executing User is: {0}", identity.Name));

            String displayName = "";
            try
            {
                displayName = Principal.FindByIdentity(new PrincipalContext(ContextType.Machine | ContextType.Domain), IdentityType.Sid, identity.User.ToString()).Description;
            }
            catch(Exception ex)
            {
                //No domain available
                displayName = Principal.FindByIdentity(new PrincipalContext(ContextType.Machine), IdentityType.Sid, identity.User.ToString()).Description;
            }

            if(displayName != null) 
                Console.WriteLine(String.Format("Executing User has Description: {0}", displayName));

            foreach( var claim in identity.Claims)
            {
                Console.WriteLine(String.Format("Has Claim: {0}, {1}", claim.Type.ToString(), claim.Value.ToString())); 
            }

            foreach (var claim in identity.DeviceClaims)
            {
                Console.WriteLine(String.Format("Has Device Claim: {0}, {1}", claim.Type.ToString(), claim.Value.ToString()));
            }

            PrincipalContext pc = new PrincipalContext(ContextType.Machine);
            foreach (var group in identity.Groups)
            {
                displayName = Principal.FindByIdentity(pc, IdentityType.Sid, group.ToString()).DisplayName;
                if (displayName == null)
                    displayName = "<unknown>";
                Console.WriteLine(String.Format("Is in Group: {0}, {1}", displayName, group.Translate(typeof(NTAccount)).Value));
            }

            Console.WriteLine();

            var test = Test4Admin.UacHelper.IsUserIsAnAdmin;
            Console.WriteLine(String.Format("Is User An Admin? {0}", test.ToString()));

            test = Test4Admin.UacHelper.IsUacEnabled;
            Console.WriteLine(String.Format("Is UAC Enabled? {0}", test.ToString()));

            test = Test4Admin.UacHelper.IsProcessElevated;
            Console.WriteLine(String.Format("Is Process Elevated? {0}", test.ToString()));

            Console.WriteLine("\nPress any key to Quit.");
            Console.ReadKey();
        }
    }
}
