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
