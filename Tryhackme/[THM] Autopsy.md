Link room: https://tryhackme.com/room/autopsy2ze0

What is the MD5 hash of the E01 image? 
===
Vào bên trong bảng tóm tắt information của autopsy, ta thấy được thông tin của bằng chứng trong đó có mã MD5
### Flag: 3f08c518adb3b5c1359849657a9b2079

What is the computer account name?
===

Vào bên trong `Autopsy` vào `Result-->Operating System Information` hiện thông tin tên của máy
### Flag: DESKTOP-0R59DJ3



List all the user accounts. (alphabetical order)
===
Vào bên trong `Autopsy` vào `Result-->Operating System User Information` hiện thông tin tên của các user của máy
H4S4N,joshwa,keshav,sivapriya,sandhya,srini,suba,shreya

### Flag: H4S4N,joshwa,keshav,sandhya,shreya,sivapriya,srini,suba


Who was the last user to log into the computer?
===
Vào bên trong `Autopsy` vào `Result-->Operating System User Information` hiện thông tin tên của các user của máy, kế bên có mục `Date Last Access` thấy thông tin của `sivapriya` đăng nhập lần cuối vào `12:05:37 EST`

### Flag: sivapriya


What was the IP address of the computer?
===
Để xem IP của máy, ta vào đường dẫn sau: `C:\Program Files\Look@LAN\irunin.ini`
Trong đó có phần `%LANIP%=192.168.130.216`

### Flag: 192.168.130.216

What was the MAC address of the computer? (XX-XX-XX-XX-XX-XX)
===

Để xem IP của máy, ta vào đường dẫn sau: `C:\Program Files\Look@LAN\irunin.ini`
Trong đó có phần `%LANNIC%=0800272cc4b9` đây là địa chỉ MAC của LAN

### Flag: 08-00-27-2c-c4-b9



What is the name of the network card on this computer?
===
Để xem Card đang sử dụng là card gì thì chúng ta sẽ vào bên trong `registry hive` để xem, nằm ở `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards\` bên trong `img_HASAN2.EO1/vol_col3/Windows/System32/config`

### Flag: Intel(R) PRO/1000 MT Desktop Adapter

What is the name of the network monitoring tool?
===
Network monitoring tool thì sẽ là `Look@LAN` tại vì ddayw là application monitor mạng, ta tìm thấy từ mấy câu trước, thu thập địa chỉ IP và MAC của máy

### Flag: Look@LAN



A user bookmarked a Google Maps location. What are the coordinates of the location?
===
Vào bên trong phần `Bookmark` của `Extracted Content`, tìm trong đó sẽ thấy có 1 link google map có kinh độ vĩ độ `12°52'23.0"N 80°13'25.0"E`

### Flag: 12°52'23.0"N 80°13'25.0"E



A user has his full name printed on his desktop wallpaper. What is the user's full name?
===
Tìm đến phần `NTUSER.dat` ta thấy được tên đầy đủ của user đó.

### Flag: Anto Joshwa


A user had a file on her desktop. It had a flag but she changed the flag using PowerShell. What was the first flag?
===
Nếu xem bằng mắt thường sẽ không tìm thấy đâu, sau một hồi tìm hiểu trong link ở dưới
Link [tại đây](https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics#Console%20History%20File)
Thì powershell được lưu dưới `ConsoleHost_history.txt`. Search cái file đó trong autopsy là ra kết quả.

### Flag: flag{HarleyQuinnForQueen}

The same user found an exploit to escalate privileges on the computer. What was the message to the device owner?
===
Vào bên trong Desktop của từng User --> check thấy của user `shreya` có một tệp file `ps1` đây là một tệp chứa UAV bypass leo quyền

### Flag: Flag{I-hacked-you}



2 hack tools focused on passwords were found in the system. What are the names of these tools? (alphabetical order)
===
Nhìn vào bên trong log scan của `Window Defender` trong đường dẫn sau: `ProgramData/Microsoft/Windows Defender/Scans/History/DetectionHistory/02` thấy được rằng Windef scan ra được 2 file đó là `lazagne` và `mimikatz` không biết công dụn của lazagne nhưng mà `mimikatz` dùng để crack pass thì đúng rồi =)))



There is a YARA file on the computer. Inspect the file. What is the name of the author?
===
Cái này thì search đuôi file có đuôi của yara file là đuôi `.yar`
Search một hồi thì thấy có một file `kiwi_passwords.yar` với đường dẫn bắt từ `C:\Users\H4S4N\Desktop\mimikatz_trunk\kiwi_passwords.yar`

Vào đó rồi xem ai là tác giả của file thôi

### Flag: Benjamin DELPY (gentilkiwi)


One of the users wanted to exploit a domain controller with an MS-NRPC based exploit. What is the filename of the archive that you found? (include the spaces in your answer) 
===
MS-NRPC là Microsoft netlogon remote protocol. Có một CVE về nó (có thể xem [tại đây](https://www.vietsunshine.com.vn/2020/09/24/phat-hien-va-ngan-chan-lo-hong-nghiem-trong-zerologon-windows-server/))

File được đặt tại đường dẫn `/img_HASAN2.E01/vol_vol3/Users/sandhya/AppData/Roaming/Microsoft/Windows/Recent/2.2.0 20200918 Zerologon encrypted.lnk	`

### Flag: 2.2.0 20200918 Zerologon encrypted