Link room: https://tryhackme.com/room/c2carnage

```
What was the date and time for the first HTTP connection to the malicious IP?(answer format: yyyy-mm-dd hh:mm:ss)
```

Filter `http` thì ta thấy được thời gian đầu tiên mà gói http được gửi tới 

<p align ="center">
  <img src="https://github.com/P5ySm1th/CTF/assets/100250271/242926c2-89a4-4d5f-b9e3-5fec07cdbd46">
</p>

### Flag: 2021-09-24 16:44:38

```
What is the name of the zip file that was downloaded?
```
Nhìn vào bên trong filter `http` ta thấy có một `zip file` ở pdu thứ `1735`

### Flag: documents.zip

```
 What was the domain hosting the malicious zip file?
```
Trace theo đống `TCP stream` hoặc `HTTP stream` của pdu thứ `1735` ta sẽ thấy được `host` của nó:

### Flag: attirenepal.com


```
Without downloading the file, what is the name of the file in the zip file?
```
Trace theo đống `TCP stream` hoặc `HTTP stream` của pdu thứ `1735` kéo xuống dưới ta thấy được header là `PK` chứng tỏ đây đúng là file zip. Dựa theo cấu trúc file zip như hình dưới

<p align ="center">
  <img src="https://github.com/P5ySm1th/CTF/assets/100250271/f1c5a5e1-7114-469a-a92c-51d8cb65a75e">
</p>

Thì ta sẽ có được tên file bên trong đó mà không cần phải download xuống . 

<p align ="center">
  <img src="https://github.com/P5ySm1th/CTF/assets/100250271/cfa2e454-ebd3-4697-be5f-76a05fe40a4a">
</p>

### Flag: chart-1530076591.xls


```
What is the name of the webserver of the malicious IP from which the zip file was downloaded?
```
Trace theo đống `TCP stream` hoặc `HTTP stream` của pdu thứ `1735` ta sẽ thấy server của nó đang chạy

### Flag: LiteSpeed

```
What is the version of the webserver from the previous question?
```
Trace theo đống `TCP stream` hoặc `HTTP stream` của pdu thứ `1735` ta sẽ thấy version của webserver

### Flag: PHP/7.2.34


```
Malicious files were downloaded to the victim host from multiple domains. What were the three domains involved with this activity?
```

Trace từ `ip.src == 10.9.23.102` sau thời điểm 2021-09-24 16:44:38 ta thấy được nó trỏ tới ba tên miền lần lượt như sau:
    finejewels.com.au, thietbiagt.com, new.americold.com

### Flag: finejewels.com.au, thietbiagt.com, new.americold.com


```
Which certificate authority issued the SSL certificate to the first domain from the previous question?
```
Dựa vào thằng web `finejewels.com.au` ta nhận biết được rằng đây là https và có chứng chỉ ssl, vào bên trong http stream, thấy được chứng chỉ ssl 

### Flag: godaddy


```
What are the two IP addresses of the Cobalt Strike servers? Use VirusTotal (the Community tab) to confirm if IPs are identified as Cobalt Strike C2 servers. (answer format: enter the IP addresses in sequential order) 
```
Đọc qua các bài viết sau đây:
- https://michaelkoczwara.medium.com/cobalt-strike-hunting-simple-pcap-and-beacon-analysis-f51c36ce6811
- https://www.mandiant.com/resources/blog/defining-cobalt-strike-components

Thì mình đã hiểu sơ lược về Cobalt Strike, ở đây mình sẽ tìm dựa theo `HTTP GET request` thì thấy được 1 địa chỉ IP có `Cobalt Strike` là 185.106.96.158. Còn IP còn lại thì mình chịu thua, lên google hỏi cách nhận biết `Cobalt Strike` HTTPS có vẻ là khá khó vì nó đã được mã hóa bằng TLS :( nhưng mà nếu mình tìm mẫu này ở trên mạng thì đã có người phân tích ở đây:
- https://dxc.com/us/en/insights/perspectives/report/dxc-security-threat-intelligence-report/february-2022-/is-squirrelwaffle-the-next-big-malspam-

### Flag: 185.106.96.158, 185.125.204.174

```
 What is the Host header for the first Cobalt Strike IP address from the previous question?
```
Để tìm host header thì chỉ cần dùng filter `ip.addr == 185.106.96.158` rồi trace theo `TCP stream` thì ra kết quả

### Flag: ocsp.verisign.com

```
 What is the domain name for the first IP address of the Cobalt Strike server? You may use VirusTotal to confirm if it's the Cobalt Strike server (check the Community tab). 
```

Có thể tìm trên trang [này](https://dxc.com/us/en/insights/perspectives/report/dxc-security-threat-intelligence-report/february-2022-/is-squirrelwaffle-the-next-big-malspam-) Đây là một report nói về malspam. Hoặc nếu được thì chúng ta có thể search theo filter sau để tìm thấy được `dns` của nó: `dns`

### Flag: survmeter.live

```
 What is the domain name of the second Cobalt Strike server IP?  You may use VirusTotal to confirm if it's the Cobalt Strike server (check the Community tab). 
```
Tương tự như trên

### Flag: securitybusinpuff.com 

```
What is the domain name of the post-infection traffic?
```

Vào mục Statistic --> HTTP --> request thấy được ngay là khi bị nhiễm cobalt strike thì nó sẽ làm gì. HTTP request gửi đi sẽ trở nên khacs ntn.

### Flag: maldivehost.net

```
What are the first eleven characters that the victim host sends out to the malicious domain involved in the post-infection traffic? 
```
Dựa vào cấu trúc của request mà ta biết được đáp án =))

### Flag: zLIisQRWZI9


```
 What was the length for the first packet sent out to the C2 server? 
```
Filter theo cách sau sẽ ra được packet đầu tiên gửi. Vì là gửi nên sẽ thực hiện POST method `http.request.method == POST`

### Flag: 281

```

The malware used an API to check for the IP address of the victim’s machine. What was the date and time when the DNS query for the IP check domain occurred? (answer format: yyyy-mm-dd hh:mm:ss UTC)

```
Kiểm tra trên mạng với từ khóa `API for checking IP ` thì nhận ra rằng có một API có tên là `ipify` dựa vào đây tìm kiếm trên wireshark ta có được flag

### Flag: 2021-09-24 17:00:04

```
What was the domain in the DNS query from the previous question?
```
Dựa vào đó trace ra tên domain từ DNS query thôi 

### Flag: api.ipify.org
```
 Looks like there was some malicious spam (malspam) activity going on. What was the first MAIL FROM address observed in the traffic? 
```
search theo filter `smtp` ta sẽ ra được đáp án 

### Flag: farshin@mailfa.com


```
How many packets were observed for the SMTP traffic?
```
Vào bên trong protocol hierarichy là thấy :) 

### Flag: 1439