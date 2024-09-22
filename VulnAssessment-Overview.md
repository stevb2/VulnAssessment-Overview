# Conducting a vulnerability scan using **Nessus** example

- **Details:**
    - Shows setting up a scan, configuring scan policies, and running the scan.
    - Provides a sample vulnerability report detailing the findings (e.g., unpatched software, insecure configurations).
    - Offers remediation steps based on the vulnerabilities found.

### Nessus Setup

Initializing Nessus
![Pasted image 20240921173353](https://github.com/user-attachments/assets/e46a0004-b26e-4395-a9b6-13d22079e0aa)


### Metasploitable 3

Preparing a test using [metasploitable3](https://github.com/rapid7/metasploitable3) .

```powershell
choco install vagrant virtualbox
mkdir metasploitable3-workspace
cd metasploitable3-workspace
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rapid7/metasploitable3/master/Vagrantfile" -OutFile "Vagrantfile"
vagrant up win2k8 --provider=virtualbox
```

![Pasted image 20240921210147](https://github.com/user-attachments/assets/b27ad054-fbeb-40b7-a015-964faf97a64d)

```powershell
PS C:\Users\CommandoVM\Desktop\metasploitable3-workspace > nmap -sC -sV 192.168.56.3
Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-21 18:03 Pacific Daylight Time
NSOCK ERROR [0.1140s] ssl_init_helper(): OpenSSL legacy provider failed to load.

Nmap scan report for 192.168.56.3
Host is up (0.00088s latency).
Not shown: 991 filtered tcp ports (no-response)
PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
22/tcp    open  ssh      OpenSSH 7.1 (protocol 2.0)
| ssh-hostkey:
|   2048 fd0898ca3ce8c13ceadd091a2e89a51f (RSA)
|_  521 7e57818ef63c1dcfeb7dbad11231b5a8 (ECDSA)
80/tcp    open  http     Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
4848/tcp  open  ssl/http Oracle Glassfish Application Server
|_http-server-header: GlassFish Server Open Source Edition  4.0
|_ssl-date: 2024-09-22T01:05:48+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=localhost/organizationName=Oracle Corporation/stateOrProvinceName=California/countryName=US
| Not valid before: 2013-05-15T05:33:38
|_Not valid after:  2023-05-13T05:33:38
|_http-title: Did not follow redirect to https://192.168.56.3:4848/
8080/tcp  open  http     Sun GlassFish Open Source Edition  4.0
|_http-server-header: GlassFish Server Open Source Edition  4.0
|_http-title: GlassFish Server - Server Running
| http-methods:
|_  Potentially risky methods: PUT DELETE TRACE
8383/tcp  open  http     Apache httpd
|_http-server-header: Apache
|_http-title: 400 Bad Request
9200/tcp  open  wap-wsp?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=UTF-8
|     Content-Length: 80
|     handler found for uri [/nice%20ports%2C/Tri%6Eity.txt%2ebak] and method [GET]
|   GetRequest:
|     HTTP/1.0 200 OK
|     Content-Type: application/json; charset=UTF-8
|     Content-Length: 314
|     "status" : 200,
|     "name" : "Sharon Ventura",
|     "version" : {
|     "number" : "1.1.1",
|     "build_hash" : "f1585f096d3f3985e73456debdc1a0745f512bbc",
|     "build_timestamp" : "2014-04-16T14:27:12Z",
|     "build_snapshot" : false,
|     "lucene_version" : "4.7"
|     "tagline" : "You Know, for Search"
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Content-Type: text/plain; charset=UTF-8
|     Content-Length: 0
|   RTSPRequest, SIPOptions:
|     HTTP/1.1 200 OK
|     Content-Type: text/plain; charset=UTF-8
|_    Content-Length: 0
49153/tcp open  msrpc    Microsoft Windows RPC
49154/tcp open  msrpc    Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9200-TCP:V=7.93%I=7%D=9/21%Time=66EF6CF8%P=i686-pc-windows-windows%
SF:r(GetRequest,191,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20applicatio
SF:n/json;\x20charset=UTF-8\r\nContent-Length:\x20314\r\n\r\n{\r\n\x20\x20
SF:\"status\"\x20:\x20200,\r\n\x20\x20\"name\"\x20:\x20\"Sharon\x20Ventura
SF:\",\r\n\x20\x20\"version\"\x20:\x20{\r\n\x20\x20\x20\x20\"number\"\x20:
SF:\x20\"1\.1\.1\",\r\n\x20\x20\x20\x20\"build_hash\"\x20:\x20\"f1585f096d
SF:3f3985e73456debdc1a0745f512bbc\",\r\n\x20\x20\x20\x20\"build_timestamp\
SF:"\x20:\x20\"2014-04-16T14:27:12Z\",\r\n\x20\x20\x20\x20\"build_snapshot
SF:\"\x20:\x20false,\r\n\x20\x20\x20\x20\"lucene_version\"\x20:\x20\"4\.7\
SF:"\r\n\x20\x20},\r\n\x20\x20\"tagline\"\x20:\x20\"You\x20Know,\x20for\x2
SF:0Search\"\r\n}\n")%r(HTTPOptions,4F,"HTTP/1\.0\x20200\x20OK\r\nContent-
SF:Type:\x20text/plain;\x20charset=UTF-8\r\nContent-Length:\x200\r\n\r\n")
SF:%r(RTSPRequest,4F,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/plai
SF:n;\x20charset=UTF-8\r\nContent-Length:\x200\r\n\r\n")%r(FourOhFourReque
SF:st,A9,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plai
SF:n;\x20charset=UTF-8\r\nContent-Length:\x2080\r\n\r\nNo\x20handler\x20fo
SF:und\x20for\x20uri\x20\[/nice%20ports%2C/Tri%6Eity\.txt%2ebak\]\x20and\x
SF:20method\x20\[GET\]")%r(SIPOptions,4F,"HTTP/1\.1\x20200\x20OK\r\nConten
SF:t-Type:\x20text/plain;\x20charset=UTF-8\r\nContent-Length:\x200\r\n\r\n
SF:");
MAC Address: 08:00:27:7F:C7:74 (Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.62 seconds
```


### Nessus Dynamic Scan Parameters

Setting the parameters for the PCI Audit scan
![Pasted image 20240921225658](https://github.com/user-attachments/assets/88731500-3b58-456b-a02a-277c6a2388ae)

![[Pasted image 20240921225515.png]]

Using the Administrator Credentials as part of this scan
![Pasted image 20240921225950](https://github.com/user-attachments/assets/d0254209-6657-4cdd-9a82-5be408d0b3b0)

Checking for a specific plugin.
![Pasted image 20240921230729](https://github.com/user-attachments/assets/5883abfe-00cd-4398-b84f-37e87a7697e9)

Executing the scan
![Pasted image 20240921231623](https://github.com/user-attachments/assets/f106a326-4b10-4314-9eba-67f01fa37be1)


### Nessus Scan Results

Interpreting the results of the scan
![Pasted image 20240921232219](https://github.com/user-attachments/assets/6378068a-0330-49d0-bc17-a8574aa53f23)


Hosts
![Pasted image 20240921232245](https://github.com/user-attachments/assets/a319f11d-c356-49c6-a9d6-eac8af65a7ed)

Vulnerabilities
![Pasted image 20240921232309](https://github.com/user-attachments/assets/7ad01507-90b9-4176-ad95-2965c2eec7cb)

Remediations
![Pasted image 20240921232329](https://github.com/user-attachments/assets/6665c694-d0d7-4104-b87c-86c5af295dae)


Generating a Report
![Pasted image 20240921232507](https://github.com/user-attachments/assets/04a0f865-e4f6-4f6e-82ba-5dd79ff5f2c2)


Reports Example
![Pasted image 20240921232746](https://github.com/user-attachments/assets/f891fc87-b19c-4813-9dd8-489a09397667)

