
## **Overview**

- **Difficulty:** Easy
- **Operating System:** Linux
- **Objective:** Capture flag via FTP
- **Tools Used:** `nmap`, `ftp`, `openvpn`

---

## **Scanning using Nmap**

Started with a nmap scan to get information about whether telnet was running on port 21 as mentioned in the task.
```
$ sudo nmap -sV 10.129.217.234
[sudo] password for alice: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-02 18:43 IST
Stats: 0:00:47 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 18:44 (0:00:07 remaining)
Nmap scan report for 10.129.217.234
Host is up (1.7s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 132.38 seconds
```

SMB is open at 445.

---

## **Accessing SMB at 10.129.71.129**

Now, let's `smbclient` into said IP with the `-N` and `-L` flag to be able to login without signing in with a password and list.
```
$ smbclient -N -L \\\\10.129.217.234

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	WorkShares      Disk      
tstream_smbXcli_np_destructor: cli_close failed on pipe srvsvc. Error was NT_STATUS_IO_TIMEOUT
SMB1 disabled -- no workgroup available
```

As we see `WorkShares` does not have admin needs, so thats where we're hitting.

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