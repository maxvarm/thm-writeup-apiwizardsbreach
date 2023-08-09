# TryHackMe - APIWizards Breach Writeup
The room is set from Blue Team point of view and represents a breach of Ubuntu VM hosting some web application via Nginx.
As DFIR analyst, you have to access the VM via SSH and investigate what happened and what is the impact.

## Initial Access
1. **Which programming language is a web application written in?**

Login via SSH as the given "dev" user. The first option is to review Nginx config, listening ports, or running processes.
The second option is simply to check application source code. In any case, the answer is:
```
Python
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/1.png?raw=true)


2. **What VPN did the malicious actor use to perform the web attack?**

From Nginx logs you can see a lot of scanning-like requests from an external IP, which is clearly not something legitimate.
Upon checking the IP on Threat Intelligence services like https://spur.us/context/149.34.244.142, you should receive the same response:
```
Proton VPN
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/2.png?raw=true)

3. **Which vulnerability was found and exploited in the API service?**

After a web scan, the hackers found a vulnerable URI parameter in /api/time endpoint. After URI-decoding the requests, you can clearly see the following pattern:
* /api/time?tz=" whoami #
* /api/time?tz=" id #
* /api/time?tz=" which ssh #
* /api/time?tz="; echo "ssh-ed25519 AAAAC...dP" >> /home/dev/.ssh/authorized_keys #

The result of these requests is command execution, starting with basic user discovery and ending with SSH key persistence on "dev" user.
You can review the ~/apiservice/src/api.py to understand how it works, but the answer is:
```
OS Command Injection
```

4. **Which file contained the credentials used to privesc to root?**

The question can be answered by either looking into source code, grepping for passwords, or checking bash history.
Luckily, bash history is configured to be logged in realtime, so most interactive commands are seen in clear. The answer is:
```
/home/dev/apiservice/src/config.py
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/3.png?raw=true)

5. **What file did the hacker drop and execute to persist on the server?**

This is the part where hackers gained root privileges. As you may see from bash history, their first step was to upload something from transfer.sh service.
The uploaded file seems to be binary to persist on the servers. Either because of self-destruction or server reboot, the malware is no longer on disk. The answer is:
```
/tmp/rooter2
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/4.png?raw=true)

6. **Which service was used to host the “rooter2” malware?**

Related to the previous question, the malware was downloaded from transfer.sh, "easy file sharing from the command line" cloud service.
The service is often used by hackers for ingress tool transfer since it is easy to use and destroy malware link after delivery. The answer is:
```
transfer.sh
```

## Further Actions
1. **Which two system files were infected to achieve cron persistence?**

There are multiple locations to store cron jobs, but given that "rooter2" was run from root, it is either system-wide cron or root one.
By manually checking cronjob locations you can find a strange job evaluating SYSTEMUPDATE env variable every day at 4:20 AM.
The content of the variable is a simple bash reverse shell to an unknown public IP, so this is the backdoored cron job.
The last question is how hackers populate this variable, given that cron jobs do not store user-specific variables, and use only system-wide.
Again, either grepping for malicious IP in /etc or by reviewing common locations like /etc/environment, you should find the answer:
```
/etc/crontab, /etc/environment
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/5.png?raw=true)

2. **What is the C2 server IP address of the malicious actor?**

The IP is shown in plaintext in a cron job from the previous question and perhaps in other persistence methods used by hackers. The answer is:
```
5.230.66.147
```

3. **What port is backdoored bind bash shell listening at?**

Bind shell, also known as forward shell, is basically a service that listens on some port (usually TCP) and creates a shell session upon connection.
Something similar to Telnet, you can read more about bind shells [here](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/linux#forward-shell). The investigation workflow starts with reviewing listening ports, looking for uncommon processes or port numbers.
Netcat process running as root and listening on 3578 port looks suspicious, and further process tree analysis confirms it
to be a netcat bind shell, somehow running in background. The answer is:
```
3578
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/6.png?raw=true)

4. **How does the bind shell persist across reboots?**

You should see that bind shell activity started from systemd(1) process, followed by bash, and finally netcat process.
It is neither a command entered via SSH nor another cronjob since there are no sshd or cron processes in the tree. The next most
common option would be a systemd service, basically a standard for running applications in the background. The answer is:
```
systemd service
```

5. **What is the absolute path of the malicious service?**

Related to the previous question, you can grep for "nc -l" pattern in all possible systemd locations. It should return a single service,
cleverly masqueraded as "socket.service". You can confirm that it is configured to run after boot and restart upon netcat termination every 20 seconds.
The answer is:
```
/etc/systemd/system/socket.service
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/7.png?raw=true)


## Even More Persistence
1. **Which port is blocked on victim's firewall??**

Listing iptables rules should give you the answer. Port 3578 is used by hackers as bind shell port, so they made sure to close it for everyone except for their C2 IP. The answer is:
```
3578
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/8.png?raw=true)


2. **How do the firewall rules persist across reboots?**

Obviously, the backdoored rules should somehow survive iptables flush or server reboot. Excluding rootkits or binary modifications, you can assume that malicious iptables definitions are stored somewhere in system files used to run commands periodically or by some trigger. Grepping for "iptables" or C2 IP should work.
Note the additional curl command in a backdoored .bashrc file, with sends an HTTP request to hackers upon root login. This is most likely done to notify the hackers about malicious rules "fix". The answer is:
```
/root/.bashrc
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/9.png?raw=true)


3. **How is the backdoored local Linux user named?**

A backdoored user should have a convenient shell like /bin/bash, be created within the attack timeline, and preferably be in a privileged group.
With this in mind, you can easily search for newly-created accounts or grep for all interactive accounts and exclude trusted ones one by one.
The backdoored user is:
```
support
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/10.png?raw=true)


4. **Which privileged group was assigned to the user?**

For hackers, a privileged group usually means "a group that grants your root, at least partially". Such groups are: admin, docker, disk, and most notably sudo.
Sudo group privileges, combined with default /etc/sudoers configuration and a password known only to hackers, give the support account unlimited root access on the server. Running "id <user>" or "groups <user>" gives you the answer:
```
sudo
```

5. **What is the comment on the backdoored SSH key?**

SSH public key authentication can be backdoored by either [modifying a legitimate public key](https://blog.thc.org/infecting-ssh-public-keys-with-backdoors) or by adding a new one. In both cases, the files containing the keys are /root/authorized_keys or /home/*/authorized_keys. Note that hackers created two keys, one
left in /home/dev/.ssh/authorized_keys during Initial Access without any comments. And the second left in /root/.ssh/authorized_keys with a specific "ntsvc" comment. So the answer is:
```
ntsvc
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/11.png?raw=true)


6. **Can you spot and name one more popular persistence method?**

Or maybe not so popular 🙂. At least this is the method I observed multiple times and really enjoyed because of its simplicity and effectiveness against EDR detections. Unfortunately, auditd or other auditing tools are not enabled, and the method is not seen in bash history, indicating "rooter2" malware activity.
In any case, the method is mentioned in multiple blogs and GitHub repos, for example [this one](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md).

One great way to detect the persistence is to use "find" command with [ctime flag](https://bytexd.com/how-to-use-find-with-atime-ctime-mtime-amin-cmin-mmin) set to attack the timeline. Ctime can not be changed by ordinary means, unlike mtime which is often masked by attacks to hide their traces.
Of course, you can go step by step manually, reviewing every binary or configuration file. Eventually, you should find that the answer is:
```
SUID binary
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/12.png?raw=true)


7. **What are the original and the backdoored binaries from question 6?**

While you already know the backdoor name (/bin/clamav), it is not yet known how it is used by hackers. Either by checking backdoor hash on VirusTotal, checking its strings, or even running the binary, you should notice that it is a /bin/bash copy. The exploitation is shown on [GTFOBins](https://bytexd.com/how-to-use-find-with-atime-ctime-mtime-amin-cmin-mmin). The answer is:
```
/bin/bash, /bin/clamav
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/13.png?raw=true)


8. **What technique was used to hide the backdoor creation date?**

Run "ls -l /bin/bash /bin/clamav" and see that their creation date is the same. Most users would think that clamav is some sort of a system file, if it was created during OS installation, together with bash binary. However, "ls" command shows mtime which can be overridden by hackers, and it is a common defense
evasion technique to hide creation date of a backoor. Technique name is:
```
Timestomping
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/14.png?raw=true)

## Final Target
1. **Which file did the "rooter2" malware drop containing gathered victim's info?**

Using the same "find" technique you can find the needed dropped file. However, I am sure that you have already found a strange ".dump.json" file in root folder while doing previous tasks. It is a strangely-encoded JSON file that contains base64-encoded values of victim's info. The answer is:
```
/root/.dump.json
```

2. **According to the dropped dump, what is the server’s kernel version?**

Open the dump from the previous question, base64-decode the second "C1" value, and split it by two colons. One of the values is victim's kernel version sent to hackers as a part of system discovery. The answer is:
```
5.15.0-78-generic
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/15.png?raw=true)


3. **Which active internal IPs were found by the “rooter2” network scan?**

The same way decode "C2" value and see that each string is an open port, scanned by "rooter2". Most likely the malware scanned a small internal subnet and only the most common TCP ports like RDP, SSH, or HTTP. Once of the IPs may be the victim's IP itself, but another one is clearly an online server. The answer is:
```
192.168.0.21, 192.168.0.22
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/16.png?raw=true)

4. **How did the hacker find an exposed HTTP index on another internal IP?**

To answer this question, you should definitely come back to root bash history. After dump reviewal, the hackers decided to perform a more aggressive scan of the internal IP. They utilized netcat to scan TCP ports of 1024-10000 range, and looks like they found something interesting. The answer is:
```
nc -zv 192.168.0.22 1024-10000 2>&1 | grep -v failed
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/17.png?raw=true)


5. **What command was used to exfiltrate CDE database from the internal IP?**

Looking further into bash history, port scan is followed by a communication over 8080 port, ending with discovery and download of cardholder data environment database partial backup file. It is safe to assume that someone left an exposed HTTP index on 8080 port that had different sensitive files exposed, including database backup, perhaps for some QA or debugging purposes. Note that hackers renamed the original file to ".review.csv". The answer is:
```
wget 192.168.0.22:8080/cde-backup.csv
```

6. **What is the most secret and precious string stored in the exfiltrated database?**

Of course it's not about leaked names, emails, and even not about credit cards. It is about a flag! 🙂
Hope you enjoyed the room and ApiWizards Inc. would harden their web application and internal network
```
pwned{v3ry-secur3-cardh0ld3r-data-environm3nt}
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/blob/main/images/18.png?raw=true)
