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
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/assets/24703293/84b853e6-ae54-42b1-b109-ebdf25c9955f)


2. **What VPN did the malicious actor use to perform the web attack?**

From Nginx logs you can see a lot of scanning-like requests from an external IP, which is clearly not something legitimate.
Upon checking the IP on Threat Intelligence services like https://spur.us/context/149.34.244.142, you should receive the same response:
```
Proton VPN
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/assets/24703293/1f72407c-ce15-4317-b12e-ac516dc97027)

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
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/assets/24703293/02684759-ac79-4d49-8d8b-f16e0e7c19b3)

5. **What file did the hacker drop and execute to persist on the server?**

This is the part where hackers gained root privileges. As you may see from bash history, their first step was to upload something from transfer.sh service.
The uploaded file seems to be binary to persist on the servers. Either because of self-destruction or server reboot, the malware is no longer on disk. The answer is:
```
/tmp/rooter2
```
![image](https://github.com/maxvarm/thm-writeup-apiwizardsbreach/assets/24703293/a1c6f612-3d29-4af1-a633-1939b36ecb65)

6. **Which service was used to host the “rooter2” malware?**

Related to the previous question, the malware was downloaded from transfer.sh, "easy file sharing from the command line" cloud service.
The service is often used by hackers for ingress tool transfer since it is easy to use and destroy malware link after delivery. The answer is:
```
transfer.sh
```

## Further Actions
1. **Which two system files were infected to achieve cron persistence?**
2. **What is the C2 server IP address of the malicious actor?**
3. **What port is backdoored bind bash shell listening at?**
4. **How does the bind shell persist across reboots?**
5. **What is the absolute path of the malicious service?**
## Even More Persistence
1. **Which firewall rule blocks backdoor access from other IPs?**
2. **How do the firewall rules persist across reboots?**
3. **How is the backdoored local Linux user named?**
4. **Which privileged group was assigned to the user?**
5. **What is the comment on the backdoored SSH key?**
6. **Can you spot and name one more popular persistence method?**
7. **What are the original and the backdoored binaries from question 6?**
8. **What technique was used to hide the backdoor creation date?**
## Final Target
1. **Which file did the "rooter2" malware drop containing gathered victim's info?**
2. **According to the dropped dump, what is the server’s kernel version?**
3. **Which active internal IPs were found by the “rooter2” network scan?**
4. **How did the hacker find an exposed HTTP index on another internal IP?**
5. **What command was used to exfiltrate CDE database from the internal IP?**
6. **What is the most secret and precious string stored in the exfiltrated database?**




