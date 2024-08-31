# CreateChester CTF Challenege 2022 
Welcome to my createchester 2022 CTF challenge writeup. CreateChester is a dynamic event where four departments from the computing courses - Computer Science, Cybersecurity, Games Devlopment and Software Engineering come together to parcitipate in a exciting chanllenge that includes a game Jam, Hackethon, and Capture the Flag compettion. 

I have selected to particpate in the Capture the Flag event, this will be a whole writeup that our group submitted. Our group came 2nd in the event out of 7 groups and consist of gorups of 5-6 students. 

The group consist of: 1 level 6 (Cyber), myself level 5 (Cyber), 2x level 4 (cyber), 2x level 4 (Computer science)

I will also upload a pdf file of the report. 

file:///G:/ctf%202023/CTF%202022%20createchester%20group%204.pdf

# Scenario 

The teams has been provided with a .ova ubuntu file and a Ciphertext, we were tasked:

•	Access the machine by any means necessary

•	Find the flags 

•	Perform a vulnerability Assessment 

•	A provided PCAP file inside (Perform a detailed analysis of its purpose)

•	Decrypted the Cipher text 


You get 10 points per flag/task completion. 

more points with be awarded for clear documentation and SPAG.

Each completion of the task or flag found will contain a clue for the next flag/task.

If you get stuck along the way, requesting for a hint will deduct 5 points from your total score. 

# The Writeup

## Introduction 

This document covers the exploitation of a vulnerable machine provided for the event createChester2022, this is a basic box, with a straight through method of solving. Though this documents the concepts of brute force, steganography, hashes, and general cryptography should become clearer as you follow the report.

A variety of tools and techniques will be explained and practically demonstrated with several screenshots that should make you reader be able to recreate all steps to solve each challenge. The starting point is obtaining access, either through brute force or using tools to directly inspect the DISK to uncover key files. Following successful access, next step is persistence though the creation of modification of authorized_keys file, following that file extraction mostly via SCP and file analysis via various common/open-source tools to reveal the hidden flags.

![image](https://github.com/user-attachments/assets/99dbc9e3-68fc-49ad-ba52-98967da76205)

## 1. Rules of Engagement 
As per the brief, the rules of engagement are as follows:

![image](https://github.com/user-attachments/assets/4bdc71b7-dedd-43f6-b19f-237e54994438)

Consequently, other methods of breaching the box, namely repair utility, disk inspection and remote attacks should all be considered valid.

## 2. Enumeration 
Through a network wide port scan via Nmap with default scripts(-sC) and version enumeration(-sV) excluding host, note the following.

![image](https://github.com/user-attachments/assets/a5130e9b-81af-45d5-ade7-0b3bd2afec82)

As show above, is possible to determine that OpenSSH version 8.9p1 is running on port 22 for secure shell [SSH] is open on an Ubuntu box, which ultimately determines a clear entry vector. 

Additionally, at first glance when launching createChesterCTF-22.ova, the following login screen provides three usernames.

![image](https://github.com/user-attachments/assets/97a0effe-c5da-46be-a662-dba6194ab228)

## 3. Accruing access 
At this phase, towards maximising efficiency the team focused on entry without resorting to brute force as the rules of engagement do not clearly define conditions against the use of repair utilities. Nevertheless, the team separated efforts and obtained access via repair utility, traditional SSH brute force though hydra, and accessed the disk directly with FTK Imager.

### 3.1 Repair utility approach (Rescatux) 
This section covers the use of Rescatux a graphical wizard for rescuing broken GNU/Linux and Windows installations (Rescatux, 2010).

Changing the target’s password.    

![image](https://github.com/user-attachments/assets/a27f46d2-c6d2-4fb0-90e5-e53cdd136622)

Select automatic, it should work for most cases.

![image](https://github.com/user-attachments/assets/ee31e8a0-9b4d-4f74-8388-876e4c0f1575)

Using default settings, the team continued the process.

![image](https://github.com/user-attachments/assets/b7696898-6e19-4a02-b1d0-f1d70cd648d2)

![image](https://github.com/user-attachments/assets/c12279e1-c5c0-456c-923d-8a25df814ce6)

Following the steps below the team managed to change the target’s credentials.

![image](https://github.com/user-attachments/assets/2939171d-7b16-49bb-90f6-a9019cf3eca7)

![image](https://github.com/user-attachments/assets/e83a31a7-da4d-49d4-b8da-bd500d834a79)

![image](https://github.com/user-attachments/assets/732d440a-3860-4c00-9e45-0bbfcc2c24c3)

Root account is disabled by default in Ubuntu so there is no point in activating user “root” as the user can simply sign in as “root” by executing “sudo su” and inputting the current user’s password, providing it is a sudoer.

After this process close the virtual machine whilst making sure return to current snapshot is disabled.

![image](https://github.com/user-attachments/assets/dc212286-0584-42ef-a2db-97ae68935fae)

Remove the disk from the optical drive.

![image](https://github.com/user-attachments/assets/b5d9564b-b1f2-409d-9d0e-b61128880d89)

Upon booting up and signing in as “peter” privileges are checked with “sudo -l”, essentially administrator privileges.

![image](https://github.com/user-attachments/assets/285790f8-e907-4bcb-8262-57baaf2814e0)

### 3.2 Brute force entry (Hydra)

Through THC Hydra a parallelized network login cracker the following command was used.

![image](https://github.com/user-attachments/assets/2ade8b9a-3c19-41c1-abab-173f0b01bd01)

The team brute forced each listed user with a famous wordlist know as rockyou.txt as illustrated below.

![image](https://github.com/user-attachments/assets/f2a994f0-1037-42d6-81a4-ff5381fb14dd)

Right after a positive match for user “smith1”, the team initiated a session via SSH and checked the user’s privilege level and consider the next figure.

The SSH initiated successfully and greeted the user with “To run a command as administrator…” (red rectangle) which means the user might be a sudoer, to verify this the command “sudo -l” to list all commands permitted and prohibited for the invoking user.

![image](https://github.com/user-attachments/assets/d4c66562-a705-4040-918c-f1cdf780f40c)

The SSH initiated successfully and greeted the user with “To run a command as administrator…” (red rectangle) which means the user might be a sudoer, to verify this the command “sudo -l” to list all commands permitted and prohibited for the invoking user.

![image](https://github.com/user-attachments/assets/f51bd888-3be2-4075-aff2-0c0aa3601675)

At this point the machine is compromised system wide allowing for vertical and lateral movement.

### 3.3 Digital Forensic approach (FTK Imager)

Convert “VDI” to “VHD” to facilitate analysis.

![image](https://github.com/user-attachments/assets/a59b0508-6657-430e-ac6e-d9ccccbbbac2)

Locate copy of “VDI” to “VHD”.

![image](https://github.com/user-attachments/assets/3fbc0681-8a18-4a2c-ad0b-089b660c2d35)

Provide the “VHD” file as evidence.

![image](https://github.com/user-attachments/assets/6e51545a-701d-475c-890c-1549b5e534c2)

Check user’s home folders for relevant content.

![image](https://github.com/user-attachments/assets/64978dc1-6b38-4f7d-9cc3-bc474ce8791a)

Additionally, one could also find files for password cracking within directory “/etc/”.

![image](https://github.com/user-attachments/assets/c06b0a68-5f96-472f-9871-f2d5d9b5ba19)

Additionally, checked the contents of “viminfo” from “/home/peter/.viminfo”. 

![image](https://github.com/user-attachments/assets/d64f06ff-e405-418b-960d-6c88e5ac068c)

## 4. Escalation of Privilege 
This section covers three methods of privilege escalation, one that relies on cracking user passwords, and another that takes advantage of an active user with sudo privileges.

### 4.1 Passwd and shadow files 

As mentioned on the previous section, user “smith1” is a sudoer, thus the team could simply take advantage of this and directly alter the designated target user “peter”. However, we decided to approach the task though exfiltrating the “passwd” and “shadow” files from the directory “/etc/” with Secure Copy [scp] respectively shown under.

![image](https://github.com/user-attachments/assets/30960868-9652-49bb-b625-be27004aa04d)

After exfiltration, both files are combined though “unshadow” a utility from John the Ripper that originates an output file more readable for the cracking tool.

![image](https://github.com/user-attachments/assets/14d94dd5-b831-4f8d-88f3-a3982b814422)

#### 4.1.1 Exploring passwd and shadow combo 

Upon looking at the combination file, as expected for an Ubuntu box the root user is disabled by default which explains the output of the following command.

![image](https://github.com/user-attachments/assets/5473a3f5-db95-45f8-b16f-2ea4fe0d6a71)

Root has no hash attribution therefore, this evidences that superuser tasks are invoked and ran by users with root privileges without the need of enabling the “root” user.

Additionally, user passwords are hashed with an algorithm known as “Yescrypt” developed by Solar Designer illustrated below with “$y$” as highlighted. Unfortunately, hashcat does not support this algorithm yet, however John the Ripper does thanks to libxcrypt (roycewilliams, 2021).

![image](https://github.com/user-attachments/assets/0dd524a9-b186-4d10-b349-039c51d62dab)

#### 4.1.2 John the Ripper 

Towards cracking the user hashes, the requirements are simple, combo file (passwd+shadow) and a wordlist. The command must use the flag “--format=crypt” since the hashing algorithm is “Yescrypt” otherwise no hashes will be loaded, the command follows the subsequent syntax.

```bash
john.exe --format=crypt --wordlist=rockyou.txt PsShCombo.txt
```

![image](https://github.com/user-attachments/assets/2be9340a-7587-4d1e-81a3-db261927d1c1)

After a while the cracking tool should output peter’s password “qwertyuio”.

### 4.2 Altering the user password remotely

The team began by login in as “smith1” a user with root privileges and changing the password of user “peter”

![image](https://github.com/user-attachments/assets/d32d09aa-bffa-495d-a9bc-8c4ec4f1e13d)

## 5. Maintaining Access 
Towards maintaining persistent access, the team generated an ssh-rsa key and copied it to the targeted machine under the user “peter”. 

![image](https://github.com/user-attachments/assets/30a2ad2f-99c7-440d-8b39-f67a4c2855fe)

Checking if file was successfully created.

![image](https://github.com/user-attachments/assets/9e5c5cf0-3ff7-4f8f-810f-99541c491c43)

After this effort, the attacker can login without having to provide a password.

![image](https://github.com/user-attachments/assets/9f8d4a31-a452-4f6d-ae37-ebbcef76b852)

## 6. Exfiltration of files (Tasks)
After locating the target’s home directory, all the files from “/home/peter/Desktop/” were transferred recursively via scp, for further analysis. Consider the following syntax and figure.

```bash
scp -r /local/directory remote_username@10.0.2.15:/remote/directory
```

![image](https://github.com/user-attachments/assets/014eed93-c59f-4ce7-87a2-d519da420330)

From our newly gained access to the system, we discovered 4 files on the desktop, these being an unnamed text document, an image, a PCAP file and an unknown binary file named with what at first appeared to be gibberish.

In the subsequent sections the team will address each file individually and provide insight.

### 6.1 Steganography 

The team decided to start with the image file “CTF.png” to determine if any messages had been hidden within. This proved to be true, as the image had a flag hidden within the data via steganography, or the art of obscuring data within an inconspicuous file, as illustrated below.

![image](https://github.com/user-attachments/assets/2c67e305-a3a9-4a0d-85ac-4fa24e32e282)

This technique writes data into the least significant bit of pixels of a given image. The command above checks for both least significant bit and most significant bit as these methods are often used when hiding data in images with no passphrase assigned making it difficult to use other tools like “steghide” and “binwalk”.

### 6.2 Suspicious named file examination 

The extracted data from the image file from the previous subsection pointed us towards a file on the desktop directory with the strange name. We started by using “hexdump -C” to determine if there was any header data that could be found to determine what type of file it was.

![image](https://github.com/user-attachments/assets/8ac4b449-671c-4be6-a0a6-3856ef9a5fb5)

The file contained the VimCrypt3 header, telling us that it was a text file encrypted with vim. From this we could tell we needed a password, and as the brief contained the hint that the filename could help with unlocking the file, we discovered that it was 32 characters in length and looked suspiciously like a hash. As such, the team used a hash identifier and found it was an MD5 hash. Which when decrypted turned out to be “123456789”.

![image](https://github.com/user-attachments/assets/409f9a83-3e68-442d-b757-c6d09c5897cb)

When opening this file with vim, the user is prompted for a password, coincidentally the password was the output of the MD5 hash decryption.

![image](https://github.com/user-attachments/assets/778c0d3e-0782-461e-8767-0f6137423c64)

After authenticating the following flag is revealed.

![image](https://github.com/user-attachments/assets/8b2056f8-e1db-47b9-9e46-11cc5358bb92)

### 6.3 PCAP analysis 

With the use of Nethor a packet analyser and visualisation tool (Nethor, n.d.), the team uncovered that the contents of this PCAP file contain communication between three relevant IP addresses noted below.

![image](https://github.com/user-attachments/assets/4bc59324-262f-47cf-a384-92556fecc7bf)

![image](https://github.com/user-attachments/assets/e04767e4-2985-421f-a872-299516200631)

![image](https://github.com/user-attachments/assets/a58746e2-87e4-4a14-9ac3-7ffee60cb8ab)

Considering the next conversation diagram, is possible to determine that there is a significant volume of traffic between 192.168.193.73 and 10.86.74.7.

![image](https://github.com/user-attachments/assets/c0daaef8-25cc-4f14-99af-72aa8f586283)

Additionally, with the previous information in mind, is possible to determine that Class A IPs [10.x.x.x] and Class C [192.168.x.x] are clearly from a different network. 

Technically if approaching the task from the standpoint that Class A IPs use a netmask of 255.0.0.0 it would be possible to think of them in the same network, but this could easy change if the subject was a Class B IP.

By taking a closer look to the PCAP file consider that when routers perform Address resolution protocol or ARP for short, they make a request for each host as the protocol is resolving exclusively Class C IPs, thus it’s impossible to determine the correlation between “10.86.74” and “10.85.174.87” as the capture was performed in an external network outside the scope of Class A IPs.

![image](https://github.com/user-attachments/assets/270d197b-7dfa-483f-a486-4ec9f1369d0b)

Consequently, due to the capture taking place outside the scope of Class A IPs so is not possible to determine the netmask, thereby is impossible to determine if they are in the same network.

Note the variety of files were contained in the “PCAP” file revealed that “192.168.193.74” was hosting a site known as “MotvilleStudios” illustrated below are the respective file correlation within the “index.html” file.

![image](https://github.com/user-attachments/assets/0594839d-408c-4ddc-bf58-b4145b1ee6a8)

Furthermore, after stringing the PCAP and querying for keywords nothing of real value was found.

![image](https://github.com/user-attachments/assets/4a192f27-2afb-4751-bdc2-74692638632b)

### 6.4 Suspicious file on the “/etc/” directory 

Referring to the previous subsection the team found the file named “system-”, this file was encrypted with vimcrypt.

![image](https://github.com/user-attachments/assets/0bd370c1-b842-4726-99a3-a9af9eddf667)

Also, when examining the “/etc/” directory one file stands out because of the permissions as highlighted note subsequent image.

![image](https://github.com/user-attachments/assets/97aa3a12-a426-4f73-9d16-3a10f20a3cdd)

Since the previous flag suggests the password should be listed in the results of the google search “most common password 2022” after a couple guesses the file is successfully decrypted with key=123456.

Opening this file provides us with the following flag.

![image](https://github.com/user-attachments/assets/f8a29081-7385-4582-9960-34b40cd3a8b5)

Upon better inspection, the plaintext shows the output of “journalctl --user” which is a utility that allows for searching and display of various logs, in this case those of the current invoking user “kali”.

The team used grep with regex to highlight IP addresses.

![image](https://github.com/user-attachments/assets/57a96381-6ad1-491c-b7e6-8036136f5e2c)

The following simply show the event of the sshd service listening for incoming connections from the host via IP “0.0.0.0” a non-routable address.

![image](https://github.com/user-attachments/assets/3a470877-108f-46b2-97ec-1a61f355b4b7)

Following this “192.168.56.100” and “192.168.56.103” attempt to secure an SSH session as root which fails.

![image](https://github.com/user-attachments/assets/c81acff5-8dc1-46a5-8253-6c2dc90c3ba2)

Immediately after, the same IPs try to connect under a different user “cyber1” resulting in a successful connection.

![image](https://github.com/user-attachments/assets/01dbd9a8-70fa-4fb0-8818-5f153ed1069a)

However, it appears the targeted user detected this intrusion and halted the session.

![image](https://github.com/user-attachments/assets/56f8caaa-6b1e-4e36-8aeb-266783e4211e)

### 6.5 Suspicious empty file 

The file titled as “Untitled Document 1” appears to simply be a file containing the sting “Nothing here.”, any data streams would show on the hex dump. Additionally, any zero-width space Unicode would show on the hex dump, thus this file is simply what it appears to be.

![image](https://github.com/user-attachments/assets/ad2b1501-a13e-4ec3-96ff-fac050b4e5d6)

## 7. Covering tracks
This stage was performed using a tool known as “covermyass” a shell script for the purpose of covering tracks or disabling system logs for the post exploitation phase (sundowndev, 2018).

Running “covermyass” followed by a “systemctl halt” command to power off the system.

![image](https://github.com/user-attachments/assets/99e76485-4ea6-4e82-bf94-b29d3f5d50d0)

## 8. Cipher text decrypting 

To decode the ciphered text, the Shifted Alphabet decoding method was incorporated as the ciphered text was a Caeser Cipher. For this method, every letter in the ciphered text was shifted to the right by 1 until all the letters formed words. The result took 24 shifts to the right to achieve the correct letter placements.

Cipher Text:

"vjg kfgc qh htgswgpea cpcnauku, cnuq mpqyp cu eqwpvkpi ngvvgtu, ku vjg uvwfa qh vjg htgswgpea qh ngvvgtu qt itqwRu qh nGvvgtu kp c ekrjgtVgzv. vjg oGvjqf ku wugf cu cp ckf vq dTgcmkpi encuukecn ekrjgtu. htgswgpea cpcnauku ku dcugf qp vjg hcev vjcv, kp cpa ikxgp uvtgvej qh ytkvvgp ncpiwcig, egtvckp ngvvgtu cpf eqodkpcvkqpu qh ngvvgtu qeewt ykvj xctakpi htgswgpekgu. oqtgqxgt, vjgtg ku c ejctcevgtkuvke fkuvtkdwvkqp qh ngvvgtu vjcv ku tqwijna vjg ucog hqt cnoquv cnn ucorngu qh vjg ncpiwcig."

Decrypted:

"the idea of frequency analysis, also known as counting letters, is the study of the frequency of letters or grouPs of lEtters in a cipherText. the mEthod is used as an aid to bReaking classical ciphers. frequency analysis is based on the fact that, in any given stretch of written language, certain letters and combinations of letters occur with varying frequencies. moreover, there is a characteristic distribution of letters that is roughly the same for almost all samples of the language."

The capitalised letters within the decrypted cipher reads “PETER”.

## 9. Vulnerability Assessment 
For this we used Linpeas.sh, a script that shows all possible paths for privilege escalations. We can use this to find common vulnerabilities within the machine. First create a python web server, then curl the script into the machine and execute using bash. 

![image](https://github.com/user-attachments/assets/6a720ceb-070e-4633-8a5b-6c9ffbc34587)

CVE’s found: 

[CVE-2022-32250] nft_object UAF [CVE-2022-2586] nft_object UAF [CVE-2022-0847] DirtyPipe

[CVE-2021-4034] PwnKit

[CVE-2021-3156] sudo Baron Samedit [CVE-2021-3156] sudo Baron Samedit 2

[CVE-2021-22555] Netfilter heap out-of-bounds write

The Ubuntu machine is running kernel version 5.15.0-52-generic and as such no POC exploits can work.

# Conclusion 
In conclusion, the team found the challenge to be an easily solvable box, which touches and allows for the exploration of serval cybersecurity related concepts that would serve a foundation for individuals who are not fully enveloped in the field.

Additionally, the rules of engagement defined on the brief allowed for extreme flexibility despite only covering three of the methods there exists a wide variety of possibilities to compromise this box.
