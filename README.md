![Total Writeups](https://img.shields.io/badge/CTF%20Writeups-185-blue?style=flat)
![Pentesting](https://img.shields.io/badge/Pentesting-19-blue?style=flat)
![IDS/IPS](https://img.shields.io/badge/IDS%2FIPS-2-blue?style=flat)
![Network Forensics](https://img.shields.io/badge/Network%20Forensics-27-blue?style=flat)
![SIEM](https://img.shields.io/badge/SIEM-16-blue?style=flat)
![Digital Forensics](https://img.shields.io/badge/Digital%20Forensics-58-blue?style=flat)
![Email Analysis](https://img.shields.io/badge/Email%20Analysis-5-blue?style=flat)
![CTI](https://img.shields.io/badge/CTI-8-blue?style=flat)
![Malware Analysis](https://img.shields.io/badge/Malware%20Analysis-16-blue?style=flat)
![Reverse Engineering](https://img.shields.io/badge/Reverse%20Engineering-3-blue?style=flat)

# CTF Writeups
Welcome to my CTF Writeups repository! Here, I document the solutions and methodologies used to solve various Capture The Flag (CTF) challenges. This repository is intended to serve as a learning resource for others interested in cybersecurity and CTF competitions.
Capture The Flag (CTF) competitions are a popular way to practice and improve cybersecurity skills. These competitions present various challenges that require problem-solving, creativity, and technical knowledge. This repository contains my writeups for different CTF challenges I have participated in.

## Writeups
The writeups in this repository (located in the "writeups" folder) are categorised based on the nature of the challenges. Each writeup provides step-by-step solutions, along with explanations of the tools and techniques used. The difficulty rating associated with each challenge matches the difficulty rating given by the platform hosting the challenge/lab/ctf, therefore, take it with a grain of salt as some challenges rated as hard are actually easy, etc. The rating is out of 5, where 5 stars means I enjoyed the challenge and 1 being I didn't find it enjoyable. 

Disclaimer! In all honesty, some of these writeups are written poorly, mainly because I complete them to learn practical skills, not to practice reporting. When it comes to well written writeups, I recommend reading my most recent ones (i.e., those furthest down in the tables). 

## Where to Start
I recommend starting with the easy or medium rated challenges, there is honestly little difference between the two ratings for the most part. You can find challenges associated with each difficulty rating by clicking CTRL + F and pasting one of the following tags:
- 🟢 Easy
- 🟡 Medium
- 🔴 Hard
  
When it comes to what platform to use, that depends on your interests and skill level. For DFIR (digital forensics and incident response) and CTI (cyber threat intelligence) based challenges I highly recommend CyberDefenders, as it provides the most realistic challenges and often requires the use of VMs or a home lab. If you are a beginner, TryHackMe is a great place to start, as it often provides a VM or you can always use the AttackBox which comes preinstalled with a bunch of tools. Lastly, if you want to learn about and practice security operations, I recommend checking out blue team labs online (BTLO).

## Table of Contents
- [Pentesting](#pentesting)
- [IDS/IPS](#idsips)
- [SIEM (ELK, Splunk, etc.)](#siem-elk-splunk-etc)
- [Digital Forensics](#endpoint-forensics)
- [Email Analysis](#email-analysis)
- [Cyber Threat Intelligence (CTI)](#cyber-threat-intelligence-cti)
- [Network Forensics](#network-forensics)
- [Malware Analysis](#malware-analysis)
- [Reverse Engineering](#reverse-engineering)
- [Tools Used](#tools-used)
- [Acknowledgments](#acknowledgments)
- [Personal Platform Profiles](#personal-platform-profiles)

### **Pentesting**
This section contains writeups focused on penetration testing. Challenges are typically boot2root which involve scanning, enumeration, vulnerability analysis and exploitation, privilege escalation, and more. Great for building foundation penetration testing skills and learning common attacks. 
| Challenge        | Writeup                                                                                | Challenge Link                                                     | Difficulty | Rating | Tags | 
| ---------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |------------|----------|-----------------------------|
| Basic | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/hack_this_site_basic.pdf) | [HackThisSite](https://www.hackthissite.org/missions/basic/) | 🟡 Medium | ⭐⭐⭐ | `burp suite` |
| Silver Platter | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/silver_platter.pdf) | [TryHackMe](https://tryhackme.com/r/room/silverplatter) | 🟢 Easy | ⭐⭐⭐ | `Nmap` `GoBuster` `ssh` `privilege escalation` |
| Dav | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/dav.pdf) | [TryHackMe](https://tryhackme.com/r/room/bsidesgtdav) | 🟢 Easy | ⭐⭐⭐ | `Nmap` `GoBuster` `hydra` `privilege escalation` |
| Wgel CTF | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/wgel_ctf.pdf) | [TryHackMe](https://tryhackme.com/r/room/wgelctf) | 🟢 Easy | ⭐⭐⭐ | `Nmap` `dirb` `ssh` `privilege escalation` |
| Lookup | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/lookup.pdf) | [TryHackMe](https://tryhackme.com/r/room/lookup) | 🟢 Easy | ⭐⭐⭐⭐ | `Nmap` `hydra` `searchsploit` `metasploit` `privilege escalation` |
| Toolsrus | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/toolsrus_writeup.pdf) | [TryHackMe](https://tryhackme.com/r/room/toolsrus) | 🟢 Easy | ⭐⭐⭐ | `Nmap` `dirbuster` `hydra` `nikto` `metasploit` `msfvenom` |
| Raven 1 | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/raven_writeup.pdf) | [VulnHub](https://www.vulnhub.com/entry/raven-1,256/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `arp-scan` `Nmap` `GoBuster` `wpscan` `nikto` `hydra` `ssh` `mysql` |
| Pickle Rick | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/pickle_rick_writeup.pdf) | [VulnHub](https://www.vulnhub.com/entry/rickdiculouslyeasy-1,207/) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Nmap` `GoBuster` `nikto` `privilege escalation` |
| Mr Robot | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/mr_robot_writeup.pdf) | [VulnHub](https://www.vulnhub.com/entry/mr-robot-1,151/) | 🟡 Medium | ⭐⭐⭐⭐ | `arp-scan` `Nmap` `GoBuster` `nikto` `wpscan` `hydra` `hashcat` `privilege escalation` |
| Photographer | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/photographer_writeup.pdf) | [VulnHub](https://www.vulnhub.com/entry/photographer-1,519/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `arp-scan` `Nmap` `GoBuster` `nikto` `enum4linux` `SMB` `burp suite` |
| Lazy Admin | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/lazyadmin_ctf.pdf) | [VulnHub](https://www.vulnhub.com/entry/lazysysadmin-1,205/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Nmap` `GoBuster` `hash-identifier` `searchsploit` `privilege escalation` |
| IDE | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/ide_writeup.pdf) | [TryHackMe](https://tryhackme.com/r/room/ide) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Nmap` `FTP` `searchsploit` `ssh` `privilege escalation` |
| Easy peasy | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/easy_peasy_writeup.pdf) | [TryHackMe](https://tryhackme.com/r/room/easypeasyctf) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Nmap` `GoBuster` `hash-identifier` `CyberChef` `steghide` `ssh ` `privilege escalation` |
| Colddbox Vulnhub | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/colddbox_writeup.pdf) | [VulnHub](https://www.vulnhub.com/entry/colddbox-easy,586/) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Nmap` `GoBuster` `wpscan` `hydra` `privilege escalation` |
| Colddbox THM | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/colddbox_thm_writeup.pdf) | [TryHackMe](https://tryhackme.com/r/room/colddboxeasy) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Nmap` `GoBuster` `wpscan` `hydra` `privilege escalation` |
| Bounty Hacker | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/bounty_hacker_writeup.pdf) | [TryHackMe](https://tryhackme.com/r/room/cowboyhacker) | 🟢 Easy | ⭐⭐⭐⭐ | `Nmap` `FTP` `hydra` `privilege escalation` |
| Blogger1 | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/blogger1_writeup.pdf) | [VulnHub](https://www.vulnhub.com/entry/blogger-1,675/#top) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `arp-scan` `Nmap` `GoBuster` `wpscan` `privilege escalation` |
| Basic Pentesting | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/basic_pentesting_writeup.pdf) | [TryHackMe](https://tryhackme.com/r/room/basicpentestingjt) | 🟢 Easy | ⭐⭐⭐⭐ | `Nmap` `GoBuster` `enum4linux` `SMB` `hydra` `john` `privilege escalation` |
| Anonymous | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/anonymous_writeup.pdf) | [TryHackMe](https://tryhackme.com/r/room/anonymous) | 🟡 Medium | ⭐⭐⭐⭐ | `Nmap` `enum4linux` `SMB` `FTP` `privilege escalation` |
| Agent Sudo       | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/agent_sudo_writeup.pdf)       | [TryHackMe](https://tryhackme.com/r/room/agentsudoctf)             | 🟢 Easy | ⭐⭐⭐⭐ | `Nmap` `curl` `hydra` `FTP` `binwalk` `steghide` `ssh` `privilege escalation` |


<br><br>

### **IDS/IPS**
Writeups here explore intrusion detection and prevention systems like Snort. These labs simulate network-based attacks and help develop skills in detecting and repsonding to suspicious traffic patterns and rule-based alerts. 
| Challenge        | Writeup                                                                                | Challenge Link                                                     | Difficulty | Rating | Tags | 
| ---------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |------------|----------|-----------------------------|
| Snort Challenge the Basics  | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/snort_challenge_the_basics.pdf) | [TryHackMe](https://tryhackme.com/r/room/snortchallenges2)       | 🟡 Medium | ⭐⭐ |  `Snort` |
| Snort Challenge live attacks | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/snort_challenge_live_attacks.pdf) | [TryHackMe](https://tryhackme.com/jr/snortchallenges2) | 🟡 Medium | ⭐⭐⭐ | `Snort` |

<br><br>

### **SIEM (ELK, Splunk, etc.)**
These challenges involve using SIEMs like Splunk, ELK, and Wazuh to identify threats. 
| Challenge                      | Writeup                                                                              | Challenge Link                                                                 | Difficulty | Rating | Tags | 
|-------------------------------|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|------------|----------|-----------------------------|
| Monday Monitor                | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/monday_monitor.pdf)        | [TryHackMe](https://tryhackme.com/r/room/mondaymonitor)                         | 🟢 Easy | ⭐⭐⭐ | `Wazuh` `CyberChef` |
| NerisBot Lab                  | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_nerisbot_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/nerisbot/) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Splunk` `Zeek` `Suricata` `VirusTotal` |
| Peak                          | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_peak.pdf)             | [BTLO](https://blueteamlabs.online/home/investigation/peak-98765b84cb)          | 🟡 Medium | ⭐⭐ | `Elastic` |
| Defaced                       | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_defaced.pdf)          | [BTLO](https://blueteamlabs.online/home/investigation/defaced-593f17897e)       | 🟢 Easy | ⭐⭐ | `Elastic` |
| SOC Alpha 3                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_soc_alpha_3.pdf)      | [BTLO](https://blueteamlabs.online/home/investigation/soc-alpha-3-cfb2546607)   | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Elastic` `VirusTotal` |
| SOC Alpha 2                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_soc_alpha_2.pdf)      | [BTLO](https://blueteamlabs.online/home/investigation/soc-alpha-2-f3825dedc4)   | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Elastic` |
| SOC Alpha 1                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_soc_alpha_1.pdf)      | [BTLO](https://blueteamlabs.online/home/investigation/soc-alpha-1-2ba4c4a550)   | 🟢 Easy | ⭐⭐⭐ | `Elastic` |
| Middle Mayhem                 | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_middle_mayhem.pdf)    | [BTLO](https://blueteamlabs.online/home/investigation/middlemayhem-aa3c27f5d1)  | 🟢 Easy | ⭐⭐⭐ | `Elastic` |
| Boogeyman 3                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/boogeyman3_writeup.pdf)    | [TryHackMe](https://tryhackme.com/r/room/boogeyman3)                             | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Elastic` |
| New Hire Old Artifacts        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/new_hire_old_artifacts.pdf)| [TryHackMe](https://tryhackme.com/r/room/newhireoldartifacts)                   | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Elastic` |
| PS Eclipse                    | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/pseclipse.pdf)             | [TryHackMe](https://tryhackme.com/r/room/posheclipse)                           | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Elastic` |
| Conti                         | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/conti.pdf)                 | [TryHackMe](https://tryhackme.com/r/room/contiransomwarehgh)                    | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Elastic` |
| SlingShot                     | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/slingshot.pdf)             | [TryHackMe](https://tryhackme.com/r/room/slingshot)                             | 🟢 Easy | ⭐⭐⭐⭐ | `Elastic` `CyberChef` |
| Benign                        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/benign.pdf)                | [TryHackMe](https://tryhackme.com/r/room/benign)                                | 🟡 Medium | ⭐⭐⭐ | `Elastic` |
| Investigating with Splunk     | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/investigating_with_splunk.pdf) | [TryHackMe](https://tryhackme.com/r/room/investigatingwithsplunk)          | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Splunk` |
| ItsyBitsy                     | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/itsybitsy.pdf)             | [TryHackMe](https://tryhackme.com/r/room/itsybitsy)                             | 🟡 Medium | ⭐⭐⭐ | `Elastic` |

<br><br>

### **Digital Forensics**
These writeups cover memory, disk, and host-based forensics. You will find challenges involving registry analysis, memory dumps, timeline reconstruction, and more. Most of these challenges involve analysing disk images, kape images, or memory dumps from compromised hosts, primarily Windows hosts. 

### **Endpoint Forensics**
| Challenge                      | Writeup                                                                              | Challenge Link                                                                 | Difficulty | Rating | Tags | 
|-------------------------------|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|------------|----------|-----------------------------|
| MinerHunt Lab | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_minerhunt_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/minerhunt/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `EvtxECmd` `Timeline Explorer` `VirusTotal` `Windows Forensics` `Microsoft SQL Server` `IFEO` `WMI` |
| LummaStealer Lab | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_lummastealer_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/lummastealer/)  | 🟡 Medium | ⭐⭐⭐⭐⭐ | `EvtxECmd` `Timeline Explorer` `DB Browser for SQLite` `Windows Forensics` |
| VaultBreak Lab | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_vaultbreak_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/vaultbreak/)  | 🟡 Medium | ⭐⭐⭐⭐⭐ | `DB Browser for SQLite` `EvtxECmd` `Timeline Explorer` `MFTECmd` `Windows Forensics` `WMI` `Scheduled Tasks` |
| IronShade | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/ironshade.pdf) | [TryHackMe](https://tryhackme.com/room/ironshade) | 🟡 Medium | ⭐⭐⭐⭐ | `Bash` `Linux Forensics` |
| Hunter Lab | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_hunter_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/hunter/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `FTK Imager` `Registry Explorer` `DCode` `EvtxECmd` `Timeline Explorer` `PECmd` `Sublime` `DB Browser for SQLite` `SysTools Outlook PST Viewer` `ShellBags Explorer` `JumpListExplorer` `Windows Forensics` |
| CrownJewel1 | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/crownjewel1.pdf) | [HackTheBox](https://app.hackthebox.com/sherlocks/CrownJewel-1) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Hayabusa` `Timeline Explorer` `EVTXCmd` `MFTECmd` `Event Viewer` `ntds.dit` `Volume Shadow Copies` |
| Lockbit Lab | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_lockbit_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/lockbit/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `EVTXCmd` `Timeline Explorer` `Notepad ++` `VirusTotal` |
| DarkCrystal Lab | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_darkcrystal_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/darkcrystal/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Volatility3` `Timeline Explorer` `EVTXCmd` |
| QBot Lab | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_qbot_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/qbot/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Volatility3` `VirusTotal` `Malicious Excel Document` |
| ELPACO-team Lab | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_elpaco_team_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/elpaco-team/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `EVTXCmd` `Timeline Explorer` `MFTECmd` `VirusTotal` |
| Retracted                     | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/retracted.pdf)             | [TryHackMe](https://tryhackme.com/r/room/retracted)                             | 🟢 Easy | ⭐⭐ | `Event Viewer` |
| Unattended                    | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/unattended.pdf)            | [TryHackMe](https://tryhackme.com/r/room/unattended)                            | 🟡 Medium | ⭐⭐⭐ | `Registry Explorer` `Autopsy` |
| Disgruntled                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/disgruntled.pdf)           | [TryHackMe](https://tryhackme.com/r/room/disgruntled)                           | 🟢 Easy | ⭐ | `cat` |
| Secret Recipe                 | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/secret_recipe.pdf)         | [TryHackMe](https://tryhackme.com/r/room/registry4n6)                           | 🟡 Medium | ⭐⭐⭐⭐ | `Registry Explorer` |
| Critical                      | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/critical.pdf)              | [TryHackMe](https://tryhackme.com/r/room/critical)                              | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Volatility3` `strings` |
| Tempest                       | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/temptest_writeup.pdf)      | [TryHackMe](https://tryhackme.com/r/room/tempestincident)                       | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Timeline Explorer` `WireShark` `Brim` `CyberChef` `VirusTotal` |
| Boogeyman 2                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/boogeyman2_writeup.pdf)    | [TryHackMe](https://tryhackme.com/r/room/boogeyman2)                            | 🟡 Medium | ⭐⭐⭐⭐⭐ | `text editor` `Olevba` `Volatility2` |
| Ramnit                        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_ramnit_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/ramnit/) | 🟢 Easy | ⭐⭐⭐⭐ | `Volatility3` `VirusTotal` |
| Reveal                        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_reveal_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/reveal/) | 🟢 Easy | ⭐⭐⭐⭐ | `Volatility3` `Timeline Explorer` `VirusTotal` |
| FakeGPT                       | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_fakegpt_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/fakegpt/) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `ExtAnalysis` `CyberChef` |
| Brave                         | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_brave_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/brave/) | 🟡 Medium | ⭐⭐⭐⭐ | `Volatility3` `HxD` |
| Redline                       | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_redline_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/redline/) | 🟢 Easy | ⭐⭐⭐⭐ | `Volatility3` `Timeline Explorer` `VirusTotal` |
| Memory Analysis               | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/lets_defend_memory_analysis.pdf) | [LetsDefend](https://app.letsdefend.io/challenge/memory-analysis)             | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Volatility3` `VirusTotal` `Crackstation` |
| Lockbit                       | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/lockbit.pdf)               | [LetsDefend](https://app.letsdefend.io/challenge/lockbit)                      | 🟢 Easy | ⭐⭐⭐⭐ | `Volatility3` `VirusTotal` |
| WinRar 0-Day                  | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/win_rar_0_day.pdf)         | [LetsDefend](https://app.letsdefend.io/challenge/winrar-0-day)                 | 🟡 Medium | ⭐⭐⭐ | `Volatility3` `CyberChef` |
| BlackEnergy Lab               | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_black_energy_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/blackenergy/) | 🟡 Medium | ⭐⭐⭐ | `Volatility3` `Timeline Explorer` `VirusTotal` |
| Memory Analysis - Ransomware | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_memory_analysis_ransomware.pdf) | [BTLO](https://blueteamlabs.online/home/challenge/memory-analysis-ransomware-7da6c9244d) | 🟡 Medium | ⭐⭐⭐⭐ | `Volatility3` |
| Tardigrade                    | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/tardigrade.pdf)            | [TryHackMe](https://tryhackme.com/room/tardigrade)                             | 🟡 Medium | ⭐ | `Linux command-line` |
| Sysinternals                  | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_sysinternals_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/sysinternals/) | 🟡 Medium | ⭐⭐ | `Autopsy` `AppCompatParser` `AmCacheParser` `VirusTotal` |
| REvil Corp                    | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/revil_corp.pdf)            | [TryHackMe](https://tryhackme.com/room/revilcorp)                              | 🟡 Medium | ⭐⭐⭐ | `Redline` `VirusTotal` | 
| Forensics                     | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/forensics.pdf)             | [TryHackMe](https://tryhackme.com/room/forensics)                              | 🔴 Hard | ⭐⭐⭐⭐⭐ | `Volatility3` `strings` | 
| Dead End?                     | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/dead_end.pdf)              | [TryHackMe](https://tryhackme.com/room/deadend)                                | 🔴 Hard | ⭐⭐⭐ | `Volatility3` `FTK Imager` `VirusTotal` |  
| Insider Lab                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_insider_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/insider/) | 🟢 Easy | ⭐⭐⭐ | `FTK Imager` |
| Seized Lab                    | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_seized_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/seized/)  | 🟡 Medium | ⭐⭐⭐ | `Volatility3` `strings` |
| Browser Forensics - Cryptominer | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_browser_forensics_cryptominer.pdf) | [BTLO](https://blueteamlabs.online/home/challenge/browser-forensics-cryptominer-aa00f593cb) | 🟢 Easy | ⭐⭐⭐ | `FTK Imager` | 
| Kraken Keylogger Lab         | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_krakenkeylogger_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/krakenkeylogger/) | 🟡 Medium | ⭐⭐ | `DB Browser for SQLite` `LECmd` `text editor` |   
| HireMe Lab                    | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_hireme_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/hireme/)  | 🟡 Medium | ⭐⭐⭐⭐ | `FTK Imager` `Registry Explorer` `LECmd` `RegRipper` `OST Viewer` |
| DumpMe Lab                    | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_dumpme_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/dumpme/)  | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Voltiliaty2` `VirusTotal` | 
| AfricanFalls Lab             | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_africanfalls_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/africanfalls/) | 🟡 Medium | ⭐⭐⭐ | `FTK Imager` `rifiuti2` `Browsing History View` `PECmd` `ShellBags Explorer` |
| Injector Lab                 | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_injector_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/injector/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `FTK Imager` `Volatility3` `Registry Explorer` `cut` | 
| NintendoHunt Lab             | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_nintendohunt_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/nintendohunt/) | 🔴 Hard | ⭐⭐ | `Volatility2` `Strings` |
| DeepDive Lab                 | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_deepdive_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/deepdive/) | 🔴 Hard | ⭐⭐ | `Volatility2` `VirusTotal` |
| CorporateSecrets Lab         | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_corporatesecrets_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/corporatesecrets/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `FTK Imager` `MFTECmd` `Timeline Explorer` `RegRipper` `PECmd` |
| Bruteforce                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_bruteforce.pdf)        | [BTLO](https://blueteamlabs.online/home/challenge/bruteforce-16629bf9a2)       | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Timeline Explorer` `cat` |
| Silent Breach                | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_silent_breach_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/silent-breach/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `FTK Imager` `Browsing History View` `DB Browser for SQLite` `Strings` `Grep` |
| Amadey Lab                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_amadey_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/amadey/)   | 🟢 Easy | ⭐⭐⭐ | `Volatility3` |
| The Crime lab                | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_the_crime_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/the-crime/) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `ALEAPP` |
| Eli Lab                      | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_denfenders_eli_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/eli/)      | 🟡 Medium | ⭐⭐ | `CLEAPP` |
| DiskFiltration               | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/diskfiltration.pdf) | [TryHackMe](https://tryhackme.com/room/diskfiltration) | 🔴 Hard | ⭐⭐⭐⭐ | `Autopsy` `Timeline Explorer` `MFTECmd` `Exiftool` `HxD` |
| Volatility Traces Lab        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_volatility_traces_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/volatility-traces/) | 🟢 Easy | ⭐⭐⭐⭐⭐ |  `Volatility 3`  `Defense Evasion` |
| MeteorHit Lab                | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_meteorhit_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/meteorhit/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Registry Explorer` `Timeline Explorer` `EVTXCmd` `MFTECmd` `VirusTotal` `NTFS Forensics` `Sysmon` `Defense Evasion` |  
| Fog Ransomware Lab          | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_fog_ransomware_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/fog-ransomware/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `DB Browser for SQLite` `MFTECmd` `Timeline Explorer` `EvtxECmd` `VirusTotal`   
| NetX-Support Lab            | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_netx_support_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/netx-support/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `DB Browser for SQLite` `FTK Imager` `MFTECmd` `EVTXCmd` `PECmd` `CyberChef` `Registry Explorer` `LECmd` |  
| Beta Gamer Lab              | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_beta_gamer_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/beta-gamer/) | 🟡 Medium | ⭐⭐⭐⭐⭐ |  `DB Browser for SQLite` `FTK Imager` `MFTECmd` `EVTXCmd` |
| Trigona Ransomware Lab | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_trigona_ransomware_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/trigona-ransomware/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `EVTXCmd` `Timeline Explorer` `Registry Explorer` `MFTECmd` `PECmd` `AmcacheParser` |
| Deep Blue                     | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_deep_blue.pdf)        | [BTLO](https://blueteamlabs.online/home/investigation/deep-blue-a4c18ce507)     | 🟢 Easy | ⭐⭐⭐ | `deepbluecli` `Event Viewer` |
| Brutus                        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/brutus.pdf) | [HackTheBox](https://app.hackthebox.com/sherlocks/Brutus) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `grep` `awk` `sed` `sort` `uniq` `last` `grep` `auth.log` `wtmp` |
| Crownjewel-2                  | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/crownjewewl2.pdf) | [HackTheBox](https://app.hackthebox.com/sherlocks/CrownJewel-2) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `EvtxECmd` `Timeline Explorer` |
 
<br><br>

### **Email Analysis**
This section dives into investigating emails, primarily phishing emails. You will learn how to extract headers, decode payloads, verify SPF/DKIM records, and asess malicious indicators in emails. 
| Challenge                      | Writeup                                                                              | Challenge Link                                                                 | Difficulty | Rating | Tags | 
|-------------------------------|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|------------|----------|-----------------------------|
| Greenholt Phish               | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/the_greenholt_phish_writeup.pdf) | [TryHackMe](https://tryhackme.com/r/room/phishingemails5fgjlzxc)            | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Thunderbird` `mxtoolbox` `VirusTotal` |
| Snapped Phish-ing Line        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/snapped_phishing_line_writeup.pdf) | [TryHackMe](https://tryhackme.com/r/room/snappedphishingline)             | 🟢 Easy | ⭐⭐⭐⭐ | `VirusTotal` `text editor` |
| Phishing Analysis             | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_phishing_analysis.pdf) | [BTLO](https://blueteamlabs.online/home/challenge/phishing-analysis-f92ef500ce) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Sublime` `URL2PNG` |
| Phishing Analysis 2           | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_phishing_analysis_2.pdf) | [BTLO](https://blueteamlabs.online/home/challenge/phishing-analysis-2-a1091574b8) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Sublime` `CyberChef` |
| Phishy v1                     | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_phishyv1.pdf)         | [BTLO](https://blueteamlabs.online/home/investigation/phishy-v1-e3b5be4fe8)     | 🟡 Medium | ⭐⭐⭐ |

<br><br>

### **Cyber Threat Intelligence (CTI)**
These labs focus on cyber threat intelligence, you will learn how to use threat intelligence platforms like VirusTotal, Malpedia, MITRE ATT&CK, and much more. Most of these challenges involve tracking malware campaigns, attributing malware to threat actors, etc. 
| Challenge                      | Writeup                                                                              | Challenge Link                                                                 | Difficulty | Rating | Tags | 
|-------------------------------|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|------------|----------|-----------------------------|
| Trooper                       | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/trooper_writuep.pdf)       | [TryHackMe](https://tryhackme.com/r/room/trooper)                               | 🟢 Easy | ⭐⭐⭐⭐ | `Open CTI` |
| Yellow RAT                    | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_yellow_rat_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/yellow-rat/) | 🟢 Easy | ⭐⭐ | `VirusTotal` |
| GrabThePhiser                 | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_grab_the_phisher_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/grabthephisher/) | 🟢 Easy | ⭐⭐⭐ | `Sublime` |
| Red Stealer                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_red_stealer_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/red-stealer/) | 🟢 Easy | ⭐⭐ | `VirusTotal` `MalwareBazaar` |
| PhishStrike Lab               | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_phishstrike.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/phishstrike/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Sublime` `URLhaus` `VirusTotal` |
| Tusk Infostealer Lab          | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_tusk_infostealer_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/tusk-infostealer/) | 🟢 Easy | ⭐ | `Kaspersky Threat Intelligence Portal` `VirusTotal` |
| Oski Lab                      | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_oski_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/oski/)     | 🟢 Easy | ⭐⭐ | `VirusTotal` `any.run` |
| IcedID                        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_icedid_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/icedid/)   | 🟢 Easy | ⭐ | `VirusTotal` `Tria.ge` `Malpedia` |

<br><br>

### **Network Forensics**
This category focuses on packet analysis through PCAP files and zeek logs. Tools like Wireshark, Zeek, and Brim are frequently used. 
| Challenge                      | Writeup                                                                              | Challenge Link                                                                 | Difficulty | Rating | Tags | 
|-------------------------------|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|------------|----------|-----------------------------|
| Boogeyman 1                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/boogeyman1_writeup.pdf)    | [TryHackMe](https://tryhackme.com/r/room/boogeyman1)                            | 🟡 Medium | ⭐⭐⭐ | `Thunderbird` `lnkparse` `cat` `Wireshark` |
| PacketDetective               | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_pakcet_defective_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/packetdetective/) | 🟢 Easy | ⭐⭐⭐⭐ | `Wireshark` |
| DanaBot                       | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_dana_bot.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/danabot/)  | 🟢 Easy | ⭐⭐⭐⭐ | `Wireshark` `VirusTotal` `Network Miner` |
| Web Investigation             | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_web_investigation_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/web-investigation/) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Wireshark` `MaxMind GeoIP database` |
| WebStrike                     | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_webstrike_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/webstrike/) | 🟢 Easy | ⭐⭐⭐⭐ | `Wireshark` |
| PoisonedCredentials           | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_poisoned_credentials_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/poisonedcredentials/) | 🟢 Easy | ⭐⭐ | `Wireshark` |
| TomCat Takeover               | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_tomcat_takeover_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/tomcat-takeover/) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Wireshark` |
| PsExec Hunt                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_psexec_hunt_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/psexec-hunt/) | 🟢 Easy | ⭐⭐⭐ | `Wireshark` |
| Shellshock Attack             | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/lets_defend_shellshock.pdf) | [LetsDefend](https://app.letsdefend.io/challenge/shellshock-attack)             | 🟢 Easy | ⭐ | `Wireshark` |
| HTTP Basic Auth               | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/lets_defend_http_basic_auth.pdf) | [LetsDefend](https://app.letsdefend.io/challenge/http-basic-auth)               | 🟢 Easy | ⭐⭐ | `Wireshark` |
| Brute Force Attack            | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/lets_defend_brute_force_attack.pdf) | [LetsDefend](https://app.letsdefend.io/challenge/brute-force-attacks)           | 🟡 Medium | ⭐⭐⭐⭐ | `Wireshark` `cat` `grep` |
| OpenWire Lab                  | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_openwire_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/openwire/) | 🟡 Medium | ⭐⭐⭐⭐ | `Wireshark` |
| Network Analysis - Web Shell  | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_network_analysis_web_shell.pdf) | [BTLO](https://blueteamlabs.online/home/challenge/network-analysis-web-shell-d4d3a2821b) | 🟢 Easy | ⭐⭐⭐⭐ | `Wireshark` |
| XMLRat Lab                            | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_xlmrat_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/xlmrat/)    | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Wireshark` `VirusTotal` `CyberChef` |
| Network Analysis - Ransomware        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_network_analysis_ransomware.pdf)| [BTLO](https://blueteamlabs.online/home/challenge/network-analysis-ransomware-3dd520c7ec) | 🟡 Medium | ⭐⭐ | `Wireshark` |
| l337 S4uc3 Lab                        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_l337_S4uc3_Lab.pdf)| [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/l337-s4uc3/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Wireshark` `Network Miner` `Brim` `volatility 2` |
| Piggy                                 | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_piggy.pdf)                 | [BTLO](https://blueteamlabs.online/home/investigation/piggy-aij2bd8h2)          | 🟢 Easy | ⭐⭐⭐ | `Wireshark` `VirusTotal` | 
| Shiba Insider                         | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_shiba_insider.pdf)         | [BTLO](https://blueteamlabs.online/home/challenge/shiba-insider-5b48123711)     | 🟢 Easy | ⭐⭐ | `Wireshark` `exiftool` | 
| Tshark Challenge II: Directory        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/tshark_challenge_2_directory.pdf)| [TryHackMe](https://tryhackme.com/r/room/tsharkchallengestwo)                  | 🟢 Easy | ⭐⭐⭐⭐⭐ | `Tshark` `VirusTotal` |
| TShark Challenge 1: Teamwork          | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/tshark_challenge_1_teamwork.pdf)| [TryHackMe](https://tryhackme.com/r/room/tsharkchallengesone)                   | 🟢 Easy | ⭐⭐ | `Tshark` `VirusTotal` |
| TShark                                | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/tshark.pdf)                     | [TryHackMe](https://tryhackme.com/r/room/tshark)                                | 🟡 Medium | ⭐⭐⭐ | `Tshark` | 
| Carnage                               | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/carnage_writeup.pdf)            | [TryHackMe](https://tryhackme.com/r/room/c2carnage)                             | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Wireshark` `VirusTotal` | 
| Warzone 2                             | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/warzone_2_challenge.pdf)        | [TryHackMe](https://tryhackme.com/r/room/warzonetwo)                            | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Brim` `Network Miner` `Wireshark` `VirusTotal` `CyberChef` |
| Warzone 1                             | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/warzone1.pdf)                   | [TryHackMe](https://tryhackme.com/r/room/warzoneone)                            | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Brim` `Network Miner` `Wireshark` `VirusTotal` | 
| Masterminds                           | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/masterminds.pdf)                | [TryHackMe](https://tryhackme.com/r/room/mastermindsxlq)                        | 🟡 Medium | ⭐⭐⭐⭐⭐ | `Brim` `VirusTotal` |
| Zeek Exercises                        | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/zeek_exercises.pdf)             | [TryHackMe](https://tryhackme.com/r/room/zeekbroexercises)                      | 🟡 Medium | ⭐⭐⭐⭐⭐ | `zeek` `CyberChef` `VirusTotal` |

<br><br>

### **Malware Analysis**
This section focuses on static and dynamic malware analysis. These writeups document the analysis of malicious PE files, scripts, macros, and more. 
| Challenge                                 | Writeup                                                                                   | Challenge Link                                                                 | Difficulty | Rating | Tags | 
|-------------------------------------------|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|------------|----------|-----------------------------|
| MalBuster                                 | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/malbuster_writeup.pdf)           | [TryHackMe](https://tryhackme.com/r/room/malbuster)                            | 🟡 Medium | ⭐⭐⭐⭐ | `pestudio` `detect it easy` `VirusTotal` `CTF Explorer` `capa` `floss` |
| Mr. Phisher                               | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/mrphisher_writeup.pdf)           | [TryHackMe](https://tryhackme.com/r/room/mrphisher)                            | 🟢 Easy | ⭐ | `LibreOffice Writer` |
| Dunkle Materie                            | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/dunkle_materie_writeup.pdf)      | [TryHackMe](https://tryhackme.com/r/room/dunklematerieptxc9)                  | 🟡 Medium | ⭐⭐⭐⭐ | `ProcDOT` `VirusTotal` |
| Maldoc101                                 | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/cyber_defenders_maldoc_101_lab.pdf) | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/maldoc101/) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `oledump` `VirusTotal` `olevba` `CyberChef` |
| Downloader                                | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/lets_defend_downloader.pdf)      | [LetsDefend](https://app.letsdefend.io/challenge/downloader)                  | 🔴 Hard | ⭐⭐⭐⭐⭐| `IDA Pro` |
| Malicious Doc                             | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/lets_defend_malicious_doc.pdf)   | [LetsDefend](https://app.letsdefend.io/challenge/malicious-doic)              | 🟢 Easy | ⭐ | `VirusTotal` | 
| PowerShell Script                         | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/lets_defend_powershell_script.pdf) | [LetsDefend](https://app.letsdefend.io/challenge/powershell-script)         | 🟢 Easy | ⭐⭐| `text editor` `VirusTotal` |
| Suspicious USB Stick                      | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_suspicious_usb_stick.pdf)   | [BTLO](https://blueteamlabs.online/home/challenge/suspicious-usb-stick-2f18a6b124) | 🟡 Medium | ⭐ | `text editor` `VirusTotal` `peepdf` |
| Reverse Engineering - A Classic Injection | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_reverse_engineering_a_classic_injection.pdf) | [BTLO](https://blueteamlabs.online/home/challenge/reverse-engineering-a-classic-injection-9791a9b784) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `pestudio` `detect it easy` `IDA Pro` `Procmon` `CyberChef` |
| PowerShell Analysis - Keylogger           | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_powershell_analysis_keylogger.pdf) | [BTLO](https://blueteamlabs.online/home/challenge/powershell-analysis-keylogger-9f4ab9a11c) | 🟢 Easy | ⭐⭐| `text editor` |
| Injection Series Part 3                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_injection_series_part_3.pdf) | [BTLO](https://blueteamlabs.online/home/challenge/injection-series-part-3-3f316e3782) | 🟡 Medium | ⭐⭐⭐⭐⭐ | `cutter` `IDA Pro` `CyberChef` |
| Injection Series Part 4                   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_ijection_series_part_4.pdf) | [BTLO](https://blueteamlabs.online/home/challenge/injection-series-part-4-8b3aaae8ca) | 🟢 Easy | ⭐⭐⭐⭐⭐ | `IDA Pro` `CyberChef` |
| Reverse Engineering - Another Injection   | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_reverse_engineering_another_injection.pdf) | [BTLO](https://blueteamlabs.online/home/challenge/reverse-engineering-another-injection-72001745c9) | 🟢 Easy | ⭐⭐⭐⭐ | `detect it easy` `strings` `IDA Pro` `CyberChef` |
| Malware Analysis - Ransomware Script      | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_malware_analysis_ransomware_script.pdf) | [BTLO](https://blueteamlabs.online/home/challenge/malware-analysis-ransomware-script-4263fe6ecf) | 🟢 Easy | ⭐⭐⭐ | `text editor`
| Nonyx                                     | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_nonyx.pdf)                  | [BTLO](https://blueteamlabs.online/home/investigation/nonyx-63b4769449)       | 🟢 Easy | ⭐⭐⭐⭐ | `volatility 2` |
| Anakus                                    | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/btlo_anakus.pdf)                 | [BTLO](https://blueteamlabs.online/home/investigation/anakus-dfea6f86e0)      | 🟢 Easy | ⭐⭐⭐ | `detect it easy` `VirusTotal` `sigcheck` `timeline explorer` |

<br><br>

### **Reverse Engineering**
Challenges in this section involve understanding program logic and uncovering hidden functionality from binaries. They often require IDA Pro, Ghidra, or Radare2.
| Challenge            | Writeup                                                                              | Challenge Link                                                                 | Difficulty | Rating | Tags | 
|---------------------|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|------------|----------|-----------------------------|
| Reversing ELF       | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/reversing_elf.pdf)         | [TryHackMe](https://tryhackme.com/r/room/reverselfiles)                         | 🟢 Easy  | ⭐⭐⭐⭐ | `radare2` `strings` |
| DLL Stealer         | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/lets_defend_dll_stealer.pdf) | [LetsDefend](https://app.letsdefend.io/challenge/dll-stealer)                  | 🟡 Medium  | ⭐⭐⭐⭐⭐ | `dotPeek` |
| Beginner Crackme    | [PDF](https://github.com/tim-barc/ctf_writeups/blob/main/writeups/beginner_crackme.pdf)      | [Crackmes.one](https://crackmes.one/crackme/5f907efe33c5d424269a15d1)          | 🟢 Easy  | ⭐ | `IDA Pro`

<br><br>

## Tools Used
Some of the tools used in these writeups include (not limited to):

| Category                                  | Tool Name           | Link                                                                                        |
| ----------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------- |
| **Network Scanning & Enumeration**        | Nmap                | https://Nmap.org/                                                              |
|                                           | GoBuster            | https://www.kali.org/tools/gobuster/                            |
|                                           | WPScan              | https://wpscan.com/                                                         |
|                                           | enum4linux          | https://www.kali.org/tools/enum4linux/                         |
| **Vulnerability Scanning and Exploitation** | Burp Suite | https://portswigger.net/burp |
|                                              | Metasploit | https://www.metasploit.com/ |
|                                              | Nikto | https://www.cisa.gov/resources-tools/services/nikto |
|                                              | Hydra | https://www.kali.org/tools/hydra/ |
|                                               | John the Ripper | https://www.openwall.com/john/ |                                          
| **Packet Analysis and Network Monitoring** | Wireshark | https://www.Wireshark.org/ |
|                                            | TShark | https://www.Wireshark.org/docs/man-pages/tshark.html |
|                                            | Snort | https://www.snort.org/ |
|                                            | Zeek | https://zeek.org/ |
|                                            | Brim | https://www.brimdata.io/download/ |
|                                            | NetworkMiner | https://www.netresec.com/?page=NetworkMiner |
| **Binary Analysis**                        | Binwalk | https://github.com/ReFirmLabs/binwalk |
| **Log Analysis and SIEM**                  | ELK | https://www.elastic.co/elastic-stack |
|                                            | Splunk | https://www.splunk.com/ |
|                                            | Wazuh | https://wazuh.com/ |
|                                            | Event Viewer | https://learn.microsoft.com/en-us/shows/inside/event-viewer |
|                                            | Sysmon-View | https://github.com/nshalabi/SysmonTools |
| **Cyber Threat Intelligence (CTI)**        | OpenCTI | https://github.com/OpenCTI-Platform/opencti |
|                                            | Mitre ATT&CK Matrix | https://attack.mitre.org/ |
|                                            | VirusTotal | https://www.VirusTotal.com/gui/home/upload |
|                                            | URLHaus | https://urlhaus.abuse.ch/browse/ |
|                                            | IPInfo | https://ipinfo.io/ |
|                                            | Cisco Talos | https://talosintelligence.com/ |
|                                            | Shodan | https://www.shodan.io/ |
|                                            | Kasperky Threat Intelligence Portal | https://opentip.kaspersky.com/ |
|                                            | Tria.ge | https://tria.ge/ |
|                                             | Malpedia | https://malpedia.caad.fkie.fraunhofer.de/ |
|                                            | Malware Bazaar | https://bazaar.abuse.ch/browse/ |
| **Malware Analysis**                       | pestudio | https://www.winitor.com/download |
|                                            | Detect It Easy | https://github.com/horsicq/Detect-It-Easy |
|                                            | capa | https://github.com/mandiant/capa |
|                                            | Floss | https://github.com/mandiant/flare-floss |
|                                            | ProcDOT | https://www.procdot.com/downloadprocdotbinaries.htm |
|                                            | Olevba | https://github.com/decalage2/oletools/blob/master/oletools/olevba.py |
|                                             | Oledump | https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py |
|                                            | IDA Free | https://hex-rays.com/ida-free |
|                                            | Radare2 | https://rada.re/n/ |
|                                            | Cutter | https://cutter.re/ |
|                                            | Ghidra | https://ghidra-sre.org/ |
|                                            | AnyRun | https://any.run/ |
|                                            | Hybrid Analysis | https://hybrid-analysis.com/ |
|                                            | Joes Sandbox | https://www.joesandbox.com/#windows |
| **Forensics and Incident Response**        | Autopsy | https://www.autopsy.com/ |
|                                            | EZ Tools | https://www.sans.org/tools/ez-tools/ |
|                                            | Volatility3 | https://github.com/volatilityfoundation/volatility3 |
|                                            | FTK Imager |  https://www.exterro.com/ftk-product-downloads/ftk-imager-4-7-3-81 |                        
|                                            | Browsing History View | https://www.nirsoft.net/utils/browsing_history_view.html |
|                                            | CLEAPP | https://github.com/markmckinnon/cLeapp |
| **Mobile Forensics**                       | ALEAPP | https://github.com/abrignoni/ALEAPP |

## **Acknowledgments**
A special thanks to all the CTF platforms and contributors who make learning cybersecurity engaging and accessible.

## Personal Platform Profiles
- [TryHackMe | Top 1%](https://tryhackme.com/p/Timzoes)
- [BlueTeamLabs | Top 10%](https://blueteamlabs.online/home/user/239fed38c2bc3b10c6499d)
- [CyberDefenders | Top 10 Aus](https://cyberdefenders.org/p/timbarclay#/overview)
