# Practical Assignment 1: Linux System Forensic Analysis

---

## Part A: The File System

The file system constitutes the backbone of any storage device, as it determines how data is organized, stored, and managed.

Among the most widely used file systems today, EXT4 (Fourth Extended File System) stands out as the default file system in most Linux distributions. This makes it a common target in forensic investigations involving servers, workstations, or embedded devices running this operating system.

EXT4 inherits and improves upon the features of its predecessors (EXT2 and EXT3), introducing advanced mechanisms such as journaling, extents (for efficient space management), delayed block allocation, and increased storage capacity. These elements not only optimize performance but also generate a rich set of metadata that can be crucial in an investigation: from creation, modification, and access timestamps to journal transaction logs that allow reconstruction of past activities, including file deletions.

---

## Objectives

- Study the metadata structure of EXT4 (inodes, superblock, block groups) and its forensic relevance.
- Learn how to use specialized tools (The Sleuth Kit, debugfs, hex editors) to inspect and extract information from an EXT4 disk image.
- Identify deleted files and determine, where possible, deletion dates through journal and inode analysis.
- Explore file recovery techniques, including the use of carving tools such as Photorec.

---

## Materials

- Any Linux distribution available on your system.
- Sleuth Kit.
- EXT4 disk image.

---

## Theoretical Questions (Read Section 1 of Topic 6)

1. What is the superblock? What critical information does the superblock of an EXT4 file system store, and why is it important for mounting and system integrity? Mention at least three specific fields and their function.

2. What is an inode? If you run the `stat` command on a file in Linux, what metadata information can you obtain and what do the timestamps mean?

3. Explain the relationship between a directory, directory entries (dentries), and inodes. How does this structure allow the system to locate a file within the file system?

4. Describe the difference between direct and indirect block addressing (single, double, and triple indirect) in an inode table. Files in EXT4 can reach up to 16 TB in size — mathematically explain how this size is achieved.

5. What fundamental advantage does the use of “extent trees” in EXT4 provide for mapping large file data compared to the indirect pointer system of Ext2/Ext3?

---

## Practical Tasks (Disk Image Analysis)

Download the disk image from the provided link and complete the following tasks:

1. Using appropriate Linux commands (fdisk, mmls), determine how many disk partitions appear in the image.

2. Open the same image with Active Disk Editor and verify that the same partitions appear as in the previous step.

3. Using Active Disk Editor, display the superblock information of partitions 1 and 3. Focus on explaining the fields that are most relevant from a forensic perspective.

4. Use the command `losetup -f -P` to mount the image file in Linux as if it were a device. Attempt to mount partitions 1 and 3 and examine their contents.

5. Use the `fls` command (from The Sleuth Kit) to list files and directories in partition 1 of the image. Investigate the meaning of the columns shown in the command output.

6. Explain why the command `icat /dev/loop0p1 690` does not produce output, while `icat /dev/loop0p1 12` does.

7. What information does the command `istat /dev/loop0p1 20` provide? Determine the name of the file referenced by inode 20 in partition 1.

8. Using Active Disk Editor, locate the inode 20 information of the previous file. Why do the direct block pointers not match?

9. Use the `tsk_recover` command to recover as many files as possible from partitions 1 and 3.

10. Use the `photorec` command to recover as many files as possible from partitions 1 and 3. Explain why the recovered files do not match those obtained in the previous step.

---

# Part B: Live Evidence Acquisition

As we know, there are two types of forensic analysis: live analysis and post-mortem analysis.

Live analysis occurs while the system is still active during the investigation. In this scenario, volatile data can be acquired, such as RAM contents, running processes, Internet connections, and temporary files. If disk encryption is used, this type of analysis may allow access to the decrypted file system using cached keys.

However, this type of analysis requires more expertise, and the system continuously modifies its data, which may affect legal admissibility.

The analyst must also avoid trusting any tools provided by the system itself, as they may have been deliberately manipulated.

---

## Objective

- Develop a script capable of collecting the evidence listed below.

---

## Materials

- Any Linux distribution available on your system.

---

## Script Requirements

The goal is to create a custom SCRIPT that can be executed from an external USB drive connected to the computer. This script will perform tasks such as copying logs to the external USB drive and collecting system information including date, time, logged-in users, process tree, system uptime, and more.

The script must perform at least the following tasks:

- Copy the contents of log directories.
- Determine the system date.
- Determine the system hostname.
- Gather CPU information.
- Identify registered system users.
- Identify running processes.
- Determine the process tree (including arguments).
- Identify mounted disks/devices.
- Review the output of disk partitioning utilities (partitions).
- Obtain disk usage statistics.
- Determine loaded kernel extensions.
- Obtain kernel boot parameters.
- Determine system uptime.
- Determine system environment (OS version, kernel version, 32 or 64 bits).
- Determine system environment variables.
- Determine memory usage of running processes.
- Determine running services.
- Determine all loaded modules.
- Determine last logins.
- Review the contents of `/etc/passwd`.
- Review the contents of `/etc/group`.
- Determine the last login per user.
- Determine who is currently logged in.
- Determine the login name used (logname).
- Determine the groups to which the current user belongs (id).
- Review `.bash_history` for each user.
- Determine current network connections.
- Check network adapters/interfaces.
- Determine socket statistics.
- Determine the list of open ports.
- Determine the routing table.
- Determine the ARP table.
- Determine network interface information.
- Review allowed hosts.
- Review denied hosts.
- Obtain static DNS resolution configuration.
- Obtain dynamic gateway and DNS information in use.
- Search for files with active SUID or GUID permissions (2000 and 4000).


APUNTES CLASE:

# Exercise 1

## Statement

12 bloques x 512 bytes + 128 direcciones a bloque x 512 bytes + 128² indirecto a bloque doble x 512 bytes + 128³ indirecto a bloque triple x 512 bytes


12 bloques x 4 kb + 1024 direcciones a bloque x 4 kb + 1024² indirecto a bloque doble x 4 kb + 1024³ indirecto a bloque triple x 4 kb



mount datos.dd /media -o loop,offset=1048576

o

losetup -f -t datos.dd
ls /dev/loop0

mount /dev/loop0p3 /media
umount /media






fls /loop0p1













icat 690 --> no sale nada porque sus bytes ya han sido pisados por otro archivo
icat 12 --> se ha borrado también pero no han sido pisados







tar
date
/etc/hostname
/proc/cpuinfo
/etc/passwd
ps -aux
pstree
lsblk
fdisk -l
df -h
lsmod
arranque mirar /boot
tiempo encendido -> top
lsrelease / uname -a
free
systemctl / status /systemcontrol
modúlos apache?
last
who para ver quién tiene la sesión iniciada
netstat -nputa
arp -a
ip a / ifconfig
hostalllow / denied
/etc/hosts
/etc/resolv.conf
find -perm 