# PRACTICE 1 — PARTITION TABLE ANALYSIS

The partition table is an essential component of a computer system. Depending on whether it uses **MBR** or **GPT**, it is physically located in different sectors of the disk and controls the boot process. In digital forensic analysis, it is necessary to study its structure to ensure that the system is not infected by malicious programs, such as malware capable of replacing the MBR and loading malicious software into memory during the boot process.

Additionally, analyzing partition tables helps forensic investigators extract details about the disk, identify the file system type used by each partition, and determine their size. These analyses may also serve as digital evidence or even assist in recovering lost data. In any case, understanding the structure of both logical and physical storage media used to store information on a computer is essential.

## Main Objectives of the Practice
- Study MBR and GPT partition tables.

## Software to Use
- Windows X  
- WinHex  
- Sleuth Kit  
- `dd`

## Tasks
- Create a Windows virtual machine.  
- Download two hard disk images from the provided source.  
- Practice sector extraction commands for the sectors where partition tables reside.  
  Remember that commands differ slightly depending on the operating system. Examples:

```bash
# Linux
dd if=disk3.dd bs=512 skip=0 count=1 | xxd
```

```cmd
:: Windows
dd count=1 bs=512 if=\\.\PHYSICALDRIVE2 of=d:\mbr.dd skip=0
```

- Extract as much information as possible from the disk images:

### 1. Determine whether the partition table is MBR or GPT.

### 2. If it is MBR, determine the following for each partition:
a. Partition number  
b. Boot indicator  
c. Cylinder, Head, Sector (CHS) of the first sector in the partition  
d. Partition type  
e. Cylinder, Head, Sector (CHS) of the last sector in the partition  
f. Logical Block Address (LBA) of the first sector  
g. Partition length in sectors  

### 3. If it is GPT, determine the following for each partition:
a. GPT header location (LBA)  
b. Header size  
c. First usable LBA  
d. Last usable LBA  
e. Disk GUID  
f. Sector containing the partition table  
g. For each partition:  
   1. Partition type  
   2. GUID  
   3. Starting LBA  
   4. Ending LBA  
   5. Name  

### 4. Compare the information obtained manually with the output of forensic tools such as Sleuth Kit. Example:

```bash
mmls -t gpt|dos <disk>
```

### 5. Comment on any peculiarities you find in the disks, such as:
- Hidden partitions  
- Blank or unallocated data areas  
- Any other noteworthy structures  
