# Exercise 3

File systems such as FAT, NTFS, ext2/ext3/ext4 store files in data blocks or clusters. The block or cluster size remains constant after being defined during the file system formatting process. In general, most operating systems attempt to store data contiguously to minimize fragmentation. When a file is deleted, its metadata (name, timestamp, size, first block or cluster location, etc.) is lost. This means that the data is still present, but only until it is partially or completely overwritten by new data.

**PhotoRec** is software designed to recover lost files including videos, documents, and files from hard drives and CDs, as well as lost images (hence the name *PhotoRecovery*) from camera memory cards, MP3 players, pen drives, and more. PhotoRec ignores the file system and performs a deep search for data, working even when the file system is severely damaged or has been reformatted.

**TestDisk** is free software designed to help recover lost partitions and/or make non-bootable disks bootable again when the cause is software failure, viruses, or human error (such as accidentally deleting a partition table).

**Autopsy** is a digital forensic analysis platform and the graphical interface for Sleuth Kit and other forensic tools. It is used by governments, public and private organizations, law enforcement, military units, and forensic professionals to investigate computer incidents. After an attack or system failure, it enables browsing through storage devices to recover files, identify system tampering, and recover photos, images, or videos.

## Main Objective of the Practice
- Practice recovering data using different forensic tools, starting from an NTFS file system.

## Software to Use
- FTK Imager 4.3 or higher  
- Active Disk Editor v7.0  
- PhotoRec  
- TestDisk  
- Bulk Extractor  
- Autopsy  

## Tasks

1. Download the disk image **“recuperacion.dd”**.

2. Analyze the disk and determine the following:
   a. Disk partitioning system (MBR/GPT)  
   b. Number of valid partitions and their sizes  
   c. Investigate whether a file system may exist

3. Use **PhotoRec** to recover as much information as possible from the disk image.  
   Do the same with **Bulk Extractor** and **Autopsy**.  
   Briefly document the process.

4. Import a multi-system virtual machine (XP–Ubuntu) from the provided OVA.  
   Corrupt the MBR on purpose and attempt to recover it using:  
   - the Windows XP installation disk  
   - the TestDisk tool

5. Import a multi-system virtual machine (Windows 7–Debian) from the provided OVA.  
   Corrupt the MBR on purpose and attempt to recover it using the Windows 7 installation disk.


UNDER DEVELOPMENT!!


Con active disk editor no podemos saber directamente de forma sencilla cuántas particiones hay, porque al estar estropeada la partición de arranque, no lo sabe.

![alt text](./images/image-73.png)

Al menos sabemos que es MBR

![alt text](./images/image-74.png)

PS C:\Users\usuario\Desktop\Práctica 3\photorec testdisk-7.2-WIP.win\testdisk-7.2-WIP> .\photorec_win.exe ..\..\recuperacion.dd                                                                     

![alt text](./images/image-75.png)

![alt text](./images/image-76.png)

![alt text](./images/image-77.png)

![alt text](./images/image-78.png)

![alt text](./images/image-79.png)

![alt text](./images/image-80.png)

![alt text](./images/image-81.png)


autopsy

![alt text](./images/image-82.png)

![alt text](./images/image-83.png)

it will create a database

![alt text](./images/image-84.png)

![alt text](./images/image-85.png)

![alt text](./images/image-86.png)

![alt text](./images/image-87.png)

Te muestra muchas más cosas, quizás un poco más lioso por la poca cantidad de archivos que tenemos, pero si el sistema fuese mucho más grnade, estaría bastante bien estructurado. Podemos ver más cosas que en photorec

![alt text](./images/image-88.png)