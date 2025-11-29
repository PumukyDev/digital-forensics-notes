# PRACTICE 2 — NTFS ANALYSIS

The file system on any storage device is essential for the overall organization, storage mechanisms, and data control of the device. Understanding how these file systems work, as well as the design of key structures, storage mechanisms, associated metadata, and file system features, is crucial for conducting forensic investigations on a computer or other device.

NTFS and FAT file systems are two widely used and commonly encountered systems. Both offer significant and mandatory forensic evidence in any investigation.

## Main Objective of the Practice
- Study the metadata provided by the NTFS file system for forensic analysis.

## Software to Use
- FTK Imager 4.3 or higher  
- Active Disk Editor v7.0  
- MFT2Csv  
- NTFSLogFile  
- UsnJrl2Csv  
- ANJP  
- AlternateStreamViewer  
- Indx2Csv  

**Disk image to use:** Download it from the provided link.

## Tasks

1. Download the disk image and open it with Active Disk Editor (ADE). Try to identify, using ADE and by inspecting the 1 KB MFT records, which of them have been deleted based on the **FLAGS** property (`in use = 0`).
   a. Locate any entry corresponding to a deleted file (for example, “texto - copia.txt”), and take a screenshot. Memory position hint: go to position `03397XXXX`.  
   b. Recover the file using FTK Imager (found in the Recycle Bin folder).

2. Identify low-level attributes of one of the files (MFT records) using Active Disk Editor 7. The attributes of interest are **$10**, **$30**, and **$80**.  
   a. Where can you find the creation, modification, and access dates?  
   b. What does the **non-resident** property mean, and what are the values 0/1 associated with it?

3. Export the **$MFT** metadata file using FTK, process it with MFT2CSV, and import it into a spreadsheet editor to analyze the attributes. The goal is to study which files were deleted and when. Filter by the field **“in use = 0”** (deleted) and/or by **RecordActive = DELETED/ALLOCATED** to obtain the deletion date/time.

4. Export the **$LogFILE** metadata file. Together with the $MFT from the previous step, it provides information about file system transactions. Process the files using **NTFSLogFile Parse** to decode the information and obtain a CSV.  
   - Search for transactions where **lf_RedoOperation = DeallocateFileRecordSegment** to locate files that were permanently deleted, since this operation deallocates the file record segment.

5. Export the metadata file corresponding to **$USNJournal**  
   (`$Extend -> $USNjrl -> $J`).  
   Process it using **UsnJrl2Csv** to decode its stored information.  
   - Filter the resulting data by **Reason = CLOSE+DELETE** to obtain the timestamps of permanent file deletions.

6. Use the **ANJP** tool to perform a combined analysis of **$MFT**, **$LogFile**, and **$USNJournal**.  
   You will see that it processes the same information as the previous sections but in an integrated way. It includes a **Parse** tab and a **Report** tab.  
   - Use the tool and take a couple of screenshots of the generated report.  
   *(Note: This is a paid tool.)*

7. Use **FTK Imager** and **AlternateDataViewer** to study the origin of the files found in the `datos.dd` image.  
   - Take a screenshot with each tool showing one example.

8. Export the directory index metadata files (**$I30**) for the three directories present in the `datos.dd` disk image:  
   - the root directory,  
   - the directory named “carpeta”,  
   - and the Recycle Bin directory.  
   Process these files with **Indx2Csv**.  
   - Analyze which files exist now and which existed in the past in each directory.

9. Install the automated file recovery tool **Recuva**.  
   Mount the `datos.dd` disk image with **FTK Imager** and use Recuva to recover as many files as possible.  
   - Compare the recovered files with those that FTK Imager is able to recover (marked with the deletion cross icon).
