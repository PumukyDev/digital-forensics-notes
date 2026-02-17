# Volatility

As we know, there are two types of forensic analysis: live and post-mortem.

The first occurs when the system is still active during the analysis. In this scenario, it is possible to acquire volatile data such as RAM, running processes, Internet connections, and temporary files. If disk encryption is used, this type of analysis allows the file system to be decrypted using the cached key. On the other hand, this type of analysis requires greater expertise, and the system constantly modifies its data, which may affect judicial admissibility.

The analyst should also not trust any tools provided by the system itself, as they may have been deliberately manipulated.


We have been provided with a [RAM capture](ram.7z) that must be subjected to a complete forensic analysis.

### Main Objectives of the Practice

- Analyze RAM memory  
- Install and learn how to use the VOLATILITY tool  

Detail the process (command used and screenshot of the command output) to obtain this information.

We are required to obtain the following information:

git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 -m venv venv
source venv/bin/activate
pip install -e [dev]

- Operating system profile  

vol -f practica1.raw windows.info

![alt text](image.png)

- Process list  

vol -f practica1.raw windows.pslist

![alt text](image-1.png)

| TreeDepth | Variable                       | Value                                                                                                                   |
|-----------|--------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| 0         | Kernel Base                    | 0x8284f000                                                                                                              |
| 0         | DTB                            | 0x185000                                                                                                                |
| 0         | Symbols                        | file:///home/kali/tools/volatility3/volatility3/symbols/windows/ntkrpamp.pdb/5B308B4ED6464159B87117C711E7340C-2.json.xz |
| 0         | Is64Bit                        | False                                                                                                                   |
| 0         | IsPAE                          | True                                                                                                                    |
| 0         | layer_name                     | 0 WindowsIntelPAE                                                                                                       |
| 0         | memory_layer                   | 1 FileLayer                                                                                                             |
| 0         | KdDebuggerDataBlock            | 0x82977be8                                                                                                              |
| 0         | NTBuildLab                     | 7600.16385.x86fre.win7_rtm.09071                                                                                        |
| 0         | CSDVersion                     | 0                                                                                                                       |
| 0         | KdVersionBlock                 | 0x82977bc0                                                                                                              |
| 0         | Major/Minor                    | 15.7600                                                                                                                 |
| 0         | MachineType                    | 332                                                                                                                     |
| 0         | KeNumberProcessors             | 1                                                                                                                       |
| 0         | SystemTime                     | 2019-11-07 12:52:54+00:00                                                                                               |
| 0         | NtSystemRoot                   | C:\\Windows                                                                                                             |
| 0         | NtProductType                  | NtProductWinNt                                                                                                          |
| 0         | NtMajorVersion                 | 6                                                                                                                       |
| 0         | NtMinorVersion                 | 1                                                                                                                       |
| 0         | PE MajorOperatingSystemVersion | 6                                                                                                                       |
| 0         | PE MinorOperatingSystemVersion | 1                                                                                                                       |
| 0         | PE Machine                     | 332                                                                                                                     |
| 0         | PE TimeDateStamp               | Mon Jul 13 23:15:19 2009                                                                                                |


vol -f practica1.raw windows.pstree

![alt text](image-3.png)

vol -f practica1.raw windows.psscan

![alt text](image-4.png)

- Command history  

vol -f practica1.raw windows.cmdscan

![alt text](image-5.png)

vol -f practica1.raw windows.consoles

![alt text](image-6.png)

- Detailed operating system information  

vol -f practica1.raw windows.info

![alt text](image-7.png)

vol -f practica1.raw windows.registry.hivelist

![alt text](image-8.png)

vol -f practica1.raw windows.registry.printkey

![alt text](image-9.png)

- Files loaded into memory  

vol -f practica1.raw windows.filescan

![alt text](image-10.png)

vol -f practica1.raw windows.dlllist

![alt text](image-11.png)

- Active connections  
w
vol -f practica1.raw windows.netscan

![alt text](image-12.png)



