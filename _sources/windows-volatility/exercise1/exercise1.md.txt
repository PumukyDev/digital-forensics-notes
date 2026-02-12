# Volatility

As we know, there are two types of forensic analysis: live and post-mortem.

The first occurs when the system is still active during the analysis. In this scenario, it is possible to acquire volatile data such as RAM, running processes, Internet connections, and temporary files. If disk encryption is used, this type of analysis allows the file system to be decrypted using the cached key. On the other hand, this type of analysis requires greater expertise, and the system constantly modifies its data, which may affect judicial admissibility.

The analyst should also not trust any tools provided by the system itself, as they may have been deliberately manipulated.

---

## SECTION A)

### Objective

- Develop a forensic tool composed of executable commands for evidence extraction and a batch processing file to launch them, in order to obtain the most relevant evidence studied in class.

### Materials

- Sysinternals Suite  
- NirSoft  
- ntsecurity.nu  
- Microsoft commands  
- Any other software you consider appropriate  

The idea is to create a USB stick containing the tools and a batch processing file. The BATCH file will be executed on the system to be examined. This BAT file will perform functions such as copying logs to the external USB drive and collecting information such as date, time, registered users, process tree, system uptime, etc.

---

## SECTION B)

### Objective

- Prepare and use the graphical triage tool Wintriage for the rapid and structured acquisition of forensic evidence on Windows systems, allowing the controlled collection of relevant information during a live forensic analysis.

Wintriage is a graphical forensic tool designed to facilitate the initial collection of evidence on compromised Windows systems. Its main focus is forensic triage, that is, the rapid acquisition of key information that allows the analyst to assess the system’s state and decide on the next steps of the investigation.

For its use, the tool should preferably be executed from an external medium (for example, a forensic USB), thereby minimizing alteration of the analyzed system and avoiding the use of local tools that may have been manipulated. Wintriage allows easy selection of the artifacts to be collected and stores the results in a previously defined directory.

Prepare the tool, learn how to configure it, and perform a test of live digital evidence acquisition.

---

## SECTION C)

We have been provided with a RAM capture that must be subjected to a complete forensic analysis.

### Main Objectives of the Practice

- Analyze RAM memory  
- Install and learn how to use the VOLATILITY tool  

Detail the process (command used and screenshot of the command output) to obtain this information.

We are required to obtain the following information:

- Operating system profile  
- Process list  
- Command history  
- Detailed operating system information  
- Files loaded into memory  
- Active connections  
