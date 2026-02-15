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

- Operating system profile  
- Process list  
- Command history  
- Detailed operating system information  
- Files loaded into memory  
- Active connections  
