# Advanced analysis Volatility

In this practice, you will learn how to use the basic functionalities of Volatility to analyze memory dumps. Volatility is a powerful memory analysis tool that allows the identification of processes, network connections, Windows registry information, open files, and more. During this activity, you will work with a real memory dump and will be required to use various plugins and command modifiers to solve the 16 questions posed.

The required steps are described below:

1. Determine the operating system profile corresponding to the memory dump.
2. Use the appropriate plugins to extract the requested information.
3. Apply command modifiers to filter and organize the results.

By the end of the practice, you should be able to identify active processes, registry keys, network connections, and other relevant artifacts.

---

## Requirements

1. Make sure you have Volatility 2.x or Volatility 3 installed.
2. Download the memory dump assigned for this practice.
3. Document the commands used to answer each of the questions.

Submit a detailed report containing the answers to the 16 questions, accompanied by screenshots of the commands executed and the results obtained.

---

## Questions

1. **Operating System Profile**  
   Use the memory dump to identify the operating system profile compatible with this dump.

2. **Running Processes**  
   How many processes were active on the system at the time the memory capture was taken?

3. **Parent Process**  
   What is the PID of the parent process of the program `7zFM.exe`?

4. **Windows Registry**  
   Determine how many registry hives are present in the memory dump. This information is critical because there are suspicions that the system is infected.

5. **Registry Keys**  
   How many registry keys exist at the root of the `SYSTEM` hive, including volatile keys?

6. **ImagePath Key**  
   Identify the value of `ImagePath` in the following key:  
   `ControlSet001\services\Smb`

7. **User Password**  
   Recover the login password of the user `Admin`.

8. **External Connections**  
   Determine how many connections to external IP addresses were established at the time of the memory capture.

9. **FILE_OBJECT Structures**  
   How many `FILE_OBJECT` structures appear in memory?

10. **Compressed File**  
    One of the open files is compressed using 7z. What default name does Volatility assign to it when exporting it as a `.dat` file?

11. **File Path**  
    What is the on-disk path of the compressed 7z file, as shown by the `filescan` plugin?

12. **File Creation Date**  
    When was the compressed file created?  
    Expected format: `DD/MM/YYYY`

13. **Visited Website**  
    Find the address of a science-related website visited using Firefox.  
    Expected format: `https://xxxxxxx.xx`

14. **Date and Time of Visit**  
    When was the website mentioned in the previous question visited?  
    Expected format: `DD/MM/YYYY HH:MM:SS (UTC)`

15. **Notepad**  
    The Notepad application contained a password that we want to recover. Can you identify it?  
    Hint: the user reuses part of their passwords.

16. **Encrypted File**  
    Analyze the contents of the compressed and encrypted 7z file. What does it contain?
