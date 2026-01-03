# PRACTICE 1: Post-mortem Analysis, Windows Artifacts

## Main objectives of the practice
- Analyze the evidence provided by different artifacts in Windows operating systems.

---

## PART A

Review Topic 4 and answer the following questions:

### 1. Regarding *prefetch*
a. What are they?  
b. What file extension do they have?  
c. In which directory can they be found?  
d. What forensic information do they store that may be relevant for an investigation?

### 2. Regarding *LOGs*
a. Which ones do you think are the most important based on the information they store?  
b. Where can they be found?

### 3. Regarding the hibernation file `hiberfil.sys`
a. Where can it be found?  
b. Which tool can be used to decode its contents?  
c. Do you think the information it contains is important?

### 4. Regarding snapshots, restore points and/or Volume Shadow Copies Service (VSS)
a. What file system is required to use this technology?  
b. Is it enabled by default or does the user need to activate it?  
c. How often are they created?  
d. Think of a couple of scenarios where they may be useful.

### 5. Questions related to the Windows Registry
a. Research how to import and export registry keys in CLI and GUI environments.  
b. List registry keys that are forensically interesting to export and analyze, explaining what information they reveal.

### 6. Events of forensic interest
What types of events may be interesting to inspect from a forensic point of view? Give a couple of examples.

### 7. Software tools
Research which software tools can be used to work with the following artifacts:
- Prefetch
- Logs
- Hibernation file
- Volume Shadow Copies Service
- System registry
- Event management
- Shortcuts
- Caches and browsing history
- Recycle Bin

---

## PART B

The practice consists of extracting as much evidence as possible from a Windows operating system by performing targeted searches on the different artifacts it uses.

Although in a real scenario this would be done using a system image, for this practice it is recommended, for agility, to use the operating system installed on the student’s computer.

### Software to be used
- **A.** Windows 10 (32 or 64 bits)
- **B.** FTK Imager
- **C.** Arsenal Image Mounter
- **D.** Registry Explorer
- **E.** Reg Ripper
- **F.** WRR
- **G.** LinkParser
- **H.** JumpListExplorer
- **I.** ShellbagExplorer
- **J.** USB Detective

### Requirements

#### 1.
Use FTK Imager to extract from your system and/or mounted image the appropriate files where evidence can be analyzed.

#### 2.
Review, one by one, the different Windows artifacts listed below and comment, using descriptions and/or screenshots, on the information obtained.

> For each artifact it will be necessary to previously extract the evidence that stores this type of information (for example, the Windows registry:  
> `C:\Windows\System32\Config\SYSTEM`, `SOFTWARE`, `SAM`, etc.).

---

## Artifacts and paths of interest

### System information
- **System version, machine name and time zone**  
  `Software\Microsoft\Windows NT\CurrentVersion`

- **Last access timestamp**  
  `System\ControlSet001\Control\Filesystem`

- **Shutdown time**  
  `System\ControlSet001\Control\Windows`

### Network
- **Network interfaces**  
  `System\ControlSet001\Services\Tcpip\Parameters\Interfaces\{GUID_INTERFACE}`

- **Network history**  
  `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\`  
  `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`

- **When a network was connected**  
  `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`

### Sharing and startup
- **Shared folders**  
  `System\ControlSet001\Services\lanmanserver\Shares\`

- **Startup programs**  
  - `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
  - `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
  - `Software\Microsoft\Windows\CurrentVersion\RunOnce`
  - `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
  - `Software\Microsoft\Windows\CurrentVersion\Run`

### User activity
- **Searches in the search bar**  
  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`

- **Typed paths in Start or Explorer**  
  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`

- **Recent documents**  
  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

- **Recent Office documents**  
  `NTUSER.DAT\Software\Microsoft\Office\{Version}\{Excel|Word}\UserMRU`

- **Reading position of the last opened document**  
  `NTUSER.DAT\Software\Microsoft\Office\Word\Reading Locations\Document X`

- **Autosaved Office files**  
  `C:\Users\{user}\AppData\Roaming\Microsoft\{Excel|Word|PowerPoint}\`

- **OpenSaveMRU**  
  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`

- **Last executed commands**  
  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`  
  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Policies\RunMRU`

- **UserAssist (programs executed)**  
  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

- **Taskbar-related events**  
  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage`

- **Recent applications**  
  `Software\Microsoft\Windows\CurrentVersion\Search\RecentApps`

### Shortcuts and Jump Lists
- **Recent documents (LinkParser / LeCMD)**  
  `C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent`

- **Jump Lists**  
  - `AutomaticDestinations`
  - `CustomDestinations`  
  Path:  
  `C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent\`

### Shellbags
- `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
- `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`

### USB and MTP devices
- **MTP devices**  
  `C:\Users\{user}\AppData\Local\Temp\WPDNSE\{GUID}`

- **USB storage (VID / PID)**  
  `SYSTEM\ControlSet001\Enum\USBSTOR`

- **USB volume names**  
  `SOFTWARE\Microsoft\Windows Portable Devices\Devices`

- **User who used the USB device**  
  `SYSTEM\MountedDevices`  
  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`

- **Logical volume serial number**  
  `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`

- **First and last connection time**  
  `SYSTEM\ControlSet001\Enum\USBSTOR\{VEN_PROD_VERSION}\{USB_SERIAL}\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`  
  `C:\Windows\inf\setupapi.dev.log`

### Databases and system artifacts
- **Cortana database (older versions)**  
  `C:\Users\{user}\AppData\Local\Packages\Microsoft.Windows.Cortana_xxxx\LocalState\ESEDatabase_CortanaCoreInstance\CortanaCoreDb.dat`

- **Windows notifications**  
  `C:\Users\{user}\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db`

- **Timeline**  
  `C:\Users\{user}\AppData\Local\ConnectedDevicesPlatform\ActivitiesCache.db`

- **Windows Store**  
  `C:\Users\{user}\ProgramData\Microsoft\Windows\AppRepository\StateRepositoryDeployment.srd`  
  `AppxAllUserStore` registry keys

### Other artifacts
- **Thumbnails and Thumbcache**  
  `thumbs.db`  
  `C:\Users\{user}\AppData\Local\Microsoft\Windows\Explorer`

- **Recycle Bin**  
  `C:\$Recycle.Bin`

- **OfficeFileCache**  
  `C:\Users\{user}\AppData\Local\Microsoft\Office\{Version}\OfficeFileCache`

- **OfficeBackstage**  
  `C:\Users\{user}\AppData\Local\Microsoft\Office\16.0\BackstageInAppNavCache`

- **Public IP (ETLParser)**  
  `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs`

- **PowerShell command history**  
  `C:\Users\{user}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

- **Prefetch**  
  `C:\Windows\Prefetch`

- **SuperFetch**  
  `C:\Windows\Prefetch\Ag*.db`

- **SRUM**  
  `C:\Windows\System32\sru\SRUDB.dat`

- **ShimCache**  
  `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`

- **AmCache**  
  `C:\Windows\AppCompat\Programs\Amcache.hve`

- **Scheduled tasks**  
  `C:\Windows\Tasks`  
  `C:\Windows\System32\Tasks`

- **Services**  
  `SYSTEM\ControlSet001\Services`

- **BAM**  
  `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`  
  `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}`

- **Event logs**  
  `C:\Windows\System32\winevt\Logs`
