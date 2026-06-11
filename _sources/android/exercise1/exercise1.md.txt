# Android forensics basics

## Evidence Extraction

Smartphones have become an essential tool across all sectors of modern society: from regular consumers to high-ranking government officials and the business sector.

Smartphones are well known for their versatility. In a single day, a smartphone can function as:

- A wallet
- A barcode reader
- A satellite navigation system
- An email or social media client
- A WiFi hotspot
- A telephone

Recently, smartphones have also been increasingly used as smart health sensors, allowing cardiac patients to safely remain at home while medical staff remotely monitor and supervise their heart conditions.

Mobile forensics refers to digital forensic analysis related to the recovery of data or digital evidence from mobile devices such as smartphones, tablets, and GPS devices.

It is important that this recovery process is performed under forensic conditions.

Several aspects must be considered during mobile forensic investigations:

- Data acquisition often requires collecting evidence from a powered-on device because hardware or software interfaces to access internal memory may intentionally be unavailable.
- External storage such as SD cards may contain valuable evidence and must also be acquired.
- Maintaining the Chain of Custody (CoC) and preserving integrity is difficult because many forensic tools require installing applications on the analyzed device.
- Mobile file systems usually cannot be mounted as read-only.
- Malware may detect analysis environments and destroy evidence.
- The acquisition process itself may alter evidence integrity, potentially affecting admissibility in court.

## Objectives

- Become aware of the difficulties involved in obtaining forensic evidence from Android devices.
- Learn how to extract forensic evidence from Android devices.

## Materials

- Android Studio
- VirtualBox
- SDK Platform Tools
- Andriller
- AFLogical OSE

## Familiarization with Android

### Install Android Studio

Android Studio can be downloaded from the [official website](https://developer.android.com/studio):

Installation on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install openjdk-17-jdk -y
```

Download Android Studio:

```bash
wget https://redirector.gvt1.com/edgedl/android/studio/ide-zips/latest/android-studio-linux.tar.gz
```

Extract the package:

```bash
tar -xvf android-studio-linux.tar.gz
```

Launch Android Studio.

![alt text](./images/image.png)

A welcome screen similar to the one shown below should appear.

![alt text](./images/image-1.png)

To view available virtual devices, open **More Actions** → **Virtual Device Manager**.

![alt text](./images/image-3.png)

![alt text](./images/image-2.png)

### Run an Android Virtual Device (AVD)

Create an emulator using the GUI from the previous section, or run the following command:

```bash
avdmanager create avd -n Android26 -k "system-images;android-26;default;x86_64" -c 10M
```

Verify that the device has been installed correctly:

```bash
avdmanager list avd
```

![alt text](./images/image-5.png)

Start the emulator as follows:

```bash
emulator -avd Android26
```

![alt text](./images/image-6.png)

### Install Android Debug Bridge (ADB Platform Tools) and test it

Installation on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install adb fastboot -y
```

Verify installation:

```bash
adb version
```
![alt text](./images/image-7.png)

Inside the emulator:

1. Open `Settings`.
2. Go to `About phone`.
3. Tap `Build number` 7 times.
4. Developer options will be enabled.
5. Go to `Developer Options`.
6. Enable `USB debugging`.

Start ADB server:

```bash
adb start-server
```

Stop ADB server:

```bash
adb kill-server
```

List devices:

```bash
adb devices
```

![alt text](./images/image-8.png)

Open shell:

```bash
adb shell
```

![alt text](./images/image-9.png)

Restart ADB as root:

```bash
adb root
```

![alt text](./images/image-10.png)

Pull files from device:

```bash
adb pull /sdcard/Download/
```

![alt text](./images/image-11.png)

Push files to device:

```bash
echo hello > hello.txt
adb push hello.txt /sdcard/Download
```

![alt text](./images/image-12.png)

Reboot device:

```bash
adb reboot
```

Install APK:

```bash
adb install app.apk
```

![alt text](./images/image-13.png)

Uninstall application:

```bash
adb uninstall owasp.mstg.uncrackable2
```

![alt text](./images/image-14.png)

List installed packages:

```bash
adb shell pm list packages
```

![alt text](./images/image-15.png)

Capture screenshots:

```bash
adb exec-out screencap -p > screenshot.png
```

![alt text](./images/image-16.png)

Record screen:

```bash
adb shell screenrecord /sdcard/demo.mp4
```

![alt text](./images/image-17.png)

Pull recorded video:

```bash
adb pull /sdcard/demo.mp4
```

![alt text](./images/image-18.png)

## Android Virtualization Close to Real Conditions

Download Android from the [official website](https://www.android-x86.org/) or using wget:

```bash
wget https://sourceforge.net/projects/android-x86/files/latest/download -O android-x86.iso
```

Recommended VMWare configuration:

- 4GB RAM
- 20GB Hard Disk
- 256MB Video Memory

After booting the virtual machine from the ISO, select **Installation - Install Android-x86 to hard disk**.

![alt text](./images/image-19.png)

Select the "Create/Modify partitions" option.

![alt text](./images/image-20.png)

Select "Yes" when asked for GPT.

![alt text](./images/image-21.png)

Then create a **Linux filesystem** partition.

![alt text](./images/image-22.png)

![alt text](./images/image-23.png)

![alt text](./images/image-24.png)

![alt text](./images/image-25.png)

Once the partition is created, click on "OK".

![alt text](./images/image-26.png)

Select "ext4" and click on "OK".

![alt text](./images/image-27.png)

Click on "YES" several times until reboot.

![alt text](./images/image-28.png)

![alt text](./images/image-29.png)

![alt text](./images/image-30.png)

![alt text](./images/image-31.png)

![alt text](./images/image-32.png)

Once the device is rebooted and the ISO is removed, before starting the device, click "e" twice on the GRUB menu to edit it.

![alt text](./images/image-33.png)

![alt text](./images/image-34.png)

Remove the `quiet` line and add `nomodeset xforcevesa`. Then press `ESC` followed by `b` to boot with the modified configuration. This step is required because, without these kernel parameters, the system may fail to start the graphical interface and remain on a text-only TTY console.

![alt text](./images/image-35.png)

![alt text](./images/image-36.png)

After logging in, the graphical desktop environment should appear.

![alt text](./images/image-37.png)

Enable Developer Options on this device using the same procedure described for the Android Studio emulator.

![alt text](./images/image-38.png)

![alt text](./images/image-47.png)

![alt text](./images/image-48.png)

![alt text](./images/image-49.png)

![alt text](./images/image-50.png)

Finally, determine the device's IP address. Several methods are available; one option is to open a terminal on the Android-x86 VM and run:

```bash
ip a
```

![alt text](./images/image-51.png)

On the host machine, connect to the device over the network using ADB as shown below. Replace the IP address with the one obtained in the previous step.

```bash
adb devices
adb connect 192.168.1.41:5555
adb devices
```

![alt text](./images/image-52.png)

To add a Google account, open **Settings** and navigate to the **Accounts** section.

![alt text](./images/image-39.png)

Click on "Add account".

![alt text](./images/image-40.png)

Sign in with any Google account.

![alt text](./images/image-42.png)

Once sign-in completes successfully, the account should appear in the Accounts list.

![alt text](./images/image-43.png)

To install AFLogical OSE, download the APK from [the official repository](https://github.com/nowsecure/android-forensics) and run:

```bash
adb install ./AFLogical-OSE_1.5.2.apk
```

![alt text](./images/image-44.png)

Select everything and click on "Capture".

![alt text](./images/image-45.png)

Once extraction completes, a dialog displaying **Data extraction completed** should appear.

![alt text](./images/image-46.png)

Pull the forensic evidence folder from the device using:

```bash
adb pull /sdcard/forensics/ .
```

The following folders should appear on the host machine.

![alt text](./images/image-53.png)

Next, Andriller is used to perform a broader logical extraction. The commands below use the Fish shell; adapt the virtual-environment activation step if you use Bash or another shell:

```bash
python -m venv env
source env/bin/activate.fish
python -m pip install --upgrade pip
python -m pip install andriller
```

![alt text](./images/image-54.png)

Execute the program:

```bash
python -m andriller
```

The Andriller GUI should open. Click **Output..** and select the destination folder for the extraction results.

![alt text](./images/image-55.png)

After selecting the output folder, click **Check** to verify the device connection.

![alt text](./images/image-56.png)

Finally, click **Extract**. Andriller connects to the device automatically and pulls the available forensic data.

![alt text](./images/image-57.png)

Once finished, a report like the following will be generated:

![alt text](./images/image-58.png)

These are the generated files:

![alt text](./images/image-59.png)

## WhatsApp Forensic Analysis

### What are consensual and non-consensual forensic analyses?

#### Consensual Analysis

A forensic analyst has authorization from the device owner to perform the analysis.

This means:

- The owner provides passwords and credentials.
- The investigator can access the device legally and directly.

#### Non-Consensual Analysis

The analysis is performed under judicial authorization.

In these situations:

- Credentials are usually unavailable.
- Advanced forensic methods may be required.
- Physical acquisition may become necessary.

### What techniques can be used to analyze WhatsApp conversations?

#### Screenshot Analysis

Conversations can be analyzed using screenshots.

However:

- Screenshots are easy to manipulate.
- Device integrity must be verified.

#### Token-Based Database Extraction

WhatsApp Web sessions may expose authentication tokens.

This can allow forensic extraction of synchronized conversations.

#### Database Extraction from the Device

This is the most reliable method.

Requirements:

- Root access
- Physical or logical acquisition

Useful commands:

Locate databases:

```bash
adb shell
find /data/data/com.whatsapp -name "*.db"
```

### Where does WhatsApp store encryption keys and databases?

#### Encryption Key

```text
/data/data/com.whatsapp/files/key
```

#### Databases

```text
/data/data/com.whatsapp/databases/
```

Important database files:

```text
msgstore.db
wa.db
```

Extract directories:

```bash
adb pull /data/data/com.whatsapp/files/key
```

```bash
adb pull /data/data/com.whatsapp/databases/
```

Root shell may be required:

```bash
adb root
adb shell
```

```bash
aapt dump badging WhatsApp.apk
```

Extract APK from device:

```bash
adb shell pm path com.whatsapp
```

```bash
adb pull /data/app/com.whatsapp/base.apk
```

Generate complete Android backup:

```bash
adb backup -apk -shared -all
```

Inspect logs:

```bash
adb logcat
```

Capture device filesystem:

```bash
adb shell ls -R /sdcard/
```

## WhatsApp Analysis

WhatsApp was installed on the device and linked to an account as shown below (the interface text appears garbled in the screenshot because certain characters failed to render correctly, not because anything was deliberately blurred):

![alt text](./images/image-60.png)

Connect to the device with root privileges and verify the WhatsApp database directory:

```bash
adb root
adb shell
ls -lah /data/data/com.whatsapp/databases/
```

![alt text](./images/image-61.png)

Pull the entire WhatsApp application data directory to the host for offline analysis.

```bash
adb pull /data/data/com.whatsapp
```

![alt text](./images/image-62.png)

Several SQLite databases contain useful artifacts; `msgstore.db` stores the message history. Query it as follows:

```bash
sqlite3 msgstore.db
select * from message ORDER BY timestamp;
```

![alt text](./images/image-63.png)

The following summary explains how to interpret the `message` table output:

#### 1. Message ID

Values such as `518`, `517`, `516`, and so on are the internal message identifiers (primary key).

#### 2. Technical fields (flags / status)

Many columns contain `0`, `-1`, or `NULL`. These represent internal state flags, for example:

- read / unread
- sent / received / pending
- system-level flags

#### 3. Chat or user identifier

Values such as `3AFDC...` typically correspond to a **JID** (Jabber ID):

- a phone number or group identifier
- WhatsApp's internal addressing format

#### 4. Timestamp (critical for timeline reconstruction)

Values such as `17007477`, `19000`, `36000`, and so on are usually UNIX timestamps, expressed in seconds or milliseconds depending on the column. They indicate when a message was sent or received.

#### 5. Message text field

The readable text visible on the right side of the output includes entries such as:

- "Seguro q hace tela calor"
- "Ya"
- "No sé si es lo mejor"
- "Comemos en algún sitio?"

These values typically map to columns named `data`, `text`, or `message`.

#### 6. Multimedia fields (empty in this capture)

The numerous `NULL` values mean:

- no image attached
- no audio attached
- no video attached

If media were present, these columns would contain file paths or MIME types.
