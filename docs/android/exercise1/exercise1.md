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

### Install Android Studio**

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

Open it.

![alt text](./images/image.png)

A menu similar to the shown below should appear.

![alt text](./images/image-1.png)

In order to know the available devices, click on "More Actions" --> "Virtual Device Manager".

![alt text](./images/image-3.png)

![alt text](./images/image-2.png)

### Run an Android Virtual Device (AVD)**

Create an emulator using the the previous GUI or using the following command:

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

### Install Android Debug Bridge (ADB Platform Tools) and test it**

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

After inicializing the machine, click on "Installation - Install Android-x86 to hardisk".

![alt text](./images/image-19.png)

Select the "Create/Modify partitions" option.

![alt text](./images/image-20.png)

Select "Yes" when asked for GPT.

![alt text](./images/image-21.png)

And createa "Linux filesystem" partition.

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

Remove the "quiet" line and type "nomodeseet xforvesa". Then, click `ESC` + `b`. This step is done because if these words are not added, the mobile will not have graphical interfe, having only a console tty.

![alt text](./images/image-35.png)

![alt text](./images/image-36.png)

After login, an graphical interface will appear.

![alt text](./images/image-37.png)

Enable the developer mode in the device as previously with the Android Studio device.

![alt text](./images/image-38.png)

![alt text](./images/image-47.png)

![alt text](./images/image-48.png)

![alt text](./images/image-49.png)

![alt text](./images/image-50.png)

Lastly, check the IP of the device, there are multiple options, but it can be done opening a terminal and executing the following command:

```bash
ip a
```

![alt text](./images/image-51.png)

In the main machine, connect to the device using adb and shown below. Take note of chaging the IP address by the one extracted in the step before.

```bash
adb devices
adb connect 192.168.1.41:5555
adb devices
```

![alt text](./images/image-52.png)

If we want to add an account, open settings and navigate to the "Accounts" section.

![alt text](./images/image-39.png)

Click on "Add account".

![alt text](./images/image-40.png)

And sign in using any account.

![alt text](./images/image-42.png)

Once the login is successfull, the account should appear in the menu.

![alt text](./images/image-43.png)

In order to install AFLogical OSE, download it from [here](https://github.com/nowsecure/android-forensics) and execute the following command:

```bash
adb install ./AFLogical-OSE_1.5.2.apk
```

![alt text](./images/image-44.png)

Select everything and click on "Capture".

![alt text](./images/image-45.png)

Once the extraction is done, a dialogue with "Data extraction completed" should appear.

![alt text](./images/image-46.png)

Extract the evidences folder using the following command:

```bash
adb pull /sdcard/forensics/ .
```

The following folders should appear.

![alt text](./images/image-53.png)

Now, the application andriller will be used to extract evidences. Note that it will be done using fish, so it may vary if using other terminals:

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

The following menu should appear, click on "Output.." and set the output folder.

![alt text](./images/image-55.png)

Once the folder is selected, click on "Check".

![alt text](./images/image-56.png)

Lastly, click on "Extract" and the program will connect to the device automatilly and will extract the evicences.

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

## Whatsapp analysis

Whatsapp has been installed and linked to an account as shown below (to be honest I did not blurred anything, characters are simply not loading XD):

![alt text](./images/image-60.png)

Connect to the device using root and verify the whatsapp database directory:

```bash
adb root
adb shell
ls -lah /data/data/com.whatsapp/database/
```

![alt text](./images/image-61.png)

Extract the entire whatsapp directory using adb for an easier analysis.

```bash
adb pull /data/data/com.whatsapp
```

![alt text](./images/image-62.png)

There are several databases with useful info, but the following one contains the messages:

```bash
sqlite3 msgstore.db
select * from message ORDER BY timestamp;
```

![alt text](./images/image-63.png)

Here is a small summary to understand what is happening:

TBD traducir y poner bonito!

1. ID del mensaje
El número tipo 518, 517, 516...
Es el identificador interno del mensaje (primary key)
2. Campos técnicos (flags / estado)
Muchos 0, -1, NULL
Son estados internos como:
leído / no leído
enviado / recibido / pendiente
flags de sistema
3. Identificador del chat o usuario
Valores tipo:
3AFDC...
Esto suele ser el JID (Jabber ID):
número de teléfono o grupo
formato interno de WhatsApp
4. Timestamp (muy importante)
Números como:
17007477, 19000, 36000, etc.
Normalmente son timestamps en formato UNIX o milisegundos
Indican cuándo se envió/recibió el mensaje
5. Campo de texto del mensaje
Lo que ves a la derecha:
“Seguro q hace tela calor”
“Ya”
“No sé si es lo mejor”
“Comemos en algún sitio?”
Esto normalmente corresponde a algo como:
data
text
message
6. Campos multimedia (vacíos en tu captura)
Muchos NULL
Significa:
no hay imagen
no hay audio
no hay vídeo
Si hubiera media verías rutas o MIME types
7. Otros campos técnicos comunes (los que no se ven bien)

En WhatsApp suelen existir también:

media_type
status
key_from_me (si lo enviaste tú o no)
remote_resource
quoted_row_id (respuestas citadas)
latitude/longitude (si hay ubicación)
📌 Interpretación rápida de tu imagen

Lo más importante de lo que muestras:

Cada fila = 1 mensaje
La columna final visible = texto del mensaje
Los bloques de NULL = sin multimedia o campos no usados
Los números grandes = timestamps o IDs internos
El hash largo (3AFDC...) = chat o usuario/grupo