# Android forensics medium

## PART A: Professional Third-Party Tools

### Objectives

- Investigate the professional tools offered by different companies for Android forensic investigations.
- Study the functionality they provide.
- Evaluate and test forensic tools for mobile devices.

## Materials

- Avilla Forensics

## Tasks

### 1. Install Avilla Forensics

In my case, I decided to install the tool directly from the institute NAS.

Once downloaded, I navigated to the installation directory and executed the `.exe` file.

The first step was entering my investigator information in order to preserve the chain of custody during the forensic process.

After that, I created a new forensic case within the application.

---

### 2. Test the functionality provided by Avilla Forensics

To test the tool, I used my Android smartphone.

The first extraction method tested was social network backup extraction through APK downgrade.

Before performing the extraction, several Android security protections had to be disabled in order to allow the acquisition process.

Because the device used was relatively old, this process was possible without major issues.

Once the protections were disabled, I selected the application package I wanted to analyze and started the extraction process.

The tool was capable of extracting different kinds of evidences depending on the permissions granted to the application and the security level of the device.

Some of the evidences obtained included:

- Application databases
- Cached files
- Multimedia files
- User account information
- Application logs
- Message backups

The amount of information extracted depended heavily on whether the device was rooted and on the Android version installed.

---

### 3. Hardware and software recommendations for mobile forensic investigations

One of the first things that should be acquired for any mobile forensic laboratory is a Faraday bag.

This is essential because many modern mobile devices may contain malware or remote wipe mechanisms capable of deleting or altering evidence remotely.

Using a Faraday bag isolates the device from any wireless communication, preserving the integrity of the evidence during transportation and acquisition.

There are many options available on the market with different prices and quality levels.

Recommended options would be:

- Mid-range professional Faraday bags
- High-quality certified Faraday bags
- Cheap alternatives, although their effectiveness and durability are questionable

Regarding forensic extraction software, there are important limitations to consider.

Except for extremely advanced spyware usually available only to governments, no software can fully bypass the protections of modern non-rooted devices.

Because of this, forensic investigators usually rely on specialized commercial solutions.

The best forensic suites currently available are:

| Tool | Physical Extraction | Android/iPhone Compatibility | Lock Bypass | Cloud Extraction | Analysis Capabilities | Cost |
|---|---|---|---|---|---|---|
| Cellebrite UFED | Excellent | Very High | Very Advanced | Good | Good | Very High |
| MSAB XRY | Excellent | Very High | Advanced | Good | Good | High |
| Oxygen Forensic Detective | Good | High | Medium | Excellent | Very Good | High |
| Magnet AXIOM | Limited | Medium | Low | Good | Excellent | High |

From a professional perspective, I would prioritize purchasing:

- Cellebrite UFED for physical extraction
- Oxygen Forensic Detective for cloud investigations
- Faraday bags for evidence preservation
- Dedicated forensic workstations with write blockers

---

## PART B: Feasibility of Android Forensic Analysis

In general, RAM memory analysis and persistent storage analysis are considered essential parts of digital forensic investigations.

After the advances achieved in Windows, Linux and macOS forensic analysis, researchers started investigating whether tools such as DD, LiME and Volatility could also be used for Android devices.

Many research papers focus on Android RAM analysis, especially on virtualized Android devices.

## Objectives

- Investigate the difficulties involved in Android forensic investigations.
- Study the feasibility of performing forensic analysis depending on device characteristics.

## Documentation

- Practical Infeasibility of Android Smartphone Live Forensics

## Tasks

### 1. Ideal situation for a perfect Android forensic investigation

The ideal forensic scenario would involve the following conditions:

- Full root access to the device
- No security barriers
- The device unlocked at acquisition time
- USB debugging enabled
- Availability of kernel source code and symbol tables
- Kernel support for loadable modules such as LiME

Under these conditions, investigators would be able to:

- Clone the internal storage
- Obtain a RAM dump
- Analyze volatile memory
- Preserve evidence integrity

However, this situation is extremely rare in real-world investigations.

---

### 2. Real-world limitations and possible solutions

#### a. Rooting without data loss

Most rooting procedures require rebooting the device.

This destroys the RAM contents, which are essential for live forensic analysis.

Possible solutions include:

- Exploiting privilege escalation vulnerabilities
- Using temporary root exploits
- Leveraging vulnerabilities such as Rage Against The Cage

However, these methods are highly device-dependent.

---

#### b. Android security mechanisms

Android devices implement many protections:

- Screen lock
- Disabled USB debugging
- Full disk encryption
- OEM lock
- Samsung Knox

These protections make physical and logical acquisition extremely difficult without user interaction.

Possible solutions include:

- Cold boot attacks
- Live acquisition while the device is unlocked
- Specialized forensic hardware
- Exploiting device vulnerabilities

---

#### c. Hardware and software fragmentation

Android fragmentation is one of the biggest challenges for investigators.

Each manufacturer uses:

- Different kernels
- Different partition layouts
- Different security mechanisms
- Different Android versions

This makes tools such as LiME and Volatility difficult to configure.

Investigators often need to:

- Identify the exact device model
- Obtain matching kernel sources
- Cross-compile forensic modules manually

In many cases, manufacturers do not provide the required sources.

---

#### d. Technical and legal limitations

Tools such as Volatility may fail due to incompatibilities or unsupported memory formats.

Additionally, using non-standard rooting techniques could invalidate evidence in legal proceedings.

Because of this, investigators must:

- Fully document every action performed
- Use validated methodologies
- Understand every forensic tool used
- Preserve chain of custody at all times

---

## PART C: Chat Analysis

In the context of a police investigation involving a murder connected to drug trafficking, three smartphones belonging to members of a criminal organization were seized.

The suspects were known as:

- Capo: Leader of the organization
- Hitman: Senior gang member
- Mule: Young and inexperienced member recently recruited

The extracted logical acquisitions and downgraded applications were analyzed in order to answer the following questions.

---

## Capo

## 1. Vehicle pickup location

Capo told Mule to travel to Madrid in order to pick up a vehicle.

The exact location mentioned in the WhatsApp conversation was:

**Cruz de la Horca, Av. Felipe II, 23, 28280 El Escorial, Madrid**

---

## 2. Voice message analysis

A WhatsApp voice message sent by Capo on October 6th during the afternoon was recovered from the WhatsApp media directory.

The audio file was located inside the WhatsApp voice notes folder.

After listening to the recording, the following phrase could be heard:

> "That is Mathew's business, do your job and stick to it."

The message was clearly a reprimand directed at Mule for asking too many questions.

---

## 3. Who killed Mule?

The final WhatsApp conversations strongly suggest that the murderer was Mathew.

The relevant chat was identified through the WhatsApp database:

- Chat ID was located
- The associated JID was identified
- The phone number was linked to the contact "Mathew" inside `wa.db`

This matches the name mentioned in the recovered voice message.

---

## Mule

## 1. Birthday party location

Two photographs taken during Mule's birthday party were recovered from the camera directory.

The EXIF metadata was analyzed using:

```bash
exiftool image.jpg
```


TBD FALTAN COSAS!!

## Hitman

## 1. Telegram location recovery

On October 7th, 2023, Hitman exchanged several Telegram messages with Capo, whose Telegram username was **Ernesto Capote**.

The Telegram database was analyzed using SQLiteStudio.

First, the user associated with Ernesto Capote was identified inside the `users` table.

After that, the messages were located inside the `messages_v2` table.

During the conversation, they mentioned receiving information from someone called **Berto**, which could be relevant for future investigation.

One of the messages sent by Capo contained a Telegram location link.

After recovering and opening the location, the coordinates pointed to:

**Rúa do Castelo Ramiro, Ourense**

---

## 2. Who killed Mule and when?

The final Telegram conversations clearly reveal the events that occurred.

Mule had stolen part of a drug shipment for personal use during his birthday party.

This caused serious problems for Capo with another criminal organization referred to as **"the Perillo group"**.

After seeing the birthday party pictures and confirming that the missing drugs had been consumed by Mule, Hitman and Capo decided that Mule had become a liability.

The conversations indicate that both of them agreed Mule needed to be eliminated in order to recover the trust of the organization.

At:

**2023-10-17 16:28:41 UTC**

Hitman, whose real name was identified as **Mathew**, sent a Telegram message to Capo confirming that the murder had been completed.

Therefore:

- **Murderer:** Mathew (Hitman)
- **Date:** October 17th, 2023
- **Time:** 16:28:41 UTC

---

## 3. Exact murder location

The photographs stored on Hitman’s phone taken on the day of the murder were analyzed.

The images were extracted from the camera directory and their metadata was examined using:

```bash
exiftool image.jpg