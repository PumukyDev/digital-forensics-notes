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

**1. Download the disk image "recuperacion.dd".**

**2. Analyze the disk and determine the following:**

**a. Disk partitioning system (MBR/GPT)**

El disco usa GPT

![alt text](./images/image-90.png)


**b. Number of valid partitions and their sizes**

El disco solo tiene una partición válida.

![alt text](./images/image-91.png)

Tiene un tamaño de 447 GB.

![alt text](./images/image-92.png)

**c. Investigate whether a file system may exist**

Esta partición utiliza el sistema de archivos NTFS.

![alt text](./images/image-93.png)

**3. Use **PhotoRec** to recover as much information as possible from the disk image.**

Abre photorec y selecciona el disco

![alt text](./images/image-75.png)

Clica en "Search"

![alt text](./images/image-76.png)

Y haz clik en "Other". Una serie de archivo sdeben aparecer.

![alt text](./images/image-77.png)

Pulsa la "C" para guardarlo en un directorio.

![alt text](./images/image-78.png)

![alt text](./images/image-79.png)

![alt text](./images/image-80.png)

Podemos ver que los archivos se han exportado correctamente.

![alt text](./images/image-81.png)

**Do the same with Bulk Extractor and Autopsy.**

Para usar autopsy, crea una caso

![alt text](./images/image-82.png)

![alt text](./images/image-83.png)

![alt text](./images/image-84.png)

selecciona el disco y pulsa en "Next". Sigue hasta terminar

![alt text](./images/image-85.png)

![alt text](./images/image-86.png)

![alt text](./images/image-87.png)

Te muestra muchas más cosas, quizás un poco más lioso por la poca cantidad de archivos que tenemos, pero si el sistema fuese mucho más grnade, estaría bastante bien estructurado. Podemos ver más cosas que en photorec

![alt text](./images/image-88.png)

Por último,, para usar bulk starctor solo hay que abrirlo, saleecionar el disco y esanear, automa´ticamente podremos ver todos los archivos.

![alt text](./images/image-32.png)

**4. Import a multi-system virtual machine (XP–Ubuntu) from the provided OVA. Recover the mbr using the TestDisk tool**

As shown, the mbr was already broken

![alt text](./images/image-4.png)

To fix it, insert a WIN-XP .iso and boot

![alt text](./images/image-5.png)

There, click "R" to repair the system.

![alt text](./images/image-6.png)

Use the command

```cmd
FIXMBR
```

To fix the MBR. Teorically, it should be repaired.

![alt text](./images/image-7.png)

![alt text](./images/image-9.png)

However, after staritng the machine, it is still broken

![alt text](./images/image-10.png)

As shown, the table has been repaired, but it is still broken. 

![alt text](./images/image-11.png)

In kali, run testdisk

```bash
testdisk
```

Seleccionamos la opción create para que exista un registro de lo que estamos haciendo

![alt text](./images/image-14.png)

Seleccionamos el disco con el que vamos a trabaja

![alt text](./images/image-15.png)

Especificamos la tabla de particiones como tipo intel.

![alt text](./images/image-16.png)

Iniciamos un análisis del disco.

![alt text](./images/image-17.png)

Este sería el resultado de dicho análisis, que es lo que ocurre tado que hemos fulminado por
completo la tabla de particiones, así que faltan las marcas

![alt text](./images/image-18.png)

Ahora, seleccionaremos quick search para buscar las particiones perdidas.

![alt text](./images/image-19.png)

Estas serían las particiones que ha encontrado, que, en efecto, son las que tenemos en el
disco

![alt text](./images/image-20.png)

Comprobamos que todo es correcto, y seleccionamos write.

![alt text](./images/image-21.png)

Y con esto, ya lo tenemos todo arreglado.

![alt text](./images/image-22.png)



**5. Import a multi-system virtual machine (Windows 7–Debian) from the provided OVA. Corrupt the MBR on purpose and attempt to recover it using the Windows 7 installation disk.**

Primero, deberemos de iniciar el sistema, en el cual hemos adjuntado un disco duro MBR, con
un live de kali, importante que no sea en modo forense, pues necesitamos sobreescribir el
disco para destruir la tabla

![alt text](./images/image-23.png)

Una vez dentro, debemos de identificar el disco que debemos destruir.

![alt text](./images/image-25.png)

En mi caso, sería sda.
Usaremos dd para reescribir la tabla de particiones de MBR, la cual se encuentra en el primer
bloqu

![alt text](./images/image-26.png)

Y con esto ya hemos destruido la tabla de particiones del disco, pasemos a la reparaci

![alt text](./images/image-27.png)

niciamos el sistema desde una iso de windows 7 y accedemos al modo de reparación

![alt text](./images/image-28.png)

Accedemos al command prompt

![alt text](./images/image-29.png)

Ejecutamos el comando

```cmd
bootrec /fixmbr
```

![alt text](./images/image-30.png)

Reiniciamos, y ya hemos reparado el sistema, aunque solo el arranque de windows, para
reparar el arranque de linux deberíamos usar otras herramientas como grubrepair

![alt text](./images/image-31.png)