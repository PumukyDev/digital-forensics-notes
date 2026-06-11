# Forensic analysis with diferent Linux file systems.

## Objetivo:

- Aprender a acceder a las posibles evidencias contenidas en imágenes de disco generadas en sistemas informáticos que ejecutan sistemas operativos Linux.
- Utilización de herramientas de recuperación de archivos borrados: foremost, photorec y scalpel

## Materiales

- Distribución Linux Kali Linux.
- Herramientas propias del sistema operativo: mount, losetup, fdisk, etc.
- Herramientas forenses: Sleuthkit, foremost, scalpel y photorec.
- Información de Internet

Una de las tareas más habituales quehacer diario de un profesional forense informático es realizar imágenes forenses de discos duros (teniendo en cuenta todos los requisitos relativos a la cadena de custodia) para posteriormente realizar un análisis de los contenidos del mismo.

En esta situación, se hace imprescindible disponer de destrezas y habilidades para conocer las peculiaridades de los distintos sistemas de archivos que utilizan los SO Linux, para ser capaces de acceder a la información contenida en estas imágenes.

Se nos pueden presentar situaciones donde aparezcan configuraciones más sofisticadas, tipo LVM, ZFS o LUKS encrypted, que hagan más difícil el acceso a la información almacenada.

Para la realización de la práctica se requiere que se descarguen las siguientes imágenes:

- [Datos](https://drive.google.com/file/d/1eN9oT3m66BphGWj5T-eEdU4GOpory-xm/view), se trata de un dispositivo de disco normal (ext4) donde sería necesario montar las particiones que se identifiquen y aplicar en ellas herramientas para la recuperación de datos borrados (photorec, foremost y scalpel).
- [LVM](https://drive.google.com/file/d/1Zy35lShfEQ4zTsOFdax09p4N1I-ko9Y8/view), se trata de un disco que hace uso de volúmenes lógicos. Habrá que dar los pasos necesarios para “desenmascarar” los grupos de volúmenes, y volúmenes lógicos definidos para acceder a su información.
- [Cifrado](https://drive.google.com/file/d/12BHCF2zr9Pp9wHRLlvic28pvehmarE27/view), se trata de un disco cifrado (contraseña “usuario”) con la tecnología propia de Linux (LUKS). Sería necesario acceder a la información que contenga

## Solution

### Datos

Mount the image using the following commands. Note that the loop number may vary dapending if there are other images mounted. Start mounting the first loop (loopXp1):

```bash
sudo losetup -fP datos.dd
mkdir evidences
sudo mount -o ro /dev/loop1p1 evidences
```

![alt text](./images/image.png)

There is only one directory called "recup_dir.1", check the content of said directory:

![alt text](./images/image-2.png)

![alt text](./images/image-1.png)

It contains multiple files, umount the first loop and mount the second one.

```bash
sudo umount /dev/loop1p1
sudo mount -o ro /dev/loop1p2 evidences
```

![alt text](./images/image-3.png)

However, the loop cannot be mounted as it is part of the swap. Them, mount the third and last loop:

```bash
sudo mount -o ro /dev/loop1p3 evidences
```

![alt text](./images/image-4.png)

An empty lost+found directory is found.

Use photorec in order to recover files. Launch it and select the first partition:

![alt text](./images/image-5.png)

Select "Linux".

![alt text](./images/image-6.png)

Select "ext2/ext3".

![alt text](./images/image-7.png)

Select "Whole" to recover as much files as possible.

![alt text](./images/image-8.png)

As shown below, many files have been recovered.

![alt text](./images/image-10.png)

Repeat the same process for the third partition.

After performing that, many files have been recovered:

![alt text](./images/image-11.png)

### LVM

Mount the partition and verigy the file system type.

```bash
sudo losetup -fP lvm.dd
lsblk -f
```

![alt text](./images/image-12.png)

As shown, it is a LVM2 file system.

Activate LVM to see the logical partitions.

```bash
sudo vgscan
sudo vgchange -ay
lsblk
```

![alt text](./images/image-13.png)

Mount the partitions and ensure that the files can be shown perfectly:

```bash
sudo mount /dev/debian-vg/root evidences/root/
sudo mount /dev/debian-vg/home evidences/home/
```

![alt text](./images/image-14.png)

### Cifrado

Mount the disk and ensure that it is a encrypted disk:

```bash
sudo losetup -fP cifrado.dd
lsblk
```

![alt text](./images/image-15.png)

It is encrypted using LUKS as shown above.

More information about the disk can be extracted using the following command:

```bash
sudo cryptsetup luksDump /dev/loop0p1
```

![alt text](./images/image-16.png)

To decrypt the file, simply run the folliowing command and write the "usuario" password. Then, all the files will be correctly deencrypted.

```bash
sudo cryptsetup luksOpen /dev/loop0p1 decrypted
sudo mount /dev/mapper/decrypted evidences
```

![alt text](./images/image-17.png)