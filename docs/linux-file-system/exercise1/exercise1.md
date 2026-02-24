# Exercise 1

## Statement

12 bloques x 512 bytes + 128 direcciones a bloque x 512 bytes + 128² indirecto a bloque doble x 512 bytes + 128³ indirecto a bloque triple x 512 bytes


12 bloques x 4 kb + 1024 direcciones a bloque x 4 kb + 1024² indirecto a bloque doble x 4 kb + 1024³ indirecto a bloque triple x 4 kb



mount datos.dd /media -o loop,offset=1048576

o

losetup -f -t datos.dd
ls /dev/loop0

mount /dev/loop0p3 /media
umount /media






fls /loop0p1













icat 690 --> no sale nada porque sus bytes ya han sido pisados por otro archivo
icat 12 --> se ha borrado también pero no han sido pisados