# Android and IOS forensics advanced

Esta práctica, en esencia, simula un escenario real en el que un analista forense debe  extraer,  preservar  y  examinar  evidencias  digitales  de  un  dispositivo  móvil, integrando  tanto  técnicas  de  volcado  físico  como  análisis  de  los  artefactos generados por diversas aplicaciones instaladas y configuradas en el dispositivo.

## Forense Android Manual

Este escenario se centra en el examen de un dispositivo Android 11, basado en un Google Pixel 3, que ha sido sometido a un proceso controlado de generación de imagen forense. A continuación, se describen los aspectos más relevantes:

### Detalles del sistema y versión de Android:

El dispositivo opera con Android 11, utilizando una imagen stock proporcionada por Google (Build: RP1A.200720.009, Patch Level: 5 de septiembre de 2020).

- Make: Google Pixel 3
- Model: G013A
- Storage: 64 GB
- RAM: 4GB
- Carrier: Google Fi
- Phone Number: 919-579-4674
- Serial: 8CEX1N716
- Wi-Fi MAC: 7c:d9:5c:ac:a2:cf
- BT MAC: 7c:d9:5c:ac:a2:ce

### Proceso de generación de la imagen forense

El  procedimiento  inicia  con  el  restablecimiento  a  valores  de  fábrica mediante el flasheo  de  una  imagen  stock.  Posteriormente,  se  realizan  los  siguientes  pasos críticos:

- Configuración del dispositivo: Se añade una cuenta de Google Fi para habilitar el servicio celular.
- Obtención de acceso privilegiado: Se desbloquea el bootloader y se instala Magisk, permitiendo el acceso root necesario para extraer información protegida.
- Población de datos: Se instalan 46 aplicaciones no nativas (junto con las aplicaciones stock) desde Google Play, las cuales son pobladas con datos de usuario mediante sus funcionalidades específicas.
- Extracción de datos: Se ha realizado una extracción lógica del contenido dela memoria del teléfono usando el software “Magnet Acquire”; descargala [aquí](https://drive.google.com/file/d/1AiMDFlSRHuEeAxw4mgzlISnflB_DB-D9/view). La salida del log del proceso de extracción se encuentra [aquí](https://drive.google.com/drive/folders/16ws1Bk0i03O58X8z2oRJNMYvRQKDZlFo).

### Finalidad y herramientas de análisis

El objetivo principal de esta práctica es identificar y analizar los artefactos forenses contenidos en el dispositivo Android de forma manual, permitiendo la reconstrucción de  eventos  y  actividades  del  usuario.  Para  lograrlo,  se  recomienda  el  uso  de herramientas como:

- FTK Imager: Para la obtención de artefactos forenses de Android.
- Otras herramientas complementarias: DB Browser (sqlite) para acceder directamente al contenido de los artefactos cuando se trata de bases de datos sqlite. Autopsy o Mobiledit que facilitan el análisis detallado de 
registros, metadatos y datos residuales en las aplicaciones y en el sistema. Notepad++ u otros editores para manejar textos planos o codificaciones hexadecimales, base64, xml, etc. Se pide extraer y analizar los artefactos que permitan obtener información sobre

### Analysis

First, uncompress the file by performing the following command:

```bash
tar -xvf "Android 11 - Pixel 3 - Data.tar"
```

1.  Propiedades  del  dispositivo:  Android  ID,  Bluetooth  name,  Bluetooth address

`data/system/users/%USERNUMBER%/settings_secure.xml`

![alt text](./images/image.png)

`data/system/users/%USERNUMBER%/companion_device_manager_associations.xml`

![alt text](./images/image-1.png)

`/data/misc/bluedroid/bt_config.conf`

![alt text](./images/image-2.png)

2.  Lista  de  contactos  del  teléfono

`sqlitebrowser data/data/com.android.providers.contacts/databases/contacts2.db`

```sql
SELECT n.data1 AS nombre,
       p.data1 AS telefono
FROM data n
JOIN mimetypes mn ON n.mimetype_id = mn._id
JOIN data p ON n.raw_contact_id = p.raw_contact_id
JOIN mimetypes mp ON p.mimetype_id = mp._id
WHERE mn.mimetype = 'vnd.android.cursor.item/name'
  AND mp.mimetype = 'vnd.android.cursor.item/phone_v2';
```

![alt text](./images/image-3.png)

3.  Llamadas  entrantes  y  salientes

`sqlitebrowser data/data/com.android.providers.contacts/databases/calllog.db`

![alt text](./images/image-4.png)

4.  Mensajes SMS

`sqlitebrowser data/data/com.android.providers.telephony/databases/mmssms.db`

![alt text](./images/image-5.png)

5.  Puntos  de  acceso  Wifi  utilizados

data/misc/apexdata/com.android.wifi/WifiConfigStore.xml

![alt text](./images/image-6.png)

6.  Dispositivos  Bluetooth  a  los  que  se  ha  emparejado 

data/misc/bluedroid/bt_config.conf

![alt text](./images/image-7.png)

7.  Fotos,  descargas,  documentos   y  material  multimedia  de  whatsapp, signal, telegram, kik y Snapchat.

**Whatsapp**

`thunar data/media/0/WhatsApp/Media/WhatsApp Images/`

![alt text](./images/image-8.png)

**Signal**

`thunar data/media/0/Signal/`

![alt text](./images/image-9.png)


**Telegram**

`thunar ~/android-postmortem/data/media/0/Telegram/Telegram\ Images/`

![alt text](./images/image-10.png)


**Kik**

`thunar ~/android-postmortem/data/media/0/Kik/`

![alt text](./images/image-11.png)

**Snapchat**

`thunar ~/android-postmortem/data/media/0/Snapchat/`

![alt text](./images/image-12.png)

8.  Aplicaciones  instaladas  en  el  dispositivo 

`sqlitebrowser data/user/0/com.android.vending/databases/localappstate.db`

![alt text](./images/image-13.png)

9.  Búsquedas  realizadas  en  Play  Store 

`sqlitebrowser data/user/0/com.android.vending/databases/suggestions.db`

![alt text](./images/image-14.png)

10. Cuentas  de  usuario  registradas.

`sqlitebrowser data/system_ce/0/accounts_ce.db`

![alt text](./images/image-15.png)

`sqlitebrowser data/system_de/0/accounts_de.db`

![alt text](./images/image-16.png)

`sqlitebrowser data/system_de/10/accounts_de.db`

![alt text](./images/image-17.png)

`data/data/com.android.vending/shared_prefs/lastAccount.xml`

![alt text](./images/image-18.png)

11. Estadísticas  de  uso  de  aplicaciones

`data/user/0/com.google.android.apps.turbo/shared_prefs/app_usage_stats.xml`

![alt text](./images/image-19.png)

12. Eventos de uso de aplicaciones y dispositivos

`sqlitebrowser data/data/com.google.android.apps.wellbeing/databases/app_usage`

![alt text](./images/image-20.png)

13. Actividades de aplicaciones y dispositivos

`sqlitebrowser data/data/com.google.android.as/databases/reflection_gel_events.db`

TBD, en este caso no existe, explicar qué ser ddebería ver. poner la explicación resumida de Julio: Esta almacena información utilizada por los Servicios de Personalización del Dispositivo (DPS), que recopilan diversas estadísticas de uso para predecir y sugerir aplicaciones y contenido al usuario. Una característica destacada de esta base de datos es que puede conservar registros de aplicaciones que fueron eliminadas del dispositivo. Los artefactos de reflection_gel_events.db pueden ayudar a establecer una línea de tiempo detallada de eventos en el dispositivo durante un periodo de tiempo más amplio que el que registran los datos de Digital Wellbeing. Aunque en este caso no encontramos esta base de datos en el dispositivo.

![alt text](./images/image-21.png)

14. Mensajes  intercambiados  en  Facebook

`sqlitebrowser data/user/0/com.facebook.orca/databases/threads_db2`

![alt text](./images/image-22.png)

15. Mensajes de Instagram.

`sqlitebrowser data/user/0/com.instagram.android/databases/direct.db`

![alt text](./images/image-23.png)

16. Mensajes de Twitter.

`sqlitebrowser data/data/com.twitter.android/databases/1068228364824178689-61.db`

![alt text](./images/image-24.png)

17. Mensajes de Telegram.

`sqlitebrowser data/user/0/org.telegram.messenger/files/cache4.db`

![alt text](./images/image-25.png)

18. Mensajes de Tiktok.

`sqlitebrowser data/user/0/com.zhiliaoapp.musically/databases/6787436503258760198_im.db`

![alt text](./images/image-26.png)

19. Mensajes de SnapChat.

`sqlitebrowser data/user/0/com.snapchat.android/databases/main.db`

![alt text](./images/image-27.png)

20. Mensajes de Signal.

- /data/user/0/org.thoughtcrime.securesms/databases/signal.db
- /data/misc/keystore/user_0/10244_USRSKEY_SignalSecret
- /data/user/0/org.thoughtcrime.securesms\shared_prefs\org.thoughtcrime.securesms_preferences.xml

están cifrados y no se pueden descrifrar. Julio tiene esto:

La base de datos de Signal se encuentra encriptada por lo que debemos seguir el siguiente proceso para poder acceder al contenido.

Signal utiliza el método de cifrado AES en modo GCM para cifrar su base de datos mediante SQLCipher. Primero, se obtiene la clave SQLCipher, y luego se utiliza una clave AES-GCM derivada de USERKEY + IV para cifrar la base de datos. Estos valores se almacenan en el archivo org.thoughtcrime.securesms_preferences.xml. Para descifrar la base de datos, es necesario invertir el proceso para obtener la clave SQLCipher.

Aunque actualmente no he conseguido acceder a la base de datos de Signal.

![alt text](./images/image-28.png)

21. Mensajes y nombre de ficheros adjuntos intercambiado con ProtonMail

`sqlitebrowser data/user/0/ch.protonmail.android/databases/dGhpc2lzZGZpckBwcm90b25tYWlsLmNvbQ=\=-MessagesDatabase.db`

![alt text](./images/image-29.png)

22. Mensajes  de  Whatsapp

`sqlitebrowser data/data/com.whatsapp/databases/msgstore.db`

![alt text](./images/image-30.png)

23. Websites visitados con Chrome

`sqlitebrowser data/data/com.android.chrome/app_chrome/Default/History`

![alt text](./images/image-31.png)

24. Websites visitados con Firefox (places.sqlite)

`sqlitebrowser data/data/org.mozilla.firefox/files/places.sqlite`

![alt text](./images/image-32.png)

25. Mensajes de Gmail

`sqlitebrowser data/data/com.google.android.gm/databases/bigTopDataDB.-1294433372`

![alt text](./images/image-33.png)

`thunar data/data/com.google.android.gm/files/downloads/5761130b154b62887de36515992b44d3/attachments/d_0_0_e5ba0594_aab96d52_b09148ce_17639171_ec181ca8`

![alt text](./images/image-34.png)

26. Navegaciones realizadas con Google Maps

`sqlitebrowser data/data/com.google.android.apps.maps/databases/gmm_sync.db`

![alt text](./images/image-35.png)

## Forense iOS Automatizada

### Objetivo

Realizar un análisis forense de un dispositivo iPhone SE, extrayendo e interpretando los artefactos digitales relevantes mediante la herramienta iLEAPP, a partir de un backup lógico sin jailbreak (checkra1n utility).

### Detalles del Dispositivo

- Make iPhone SE
- Model A1662 (Rose Gold)
- Order Number MLXL2LL/2
- RAM 2 GB
- Storage 64 GB
- Carrier Google Fi
- Phone Number 919-579-4674
- Serial DX3T126VH2XV
- Wi-Fi MAC A0:D7:95:79:DD:A1
- BT MAC A0:D7:95:79:DD:A2
- iOS Version 13.4.1 (Build 17E262)
- Passcode 0731

### Adquisición Forense:

1.  Método de adquisición: Backup lógico vía iTunes. Pulsa [aquí](https://drive.google.com/file/d/1npTXJTNtt2gmMhJ8fAw0FFuq7XBsjcwf/view) para obtener el fichero de backup

- Formato obtenido: Archivo .zip.
- Contraseña del backup cifrado: mypassword123
- No se realizó jailbreak al dispositivo.

2.  Método de adquisición: Magnet Acquire y volcado completo del dispositivo. Pulsa [aquí](https://drive.google.com/file/d/1j7fUmxzmk_R2fWP9v1XFPGfEef3wUAXd/view) para obtener la imagen del dispositivo. Usarás esta imagen en el segundo informe que se generará más adelante.

### Herramientas a Utilizar: 

**iLEAPP (iOS Logs Events And Preferences Parser)**

- Desarrollada por Alexis Brignoni y Yogesh Khatri. 
- Permite analizar respaldos de iTunes/iOS para extraer artefactos forenses.

**Itunes Backup Explorer**

- Permite transformar decodificar los backups de iOS


## Pasos a Seguir

1. Preparación del Entorno

- Utiliza un equipo con sistema operativo Windows/Linux/macOS.
- Descarga e instala iLEAPP desde el [repositorio oficial](https://github.com/abrignoni/iLEAPP):

```bash
wget wget https://github.com/abrignoni/iLEAPP/releases/download/v2.5.0/ileappGUI-v2.5.0-Linux_x86_64.AppImage
chmod +x ileappGUI-v2.5.0-Linux_x86_64.AppImage
./ileappGUI-v2.5.0-Linux_x86_64.AppImage
```

![alt text](./images/image-38.png)

2. Descomprimir el Backup

- Descomprime el archivo .zip del backup en una carpeta local.
- Decodifica la carpeta con el backup descomprimido usando la aplicacion “Itunes Backup Explorer”. Si se solicita, introduce la contraseña: mypassword123.

```bash
unzip c623fbd7e91b041e07a68f8523f53a35973e475d.zip
mkdir input output
wget https://github.com/MaxiHuHe04/iTunes-Backup-Explorer/releases/download/v1.7/itunes-backup-explorer_1.7_debian_x64.deb
sudo apt install ./itunes-backup-explorer_1.7_debian_x64.deb
```

![alt text](./images/image-39.png)

![alt text](./images/image-40.png)

![alt text](./images/image-41.png)

![alt text](./images/image-42.png)

![alt text](./images/image-43.png)

![alt text](./images/image-44.png)

![alt text](./images/image-45.png)

![alt text](./images/image-46.png)

3. Ejecutar iLEAPP

- Abre iLEAPP y selecciona como entrada la carpeta descomprimida y decodificada del backup. 
- Define una carpeta de salida para el informe.
- Inicia el análisis automático.

![alt text](./images/image-47.png)

![alt text](./images/image-48.png)

![alt text](./images/image-49.png)

4. Revisión del Informe

- Al finalizar, iLEAPP generará un informe HTML con múltiples pestañas.
- Revisa especialmente los siguientes artefactos:

**Safari: Historial de navegación.**

![alt text](./images/image-50.png)

**Location Services: Registros de localización GPS.**

Not found

**iMessage / SMS: Conversaciones.**

![alt text](./images/image-51.png)

**Installed Apps: Lista de aplicaciones.**

![alt text](./images/image-52.png)

![alt text](./images/image-53.png)

**Battery Usage: Actividad de apps.**

Not found

**Network Connections: Conexiones Wi-Fi conocidas.**

![alt text](./images/image-54.png)

**Lockdown / Device Info: Información del dispositivo**

![alt text](./images/image-55.png)

![alt text](./images/image-56.png)

5. Realiza un Segundo Informe con iLEAPP

- Usaremos la imagen del dispositivo completa, sin necesidad de descomprimir, con la aplicación iLEAPP. 
- Compara este informe con el anterior y verifica que es mucho más completo.

![alt text](./images/image-58.png)

**Safari: Historial de navegación.**

![alt text](./images/image-59.png)

**Location Services: Registros de localización GPS.**

![alt text](./images/image-63.png)

**iMessage / SMS: Conversaciones.**

![alt text](./images/image-60.png)

**Installed Apps: Lista de aplicaciones.**

![alt text](./images/image-61.png)

**Battery Usage: Actividad de apps.**

![alt text](./images/image-62.png)

**Network Connections: Conexiones Wi-Fi conocidas.**

![alt text](./images/image-64.png)

**Lockdown / Device Info: Información del dispositivo**

![alt text](./images/image-66.png)

![alt text](./images/image-65.png)

