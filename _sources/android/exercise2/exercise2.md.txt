# Android forensics medium

## Professional Third-Party Tools

### Objectives

- Investigate the professional tools offered by different companies for Android forensic investigations.
- Study the functionality they provide.
- Evaluate and test forensic tools for mobile devices.

### Materials

- Avilla Forensics

### Tasks

Se pide: 

1.  Instala Avilla Forensics. Puedes descargarlo desde [aquí](https://onedrive.live.com/?redeem=aHR0cHM6Ly8xZHJ2Lm1zL3UvYy9jYWQwMDBkNmE5NmU1OWU0L0lRQ0pGR1l6MFl5YlNvMlBOWERfTkxkM0FYODdWUE9iQ3NuLUJ1YmVBV0EyQl9VP2U9WVE3OVY5&cid=CAD000D6A96E59E4&id=CAD000D6A96E59E4%21s336614898cd14a9b8d8f3570ff34b777&parId=CAD000D6A96E59E4%211704272&o=OneUp).

2.  Probar la funcionalidad que ofrece. Para ello deberás utilizar tu teléfono móvil o  tablet.  Ilustra  con capturas de pantalla y algún comentario las evidencias que te permiten obtener. 

Escribirmos nuestros datos personales para no perder la cadena de custodia

![alt text](./images/image.psd(27).png)

Le damos a "NEW CASE" para crear un nuevo caso

![alt text](./images/image.psd(28).png)

Extraemos un backuop de whatsapp usando apk downgrade, para ello tnemos que desactivar las protecciones del dispositivos y datle a "Test Application".

![alt text](./images/image.png)

Seleccionamos el paquete que queremos extraer, en este caso `com.whatsapp` y le damos a "Extract".

![alt text](./images/image-1.png)

Tendremos un backup completo de whatsapp, extendible a varias aplicaciones de mensajería más

![alt text](./images/image.psd(29).png)

3.  Supón que trabajas en el sector del peritaje informático. Le has comentado a 
tu jefe la dificultad que presentan los dispositivos móviles a la hora de realizar 
una  adquisición  de  evidencias  de  los  mismos.  Tu  jefe  te  ha  encargado  la 
tarea  de  que  compres  lo  necesario  para  resolver  las  dificultades  que 
encuentres.   Busca  información en Internet de qué software/materiales hay 
disponibles, y justifica cuales comprarías

TBD. Parafrasear esto, mirar mejores herramientas, mejorar la tabla, convertir al inglés. Hacer un buen cambio a esto.

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

## Feasibility of Android Forensic Analysis

In general, RAM memory analysis and persistent storage analysis are considered essential parts of digital forensic investigations.

After the advances achieved in Windows, Linux and macOS forensic analysis, researchers started investigating whether tools such as DD, LiME and Volatility could also be used for Android devices.

Many research papers focus on Android RAM analysis, especially on virtualized Android devices.

### Objectives

- Investigate the difficulties involved in Android forensic investigations.
- Study the feasibility of performing forensic analysis depending on device characteristics.

### Documentation

- [Practical Infeasibility of Android Smartphone Live Forensics](https://faui1-files.cs.fau.de/filepool/gruhn/thesis_waechter.pdf)

### Tasks

#### Ideal situation for a perfect Android forensic investigation

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

#### Real-world limitations and possible solutions

##### Rooting without data loss

Most rooting procedures require rebooting the device.

This destroys the RAM contents, which are essential for live forensic analysis.

Possible solutions include:

- Exploiting privilege escalation vulnerabilities
- Using temporary root exploits
- Leveraging vulnerabilities such as Rage Against The Cage

However, these methods are highly device-dependent.

##### Android security mechanisms

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

##### Hardware and software fragmentation

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

##### Technical and legal limitations

Tools such as Volatility may fail due to incompatibilities or unsupported memory formats.

Additionally, using non-standard rooting techniques could invalidate evidence in legal proceedings.

Because of this, investigators must:

- Fully document every action performed
- Use validated methodologies
- Understand every forensic tool used
- Preserve chain of custody at all times

## Chat Analysis

As part of a police investigation into a murder, three mobile phones belonging to members of a criminal gang involved in drug trafficking were seized. Although the mobile phones had only been in use for a short period of time and the criminals tried not to use many cloud services, they made some mistakes that resulted in the download of personal data from some of these services, providing analysts with important information for the case investigation. You will have to take on the role of a forensic analyst and analyze the obtained data to answer some questions related to the investigation. The three criminals had the following nicknames:

- Capo: Leader and criminal mastermind of the gang.
- Hitman: Veteran member of the gang responsible for the more “sensitive” matters.
- Mule: A young and reckless guy who recently joined the gang. He was found dead near a shopping center.

At the following [link](https://informatica.ieszaidinvergeles.org:5001/sharing/c7p8DyLrT), you will find a compressed file containing the data extracted from the mobile phones used by the criminals.

By analyzing the information available in the logical acquisitions and application downgrades, try to answer the following questions about the 3 criminals. Write a report providing screenshots to support your answers.

## Capo

**Capo had several WhatsApp conversations with Mule (Mulligan Two). In the first one, he says that he has to travel near Madrid to pick up a car. Where exactly does he have to pick it up?**

Navigate to "/Capo, Mulero y Matón/capo_maton_mulero_moviles/Capo" and check where the Whatsapp database is located:

```bash
find . -name msgstore.db
```

![alt text](./images/image-2.png)

Open the rute using sqlitebrowser

```bash
sqlitebrowser ./BackupADB_Capo/apps/com.whatsapp/databases/msgstore.db
```

Then, navigate to the "Execute SQL" section, write the following sql request and click on the play button to execute it.

```sql
select * from message
```

As shown above, all the message are shown in plain text. Analyze the conversation an check if there is useful data.

![alt text](./images/image-3.png)

As shown, the car is a Dacia, parked in the cementery near to "Cruz de la horca".

![alt text](./images/image-4.png)

Using google maps the location `Cruz de la Horca Av. Felipe II, 23, 28280 El Escorial, Madrid` can be obtained. This is the parking where the car was parked.

![alt text](./images/image-6.png)

![alt text](./images/image-5.png)

**On October 6 in the middle of the afternoon, Capo sent Mule a WhatsApp voice message scolding him about something. Recover the audio file and listen to the message. Why is he scolding him?**

Analyzing the same database than before, it can be seen that there is a message_type with id "2". This means that it is an audio.

![alt text](./images/image-7.png)


Vavigate to `/capo_maton_mulero_moviles/Capo/BackupADB_Capo/Shared/WhatsApp/Media/WhatsApp Voice Notes/202340` to find said audio and play it.

![alt text](./images/image-8.png)

The audio says literaly: "Eso es cosa de Mathew, haz tu trabajo y limitate a eso, ¿capiste?". Which translated to English is "TBD". Capo is anoyed because of Mule asking about something.

Investigating a lite more, it can be seen that Mule ask for the job: "Eeeeeeh, mola. Y va a ser muy heavy el recadito ?"

![alt text](./images/image-9.png)

**Based on the last series of WhatsApp messages available on Capo’s phone, who appears to have killed Mule?**

Mirando nuevamente la base de datos, se puede ver cómo después de hablar con mulero (2), habla con otra persona (3), pero todavía no sabemos quién es.

![alt text](./images/image-10.png)

Mirando un poco más los chats, podemos ver que antes o normalmente hablan por telegram, pero como no funciona, se pasan a whatsapp. Se puede ver en la conversación que la persona (3) es quien ha efectuado el asesinato:

- "Quién me vio? Como me enteré va a saber!! Si no había nadie cago en todo!!!!"

Así que está admitiendo que es él. Pero todavía no sabemos quién es (3).

![alt text](./images/image-11.png)

Para ello, nos vamos a sqlite otra vez y hacemos la siguiente búsqueda, viendo que el "_id" 3, tiene asignado un contacto de "jid_row_id" igual a 9

![alt text](./images/image-12.png)

Luego biscamos por ese jid 9 y miramos cual es el número de telefono de este.

![alt text](./images/image-13.png)

Con ello sacamos el número de teléfono `+34 672921162`

abrimos la base de datos donde se guardan los contactos de whatsapp y miramos quién es ese número de teléfono

```bash
sqlitebrowser ./BackupADB_Capo/apps/com.whatsapp/databases/wa.db
```

![alt text](./images/image-14.png)

con esto vemos que quien ha matado a la víctima, es decir (3), es Mathew.

## Mule:

**Mule took two photographs with his mobile phone camera at his birthday party on the beach. Could you determine on which beach the party took place?**

Para ver las fotos de su cámara, nos metemos en su directorio ("Mulero") y nos vamos al directorio de la cámara:

```bash
cd ./BackupADB/shared/0/DCIM/Camera/
```

![alt text](./images/image-15.png)

Las fotos relacionadas con una playa son las siguientes:

![alt text](./images/image-16.png)

![alt text](./images/image-17.png)

Sacamos los metadatos de las imagenes de la camara para sacar la posición donde han sido tomadas. Desde whatsapp no habría sido posible porque limpia los metadatos.

```bash
exiftool IMG_20231008_190256.jpg
```

![alt text](./images/image-18.png)

![alt text](./images/image-19.png)

Podemos ver que el móvil tenía activada la ubicación y que encima la metía como metadatos en las imágenes! Con ello, podemos sacar que la ubicación desde la que fueron tomadas fue `43°30'13.12"N, 8°19'10.68"W`

Tras buscarlo en google maps, podemos ver lo siguiente:

![alt text](./images/image-20.png)

![alt text](./images/image-21.png)

Las fotos fueron tomadas en `Praia do Outeiro`, en Ferrol.

**Mule was interested in investing in cryptocurrencies and visited some websites with information about them. Which pages did he visit?**

La base de datos que tenemos que buscar es places.sqlite, podemos mirar dónde está usando el siguiente comando:

```bash
find . -name places.sqlite
```

![alt text](./images/image-22.png)

Abrimos la ubicación del archivo usando sqlitebrowser nuevamente:

```bash
sqlitebrowser "./APK Downgrade/org.mozilla.firefox/apps/org.mozilla.firefox/f/places.sqlite"
```

Y sacamos la información de la tabla moz_places como se ve a continuación:

![alt text](./images/image-23.png)

Podemos ver que en algún momento Mulero entró en la página `https://www.novatostradingclub.com/criptomonedas/como-ganar-dinero-con-criptomonedas/`

## Hitman:

**On October 7, 2023, Hitman exchanged several messages with Capo on Telegram (Telegram user: Ernesto Capote) regarding a tip-off that had been received. In the third message of the day, Capo sent him the location of a street on the outskirts of Ourense. Can you recover the location from the Telegram messages and identify which street it is?**

Ahora, tendremos que cambiarnos al directorio de "Maton", posteriormente, podemos encontrar la base de datos de telegram con el siguiente comando:

```bash
find . -name cache4.db 
```

![alt text](./images/image-24.png)

Sacanddo la información de la tabla de users, podemos ver que Ernesto Capote tiene el uid `6614674280`. Esto será de utilidad en el siguiente paso

```bash
sqlitebrowser "./APK Downgrade/org.telegram.messenger/apps/org.telegram.messenger/files/cache4.db"
```

![alt text](./images/image-25.png)

Ahora si miramos la table de "messages_v2", podemos ver uno de los mensajes de uid `6614674280` que manda una dirección de google maps.

![alt text](./images/image-26.png)

Después de buscar la [dirección](https://maps.app.goo.gl/GTBT9atyWAoH8UJ19), podemos ver que es una casa de Ourense.

![alt text](./images/image-27.png)

![alt text](./images/image-28.png)

**In the last Telegram messages exchanged between Hitman and Capo, it becomes definitively clear who killed Mule. Who did it and when?**

Para poder entender bien qué pasó, hay que analizar muchos mensajes, esto es todo lo que se ha podido ver:

![alt text](./images/image-32.png)

"Oye, estuve con uno de los de Perillo. Están cabreados porque dicen que les faltan 100gr del material."

![alt text](./images/image-33.png)

"Se me dio por mirar las redes del nuevo y me encontré con esto..."

![alt text](./images/image-34.png)

es la siguiente foto:

![alt text](./images/image-36.png)

![alt text](./images/image-37.png)

"¿Le haces una visita?"

después de unos cuantos mensajes, se ve esto

![alt text](./images/image-38.png)

"Yo creo que la cosa está clara. Tenemos que deshacernos de él"

![alt text](./images/image-29.png)

"Trabajito listo. Ayer lo seguí y al salir del supermercado me Reuní con el."

![alt text](./images/image-30.png)

"Todo limpio, no es fácil encontrar nada"

![alt text](./images/image-31.png)

"Ése no vuelve a dar por culo."

Después de todo esto TBD traducir al ingles y parafrasear: Leyendo las conversaciones, podemos ver lo que ha ocurrido, Mulero tomo parte de un cargamento de droga para consumirlo en su cumpleaños, esto trajo problemas a Capo, Matón vio las imagenes del cumpleaños de Mulero, donde vio la droga faltante, tras interrogar a Mulero, tanto Matón como Capo conluyeron que, para recuperar la confianza de la organización criminal, debian de acabar con mulero.

**Now that we know the date of the murder, let’s look at the photos taken with Hitman’s phone that day to see if they provide any clue as to where it took place. Can you indicate the exact location?**

![alt text](./images/image-39.png)

En el directorio de la cámara de fotos de "Maton", podemos ver 2 imágenes de un sitio ese día:

![alt text](./images/image-40.png)

![alt text](./images/image-41.png)

Al igual que antes, sacamos los metadatos de la imagen para ver si podemos sacar la ubicación:

```bash
exiftool IMG_20231016_221751.jpg
```

![alt text](./images/image-42.png)

Podemos ver que las dotos han sido tomadas desde `43°30'21.45"N, 8°12'18.47"W`.

Si miramos en google maps, encontramos esto:

![alt text](./images/image-43.png)

![alt text](./images/image-44.png)
