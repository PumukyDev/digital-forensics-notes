# Evidence in Web Browsers

Browser forensics analysis is a large and independent area of specialization.

Web browsers are used on mobile devices, tablets, netbooks, desktop computers, etc., and they are often used not only to browse the web, but also to navigate through the device’s file system. The web browser cache may contain images, videos, documents, executable files, and downloaded scripts. Web browsers may also store data entered into forms, such as search queries, logins and passwords for webmail accounts, social networks, other websites, and financial information (for example, credit card numbers). Bookmarks and search history can give investigators insight into the interests of the device owner.

Browser forensics analysis is mainly important in incident response to understand how an attack on a computer or a computer network began and to identify the source of the security compromise.

The main sources of malware, spyware, and adware are emails (including webmail), social networks, and other compromised websites. Typically, users access all these sources (webmail, social networks, websites) through web browsers.

One of the most well-known web browsers is Internet Explorer. This browser is a component of the Windows operating system and is often used as the default web browser. In Windows 10, Microsoft replaced Internet Explorer with Microsoft EDGE. Microsoft EDGE is a web browser that includes new features. Microsoft plans to replace Internet Explorer with Microsoft EDGE on all devices, including Android and iOS mobile devices. Internet Explorer and Microsoft EDGE can operate in InPrivate mode, without storing information about web resources visited by the user.

Another popular web browser is Google Chrome. It has the following characteristics:

- Integration with Google services.
- Synchronization of user passwords across devices.
- Ability to use extensions and add-ons.
- Fast operation.
- Collection of user data.
- High memory consumption.
- Google Chrome can operate in Incognito mode, which prevents the browser from permanently storing history information, cookies, site data, or form entries.

Third-party developers have created a large number of web browsers based on the Chrome Engine, such as: 360 Extreme Explorer, Avast SafeZone, Chromium, Comodo Dragon, CoolNovo, Cốc Cốc, Epic Browser, Flock, Vivaldi, Rockmelt, Sleipnir, SRWare Iron, Titan Browser, Torch Browser, Yandex.Browser, Opera, Orbitum, Breach, Nihrome, Perk, QIP Surf, Baidu Spark, Uran, Chromodo, Sputnik, Amigo, etc.

All these browsers have functionality similar to Google Chrome and produce web browser artifacts similar to those of Google Chrome. These browsers are compatible with most Google Chrome extensions and add-ons.

One of the most well-known web browsers based on the Google Chrome engine is Opera. Opera was the first to introduce features that were later adopted by other web browsers, such as speed dial, pop-up blocking, reopening recently closed pages, private browsing, and tabbed browsing. In addition, Opera includes a free Virtual Private Network (VPN) service that allows users to browse the web anonymously.

Firefox is a fairly popular web browser, and its artifacts can be found on devices under investigation. This web browser has the following characteristics:

- More secure (compared to other browsers).
- Advanced private browsing mode, which disables location tracking and user advertising.
- Its own extensions ecosystem.

Gecko is a browser engine developed by Mozilla. It is used in the Firefox browser, the Thunderbird email client, and many other projects.

Based on Gecko, third-party developers have created several web browsers, including: Firefox, Waterfox, Cyberfox, SeaMonkey, Netscape Navigator, CometBird, BlackHawk, IceCat, IceDragon, Pale Moon, Flock, K-Meleon, Galeon, FlashFox, Orfox, Vega.

Some web browser data is encrypted (for example, website passwords). Internet Explorer and Microsoft EDGE use the Data Protection Application Programming Interface (DPAPI). The DPAPI mechanism appeared in Windows 2000 and is used to protect stored passwords and confidential information on the computer. This mechanism includes data encryption and decryption functions and uses RAM.

A user password is required to decrypt encrypted data. If the password is registered in the account using a username and password, the operating system uses the password hash to decrypt the encrypted data.

As a general rule, data encryption is performed using the SHA1 algorithm; however, in some cases, data is encrypted using a less cryptographically secure algorithm.

A forensic examiner may often face the following difficulties when analyzing web browsers:

- Many browsers, large amounts of data.
- Different types of data.
- Encryption used to protect user data.
- User use of private mode (or incognito mode), in which the examined computer may not contain web browser artifacts.

Of course, each web browser leaves its own individual artifacts on the operating system. The types of web browser artifacts may vary depending on the browser version. Typically, when investigating web browser artifacts, the following types of artifacts can be extracted:

- Browsing history
- Files in the cache directory
- Cookies
- Typed URLs
- Sessions
- Most visited sites
- Screenshots
- Form values (searches, autocomplete)
- Downloaded files (Downloads)
- Bookmarks

(Source: *An Overview of Web Browser Forensics | Digital Forensics | Computer Forensics | Blog*)

## Main Objectives of the Practice

- Identify where the evidence generated by web browsers is located and learn how to analyze it using various tools.

## Software to Be Used

A. File Explorer  
B. Various tools provided by NirSoft

## Practice Description

The practice consists of extracting all the evidence mentioned above in the introduction (history, downloads, cookies, cache, sessions, and form data).

## Tasks Required

1. Use the operating system of your own computer and/or a virtual machine where the most common browsers are installed: Firefox, Chrome, and Internet Explorer.
2. Investigate the directory paths where each browser stores its evidence.
3. Download and test the different tools offered by NirSoft to analyze and process the evidence obtained in section 2.
