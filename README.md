USBkey Linux PAM with Littlewire and eeprom shield
=============

This PAM module uses littlewire library

Steps to use this module:
- Go to USBKeygen
- Compile it using "make" command.
- Insert littleWire usb tool with eeprom shield on it.
- Get root access (su)
- Run usbkeygen as root with a 32-byte key as parameter, you can try to generate 32byte random string from http://strongpasswordgenerator.com/
- So commandline will be: ./usbkeygen r6B4915kO41G0603DL4H91s116b8LE5T

Above steps, will encrypt a fixed string using given key, store it in system and write the key in eeprom.

Now go to PAM folder.
- Compile it using "make" command.
- Then install it using "make install". This should put pam_usbkey.so into /lib/security or /lib/security64 or other location depend linux distro you're using, googling it for your distro where pam module .so location.
- Now edit PAM file you can to use pam_usbkey and add some rule like "auth required pam_usbkey.so"
In my case, I use it in my Debian system with GDM desktop environment, so I have "auth required pam_usbkey.so" in my /etc/pam.d/gdm-password

Now if you logout and try to login, even if you enter correct username/password, if you don't put littlewire with eeprom shield, you shouldn't be able to login.

For more info: http://www.codeandsec.com/Linux-RFID-Pluggable-Authentication-Modules
