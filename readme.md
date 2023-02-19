This simulates an itho service module interface.

The interface is an USB to serial device with a microcontroller that sends i2c command to itho products.

The serial protocol from PC (servictool) to servicemodule is:

- 0x10 0x16   "ping". Reply with 0x10 0x16.
- 0x10 0x02   start message
- 0x10 0x03   end message
- 0x10 0x10   literal byte 0x10

The servicetool simply sends the ping command on all open usb-serial devices "COMxx".
When a reply is recieved, it assumes the servicemodule is connected.

It then just send i2c commands back and forth.

Usage:
------

Install linked virtual ports using `com0com` and create linked ports (name must start with COM)

```
command> install PortName=COM20 PortName=COM21
       CNCA2 PortName=COM20
       CNCB2 PortName=COM21
ComDB: COM20 - logged as "in use"
ComDB: COM21 - logged as "in use"
```

Or use two FT232RL usb-serial devices connected as null modem (crossed TX/RX):
```
GND ---- GND
RX  ---- TX
TX  ---- RX
```
RTS/CTS handshaking is not used.
COM is 115200,8N1

Run `python itho.py` and start the Itho servicetool:

```
python itho.py
From servicetl: 10 16
To servicetool: 10 16 [2]
From servicetl: 10 02 00 80 90 E0 04 00 0C 10 03
#msgclass:  0x90e0
To servicetool: 10 02 80 82 90 E0 01 07 00 01 00 0D 4C 25 00 07 10 03 [18]
From servicetl: 10 02 82 80 90 E1 04 00 89 10 03
#msgclass:  0x90e1
To servicetool: 10 02 80 82 90 E1 01 03 10 10 10 10 10 10 59 10 03 [17]
From servicetl: 10 02 82 80 A4 10 04 13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28 00 0B 10 03
#msgclass:  0xa410_40
To servicetool: 10 02 80 82 A4 10 10 01 13 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 01 00 28 F0 1B 10 03 [31]
...
```
