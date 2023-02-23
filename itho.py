import serial

COMPORT = 'COM21'

inbuf = []
outbuf = []

itho_commands = {
   'ping':      '10 16',
   'start':     '10 02',
   'end':       '10 03',
}

itho_commands_wpu = {
   # QueryDeviceType
   '0x90e0':    '80 82 90 E0 01 07 00 01 00 0D 4C 25 00 07',
   '0x90e1':    '80 82 90 E1 01 03 10 10 10 59', #fake serial with multple 10s to test connection
   # QueryStatusFormat
   '0xa400':    '80 82 A4 00 01 86 92 92 92 92 92 92 92 92 92 92 92 92 92 92 0C 0C 0C 0C 92 10 0C 00 00 00 00 00 0C 0C 0C 0C 0C 10 92 92 00 00 00 00 92 92 92 92 00 00 10 0C 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 12 00 00 20 00 00 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 00 20 20 20 20 0C 00 92 00 90 10 00 00 92 10 00 92 10 00 00 00 00 10 10 10 10 10 10 10 00 10 10 10 10 10 10 10 AD',
   # QueryStatus
   '0xa401':    '80 82 A4 01 01 D5 01 F4 04 53 09 8A 09 AA 0A 69 0A F6 0A 40 09 59 0A 36 09 DD 0A 8E 00 A5 00 00 00 00 00 00 00 00 FF E8 00 00 00 00 00 00 32 32 00 00 00 01 00 00 00 07 EB 07 9E 00 01 FF 00 09 78 0A D2 09 78 0A D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 F4 25 00 63 ED 2F 34 2D 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 0D 00 00 01 D0 00 00 01 5B 00 00 00 94 00 01 27 10 00 00 00 00 00 32 00 02 BC 00 96 00 03 C2 00 00 00 00 00 FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 85',
   # Settings
   '0xa410_0':  '80 82 A4 10 01 13 00 00 00 64 00 00 00 00 FF FF FF FF 00 00 00 01 10 00 F0 D5',
   '0xa410_1':  '80 82 A4 10 01 13 00 00 B8 49 00 00 00 00 FF FF FF FF 00 00 00 01 20 01 F0 27',
   '0xa410_f': '80 82 A4 10 01 13 00 00 00 03 00 00 00 00 00 00 00 03 00 00 00 01 00 0F F0 30', 
   '0xa410_28': '80 82 A4 10 01 13 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 01 00 28 F0 1B',
   # Counters
   '0xc210':   '80 82 C2 10 01 35 1A 0D 2E 0E 51 01 38 03 8B 00 00 02 69 01 40 0D 9B 22 2A 0A 84 0A 0B 03 51 02 F6 00 00 01 B1 01 5A 00 BA 00 0F 00 00 00 00 00 01 00 2E 00 23 00 0E 01 39 01 2B 50',
   # c220 flags?
   '0xc220':    '80 82 C2 20 01 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0B',
   # c340 manual operation
   '0xc030':    '80 82 C0 30 01 1F 01 00 00 92 01 C2 00 92 13 88 00 92 0F A0 00 92 01 F4 00 92 03 20 00 92 1B 58 00 92 0F A0 00 A8',
   'device': 'WPU 5G fw76 v37'
   }

itho_commands_autotemp = {
   # QueryDeviceType
   '0x90e0':    '80 82 90 E0 01 07 00 01 00 0F 2E 0A 00 3E',
   '0x90e1':    '80 82 90 E1 01 03 0B D3 50 5B', # real
   # QueryStatusFormat
   '0xa400':    ' 80 82 A4 00 01 77 00 00 00 00 00 00 92 92 00 12 92 92 00 12 92 92 00 12 92 92 00 12 92 92 00 12 92 92 00 12 92 92 00 12 92 92 00 12 92 92 00 12 92 92 00 12 92 92 00 12 92 92 00 12 0C 0C 0C 0C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 10 10 10 10 10 10 10 10 10 92 10 10 10 10 10 10 10 10 10 10 10 10 10 10 18',
   # QueryStatus
   '0xa401':    '80 82 A4 01 01 B4 03 02 00 00 00 00 07 D4 07 9E 00 00 00 07 AB 07 6C 00 00 00 07 AD 07 6C 00 00 00 07 F7 07 6C 00 00 00 07 DE 07 6C 00 00 00 07 F3 07 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 64 64 64 64 00 00 00 00 00 00 00 00 64 64 64 64 64 64 64 64 64 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 0F 01 FF 00 00 01 F4 03 15 00 00 00 ED 00 EC 00 56 00 3A 00 C9 00 BD 00 00 00 00 00 00 00 00 00 00 00 00 6D',
   # Settings
   '0xa410_32':    '80 82 A4 10 01 13 00 00 00 0F 00 00 00 01 00 00 00 1E 00 00 00 01 00 32 4F 86',
   # man op
   '0xc030_0': '80 82 C0 30 01 27 00 00 00 00 0F 00 00 00 00 00 00 00 03 00 00 00 00 00 0C 00 00 00 00 00 10 00 00 00 00 00 60 00 00 00 00 00 80 00 00 D8', 
   '0xc030_1': '80 82 C0 30 01 09 01 00 00 00 0F 01 FF 00 00 F4',
   '0xc030_33': '80 82 C0 30 01 27 33 00 00 00 00 00 0B D4 68 00 00 00 54 81 88 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 54 81 88 B2',
   '0xc030_36': '80 82 C0 30 01 AB 36 00 00 54 81 88 03 0F 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 54 A9 AC 03 03 00 03 54 A9 58 04 0C 00 03 54 A9 CC 05 10 00 03 54 AA 0E 06 60 00 03 54 A9 09 07 80 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8',
   'device': 'Autotemp fw46 v10'
   }

# Choose device
itho_commands.update(itho_commands_wpu)
#itho_commands.update(itho_commands_autotemp)


def pretty_list(l):
    # [b'\x80', b'\x82', ] => "80 82 ..." 
    return ' '.join('{:02X}'.format(ord(rawbyte)) for rawbyte in l)


def get_command(cmd):
    command = bytearray.fromhex(itho_commands.get(cmd, ''))
    if len(command) == 2:
        # skip start, end
        return command
    # 0x10 is a control character. A literal value 0x10 must be sent as "0x10 0x10"
    out = []
    for b in command:
        if b == 0x10:
            out.append(b)
            out.append(0x10)
        else:
            out.append(b)
    return out


def add_checksum(l):
    """checksum is sum of all bytes, mod 256 (uint8_t) and negated"""
    chk = 256 - sum(l[:-1]) % 256
    l[-1] = chk
    return l 
#print([hex(x) for x in add_checksum([int(x,16) for x in itho_commands['0x90e1'].split()])])
#exit()


def send_cmd(cmd):
    command = get_command(cmd)
    outbuf.extend([val.to_bytes(1, 'big') for val in command])


def process_incomming_command(x):
    # is start of command
    if x[0] != b'\x10' or x[1] != b'\x02' or x[3] != b'\x80':
        print(x)
        print("#Malformed command")
        return

    msgclass = hex(ord(x[4])*256+ord(x[5]))
    # append index to msgclass
    if msgclass == "0xa410":
        idx = ord(x[25])
        msgclass += "_"+hex(idx)[2:]
    if msgclass == "0xc030":
        idx = ord(x[8])
        msgclass += "_"+hex(idx)[2:]
    print('#msgclass: ', msgclass)
    if not get_command(msgclass):
        print('Unknown: skipping.')
        return
    
    # send reply
    send_cmd('start')
    send_cmd(msgclass)
    send_cmd('end')

print("Simulating: ", itho_commands['device'])
ser = serial.Serial(COMPORT, 115200, timeout=1)
byte_10_recieved = False
while True:
    recv = ser.read()
    if recv == b'':
        continue
    inbuf.append(recv)

    if byte_10_recieved:
        # last byte was 0x10
        byte_10_recieved = False
        if recv == b'\x16':
            #ping!
            print(f'From servicetl: {pretty_list(inbuf)}')
            inbuf = []
            send_cmd('ping')
        elif recv == b'\x02':
            #print('new incoming command!')
            pass
        elif recv == b'\x03':
            print(f'From servicetl: {pretty_list(inbuf)}')
            process_incomming_command(inbuf)
            inbuf = []
        elif recv == b'\x10':  
            # literal byte 0x10
            inbuf.pop()

    if recv == b'\x10': # new command
        byte_10_recieved = True   

    if outbuf:
        print(f'To servicetool: {pretty_list(outbuf)} [{len(outbuf)}]')
        for rawbyte in outbuf:
            ser.write(rawbyte)            
        outbuf = []
