(this page has been restored after deletion, please don't delete again)

# 1. Encryption scheme used in RTMFP #

## 1.1. Goal ##

'''From this plain request'''
```
0B 82 60 30 00 53 42 41 0A 72 74 6D 66 70 3A 2F 
2F 73 74 72 61 74 75 73 2E 61 64 6F 62 65 2E 63 
6F 6D 2F 39 35 36 64 30 30 39 35 62 63 39 34 31 
36 32 34 62 32 30 64 62 37 37 66 2D 37 36 33 61 
63 34 66 34 36 32 38 39 2F 7D 1C 42 FB 55 1B B4 
E7 8F 34 B6 C4 A0 11 CC BD
```

'''to this encrypted request'''
```
95 BD 4A 12 D9 7A E8 AF 4C C7 A2 BD 26 39 77 19 
D7 42 31 A2 31 BB 05 7C 0D E4 03 2A 4E FA C3 9B 
11 D8 B8 98 3F D6 AA B7 A1 98 F2 5F 75 ED E2 41 
E5 20 0B 30 FC 5D 46 33 05 F5 8B 93 A9 BE 90 2D 
8F 07 72 87 20 B1 5E 15 08 95 83 A9 C1 C9 9A 6A 
EC 93 04 FF 2B 66 A5 25 6D E7 06 48 D4 38 01 6B 
8A C6 67 8B
```

## 1.2. Compute the length of the padding bytes ##
```
paddingBytesLength=(0xffffffff-plainRequestLength-0x01)&0x0F
```
Eg:
```
paddingBytesLength=(0xffffffff-0x59-0x01)&0x0f=0x05
```

## 1.3. Padd the plain request with paddingBytesLength of value 0xff at the end ##
Eg:
```
0B 82 60 30 00 53 42 41 0A 72 74 6D 66 70 3A 2F 
2F 73 74 72 61 74 75 73 2E 61 64 6F 62 65 2E 63 
6F 6D 2F 39 35 36 64 30 30 39 35 62 63 39 34 31 
36 32 34 62 32 30 64 62 37 37 66 2D 37 36 33 61 
63 34 66 34 36 32 38 39 2F 7D 1C 42 FB 55 1B B4 
E7 8F 34 B6 C4 A0 11 CC BD FF FF FF FF FF
```

## 1.4. Compute the CRC and add it at the beginning of the request ##
```
r1=sum of all bytes 16 bit aligned
r2=(r1>>16)+(r1&0x0000ffff)
r3=r2>>16
r4=r2+r3
r5=~r4
r6=r5&0x0000ffff
```
Eg:
```
r1=0x0B82+0x6030+...+0xBDFF+0xFFFF+0xFFFF=0x000FF5A3
r2=0x0000000F+0x0000F5A3=0x0000F5B2
r3=0x00000000
r4=0x0000F5B2+0x00000000=0x0000F5B2
r5=0xFFFF0A4D
r6=0x0A4D
```
The request becomes
```
0A 4D 0B 82 60 30 00 53 42 41 0A 72 74 6D 66 70 
3A 2F 2F 73 74 72 61 74 75 73 2E 61 64 6F 62 65 
2E 63 6F 6D 2F 39 35 36 64 30 30 39 35 62 63 39 
34 31 36 32 34 62 32 30 64 62 37 37 66 2D 37 36 
33 61 63 34 66 34 36 32 38 39 2F 7D 1C 42 FB 55 
1B B4 E7 8F 34 B6 C4 A0 11 CC BD FF FF FF FF FF
```

## 1.5. Encrypt the resulted request ##
```
#!sh
openssl aes-128-cbc -in plain.bin -out encrypted.bin -nosalt -iv 00000000000000000000000000000000 -K 41646F62652053797374656D73203032
```
  * ''plain.bin'' - the file containing the binary representation resulted at step 4
  * ''encrypted.bin'' - the file containing the binary representation of the encrypted request
  * ''41646F62652053797374656D73203032'' - hexadecimal representation of ''Adobe Systems 02''
Result output
```
D9 7A E8 AF 4C C7 A2 BD 26 39 77 19 D7 42 31 A2
31 BB 05 7C 0D E4 03 2A 4E FA C3 9B 11 D8 B8 98
3F D6 AA B7 A1 98 F2 5F 75 ED E2 41 E5 20 0B 30
FC 5D 46 33 05 F5 8B 93 A9 BE 90 2D 8F 07 72 87
20 B1 5E 15 08 95 83 A9 C1 C9 9A 6A EC 93 04 FF
2B 66 A5 25 6D E7 06 48 D4 38 01 6B 8A C6 67 8B
XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX
```

## 1.6. Discard the last line (16 bytes) ##

## 1.7. Add another 4 bytes of CRC at the beginning of the resulted request at step 6 ##
```
CRC=DWORD1 xor DWORD2
```
Eg:
```
CRC=0xD97AE8AF xor 0x4CC7A2BD = 0x95BD4A12
```
Final request
```
95 BD 4A 12 D9 7A E8 AF 4C C7 A2 BD 26 39 77 19 
D7 42 31 A2 31 BB 05 7C 0D E4 03 2A 4E FA C3 9B 
11 D8 B8 98 3F D6 AA B7 A1 98 F2 5F 75 ED E2 41 
E5 20 0B 30 FC 5D 46 33 05 F5 8B 93 A9 BE 90 2D 
8F 07 72 87 20 B1 5E 15 08 95 83 A9 C1 C9 9A 6A 
EC 93 04 FF 2B 66 A5 25 6D E7 06 48 D4 38 01 6B
8A C6 67 8B
```

## 1.8. Done. The request computed at step 7 can be sent over the wire ##

# 2. Plain request/response dissecting #
## 2.1. Request ##
This is our plain request (note, this is another case different from the one analyzed in the encryption section): the first request that flows from the flash player to the server
```
0B 11 DD 30 00 53 42 41 0A 72 74 6D 66 70 3A 2F 
2F 73 74 72 61 74 75 73 2E 61 64 6F 62 65 2E 63 
6F 6D 2F 39 35 36 64 30 30 39 35 62 63 39 34 31 
36 32 34 62 32 30 64 62 37 37 66 2D 37 36 33 61 
63 34 66 34 36 32 38 39 2F 5B A1 95 F3 3D 16 51 
D9 95 FD 22 19 A7 73 51 B0
```
  * '''0x0B''' - unknown, pretty "stable". Always appears as the first byte
  * '''0x11 0xdd''' - unknown, looks like they are random
  * '''0x30''' - some kind of marker. On flash to server requests this is 0x30. On server to flash responses this is 0x70
  * '''0x0053''' - the length of the rest of the message
  * '''0x42''' - the length of the rest of the message, excluding the final 16 bytes
  * '''0x41''' - the length of the rest of the message, excluding the final 16 bytes. Yes, it looks like a message in a message in a bottle
  * '''0x0a''' - unknown, pretty "stable". Same value no matter how long is the URI in the request
  * '''0x72 0x74... 0x38 0x39 0x2F''' - the URI
  * '''last 16 bytes''' - random bytes. I suspect that those are an encryption key used further into the messages flow

## 2.2. Response ##
```
0B 73 FF 70 00 9F 10 5B A1 95 F3 3D 16 51 D9 95
FD 22 19 A7 73 51 B0 40 A2 44 70 40 AF C0 47 12
27 13 D2 EF 30 72 F9 A1 C9 59 91 82 A6 4A 6D 80
99 97 F1 00 8E 16 A6 A8 57 CF 49 E1 60 7B 60 98
A2 50 8D C7 EB 68 DF 4A F9 4F F1 84 30 58 31 20
B5 03 DA 3F DD 64 98 FB 01 0A 41 0E 24 3E FC 67
5F D8 62 85 3B 0C 94 DA AF B1 51 93 9B 4D 95 75
C0 89 30 EF FE 7A BB 35 1D 39 58 67 E6 B5 B9 63 
7D B9 DA 23 C4 E5 A0 83 B7 A6 33 AF C3 16 AC 06 
1A 33 CA C1 F0 7E 91 01 C2 07 1B B5 02 15 02 02 
15 05 02 15 0E
```
  * '''0x0B''' - unknown, pretty "stable". Always appears as the first byte
  * '''0x73 0xff''' - unknown, looks like they are random
  * '''0x70''' - some kind of marker. On server to flash requests this is 0x70. On flash to server responses this is 0x30
  * '''0x009F''' - the length of the rest of the message
  * '''0x10''' - the length of the key that was passed in the request
  * '''next 16 bytes''' - the key from the request (last 16 bytes)
  * '''0x40''' - a length
  * '''next 0x40 bytes''' - the payload (unknown for now)
  * '''0x01''' - a length
  * '''next 0x01 byte''' - the payload (unknown for now)
  * '''0x41''' - a length
  * '''next 0x41 bytes''' - the payload (unknown for now)
  * '''0x02''' - a length
  * '''next 0x02 bytes''' - the payload (unknown for now)
  * '''0x02''' - a length
  * '''next 0x02 bytes''' - the payload (unknown for now)
  * '''0x02''' - a length
  * '''next 0x02 bytes''' - the payload (unknown for now)
# 3. Authors #

(removed the author since he seems to have some issues with Adobe)