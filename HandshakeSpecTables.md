#Handshake Specification Tables for RTMPE.

# Client Chunk 1 #

| **Start** | **Stop** | **Length** | **Semnification** | **Zone Name** |
|:----------|:---------|:-----------|:------------------|:--------------|
| 0 | 	3	| 4	| uptime	| A |
| 4 |	7	| 4	| version	| B |
| 8 | 11 | 4 |	digest offset |	C |
| 12 |	12+digest offset-1 |	digest offset |	Unknown zone |	D |
| 12+digest offset |	12+digest offset+31 |	32	| digest |	E |
| 12+digest offset+32 |	739 |	696-digest offset |	Unknown zone |	F |
| 740 |	771 |	32 |	Unknown zone |	G |
| 772 |	772+dh offset -1 |	dh offset |	Unknown zone	| H |
| 772+dh offset |	772+dh offset+127	| 128 |	dh	| I |
| 772+dh offset+128 |	1403	| 504-dh offset |	Unknown zone	| J |
| 1404 |	1531 |	128	| Unknown zone	| K |
| 1532 |	1535 |	4	| dh offset	| L |


## Comments ##

A: I always put it 0

B: Impersonate with 9.0.124.2 (4 bytes: 9,0,124,2)

C: the bytes in this zone gives the offset to the digest with the formula:
  1. uint32\_t offset = b0 + b1 + b2 + b3;
  1. offset = offset % 728;
  1. offset = offset + 12;
Where bn is the n'th byte starting at this region

E: HMACsha256 over entire 1536 bytes except zone E (the digest itself) using fisrt 30 bytes from genuineFPKey as key

I: the client's public key from the DH key pair

L: The location of the client's public key computed with this formula:
  1. uint32\_t offset = b0 + b1 + b2 + b3;
  1. offset = offset % 632;
  1. offset = offset + 772;
Where bn is the n'th byte starting at this region

Of course, DH key must be computed before computing zone E

# Server #

| **Start** |	**Stop** |	 **Length** |	**Semnification** | **Zone name** |
|:----------|:---------|:------------|:------------------|:--------------|
| 0 |	3 |	4 |	uptime |	A |
| 4 |	7 |	4 |	version |	B |
| 8 |	11 |	4 |	digest offset |	C |
| 12 |	12+digest offset-1 |	digest offset |	Unknown zone	| D |
| 12+digest offset |	12+digest offset+31 |	32 |	digest |	E |
| 12+digest offset+32 |	739 |	696-digest offset |	Unknown zone	| F |
| 740 |	771 |	32	| Unknown zone	| G|
| 772 |	772+dh offset -1 |	dh  offset	| Unknown zone	| H |
| 772+dh offset |	772+dh offset+127 |	128	| dh	| I |
| 772+dh offset+128 |	1403 |	504-dh offset	| Unknown zone |	J |
| 1404 |	1531 |	128 |	Unknown zone |	K |
| 1532 |	1535 |	4 |	dh offset |	L |
| 1536 |	3039 |	1504 |	Unknown zone	| M |
| 3040 |	3071 |	32 |	2 stage Hash |	N |

## Comments ##

A: I always put it 0

B: Impersonate with 3.5.1.1 (4 bytes: 3,5,1,1)

C: the bytes in this zone gives the offset to the digest with the formula:
  1. uint32\_t offset = b0 + b1 + b2 + b3;
  1. offset = offset % 728;
  1. offset = offset + 12;
Where bn is the n'th byte starting at this region

E: HMACsha256 over first 1536 bytes except zone E (the digest itself) using fisrt 36 bytes from genuineFMSKey as key

I: the server's public key from the DH key pair

L: The location of the server's public key computed with this formula:
  1. uint32\_t offset = b0 + b1 + b2 + b3;
  1. offset = offset % 632;
  1. offset = offset + 772;
Where bn is the n'th byte starting at this region

Of course, DH key must be computed before computing zone E

N: 2 stage sha256 hash
  1. chalange=hmacsha256 over zone E from client chunk 1 using entire genuineFMSKey as key
  1. final hash=hmacsha256 over zone M using chalange as key

# Client Chunk 2 #

| **Start** |	**Stop** | **length** |	**Semnification** | 	**Zone name** |
|:----------|:---------|:-----------|:------------------|:---------------|
| 0	| 1503	| 1504	| Unknown zone	| A |
| 1504 |	1535 |	32 |	2 stage Hash	| B |

## Comments ##

B: 2 stage sha256 hash
  1. chalange=hmacsha256 over zone E from server using entire genuineFPKey as key
  1. final hash=hmacsha256 over zone A using chalange as key


# Keys #
```
genuineFMSKey[] = {
    0x47, 0x65, 0x6e, 0x75, 0x69, 0x6e, 0x65, 0x20,
    0x41, 0x64, 0x6f, 0x62, 0x65, 0x20, 0x46, 0x6c,
    0x61, 0x73, 0x68, 0x20, 0x4d, 0x65, 0x64, 0x69,
    0x61, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
    0x20, 0x30, 0x30, 0x31, // Genuine Adobe Flash Media Server 001 (36 bytes)
    0xf0, 0xee, 0xc2, 0x4a, 0x80, 0x68, 0xbe, 0xe8,
    0x2e, 0x00, 0xd0, 0xd1, 0x02, 0x9e, 0x7e, 0x57,
    0x6e, 0xec, 0x5d, 0x2d, 0x29, 0x80, 0x6f, 0xab,
    0x93, 0xb8, 0xe6, 0x36, 0xcf, 0xeb, 0x31, 0xae
}; // 68


genuineFPKey[] = {
    0x47, 0x65, 0x6E, 0x75, 0x69, 0x6E, 0x65, 0x20,
    0x41, 0x64, 0x6F, 0x62, 0x65, 0x20, 0x46, 0x6C,
    0x61, 0x73, 0x68, 0x20, 0x50, 0x6C, 0x61, 0x79,
    0x65, 0x72, 0x20, 0x30, 0x30, 0x31, // Genuine Adobe Flash Player 001 (30 bytes)
    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8,
    0x2E, 0x00, 0xD0, 0xD1, 0x02, 0x9E, 0x7E, 0x57,
    0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
    0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
}; // 62

```