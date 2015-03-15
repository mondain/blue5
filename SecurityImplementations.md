Security Implementations in Flash thanks to Matthew Kaufman

# RTMP #
What is passed in is in plaintext and visible to anyone who can decode the RTMP chunk stream format, which is now published.

# RTMPS #
What is passed in is protected by SSL guarantees, which is that there is no passive observation and that the server's SSL certificate is valid per the certificate checking that takes place for SSL. (System dependent as to what root CAs are valid, how CRLs are handled, etc.) The check of the server certificate authenticates that the server is a valid server but not that the client is a valid Flash Player or that they're your user.

# RTMPE #
What is passed in is encrypted with a well-known encryption algorithm (stream cipher) which is keyed using a well-known public-key-exchange algorithm which prevents passive observation and which provides perfect forward secrecy. There is no server certificate, so no checking that the server is valid per SSL guarantees. As a result, man-in-the-middle attacks are possible. The specification is unpublished, so a man-in-the-middle attacker would need a reverse-engineered version of the protocol in order to mimic the key exchange and cryptography. Session nonces are provided (as of 10.0.22) and are tied to the key exchange in such a way that client and/or server authentication can be built on top of those exchanged values.

# RTMFP #
What is passed in is encrypted with a well-known encryption algorithm (block cipher) which is keyed using a well-known public-key-exchange algorithm. that prevents passive observation and which provides perfect forward secrecy. There is no server certificate as such, though the protocol does have provision for adding server certificates. Because there is no certificate check, there is no authentication of the server a la SSL. As a result, man-in-the-middle attacks are possible. The specification is unpublished, so a man-in-the-middle attacker would need a reverse-engineered version of the protocol in order to minic the key exchange, cryptography, and all low-level protocol functionality necessary to keep the session working and passing data (much more work than keeping RTMPE-over-TCP going). Session nonces are provided and are tied to the key exchange in such a way that client and/or server authentication can be built on top of those exchanged values.

# RTMFP peer-to-peer #
When an RTMFP peer connects to another RTMFP peer by Peer ID, the public-key-exchange algorithm is tied to the Peer ID in such a way that it is not possible to conduct a man-in-the-middle attack. All other guarantees provided by RTMFP (no passive observation, perfect forward secrecy) are also in place.
