package ws.blue5.net.rtmpe;

/*
 * Blue5 media server support library - http://www.blue5.ws/
 * 
 * Copyright (c) 2009 by respective authors. All rights reserved.
 * 
 * This library is free software; you can redistribute it and/or modify it under the 
 * terms of the GNU Lesser General Public License as published by the Free Software 
 * Foundation; either version 2.1 of the License, or (at your option) any later 
 * version. 
 * 
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along 
 * with this library; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.mina.core.buffer.IoBuffer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.red5.server.net.IHandshake;
import org.red5.server.net.rtmp.message.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ws.blue5.RtmpSession;
import ws.blue5.util.Utils;

/**
 * Provides handshaking support for the RTMPE protocol.
 * 
 * <br/>
 * This class originated from the flazr project by Peter Thomas.
 * <br />
 * 
 * @see crtmpserver <a href="http://www.rtmpd.com/browser/trunk/sources/thelib/src/protocols/rtmp/basertmpprotocol.cpp">rtmp protocol code</a>
 * @see crtmpserver <a href="http://www.rtmpd.com/browser/trunk/sources/thelib/src/protocols/rtmp/inboundrtmpprotocol.cpp">inbound rtmp code</a>
 * 
 * @author Peter Thomas (ptrthomas@gmail.com)
 * @author Paul Gregoire (mondain@gmail.com)
 */
public class RTMPEHandshake extends RTMPHandshake {

	private static final Logger logger = LoggerFactory.getLogger(RTMPEHandshake.class);

	private static final int HANDSHAKE_SIZE_SERVER = 1 + (Constants.HANDSHAKE_SIZE * 2);

	protected static final int SHA256_DIGEST_LENGTH = 32;

	private static final byte[] RANDOM_CRUD = {
	    (byte) 0xf0, (byte) 0xee, (byte) 0xc2, (byte) 0x4a,
	    (byte) 0x80, (byte) 0x68, (byte) 0xbe, (byte) 0xe8, (byte) 0x2e, (byte) 0x00, (byte) 0xd0, (byte) 0xd1,
	    (byte) 0x02, (byte) 0x9e, (byte) 0x7e, (byte) 0x57, (byte) 0x6e, (byte) 0xec, (byte) 0x5d, (byte) 0x2d,
	    (byte) 0x29, (byte) 0x80, (byte) 0x6f, (byte) 0xab, (byte) 0x93, (byte) 0xb8, (byte) 0xe6, (byte) 0x36,
	    (byte) 0xcf, (byte) 0xeb, (byte) 0x31, (byte) 0xae
	};

	protected static final byte[] SERVER_CONST = "Genuine Adobe Flash Media Server 001".getBytes();

	protected static final byte[] CLIENT_CONST = "Genuine Adobe Flash Player 001".getBytes();

	private static final byte[] SERVER_CONST_CRUD = concat(SERVER_CONST, RANDOM_CRUD);

	private static final byte[] CLIENT_CONST_CRUD = concat(CLIENT_CONST, RANDOM_CRUD);

	private IoBuffer data;
    
	static {
		//get security provider
		Security.addProvider(new BouncyCastleProvider());	
	}

    /**
     * @TODO: Implement this!
     */
	public IoBuffer generateResponse(IoBuffer input) {
	    return null;
	}

	private static byte[] concat(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}

	private static int addBytes(byte[] bytes) {
		if(bytes.length != 4) {
			throw new RuntimeException("unexpected byte array size: " + bytes.length);
		}
		int result = 0;
		for(int i = 0; i < bytes.length; i++) {
			result += bytes[i] & 0xff;
		}
		return result;
	}

	private static int calculateOffset(byte[] pointer, int modulus, int increment) {
		int offset = addBytes(pointer);
		offset %= modulus;
		offset += increment;
		return offset;
	}

	protected static byte[] getFourBytesFrom(IoBuffer buf, int offset) {
		int initial = buf.position();
		buf.position(offset);
		byte[] bytes = new byte[4];
		buf.get(bytes);
		buf.position(initial);
		return bytes;
	}

	private static byte[] getSharedSecret(byte[] otherPublicKeyBytes, KeyAgreement keyAgreement) {
		BigInteger otherPublicKeyInt = new BigInteger(1, otherPublicKeyBytes);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("DH");
			KeySpec otherPublicKeySpec = new DHPublicKeySpec(otherPublicKeyInt, RTMPHandshake.DH_MODULUS, RTMPHandshake.DH_BASE);
			PublicKey otherPublicKey = keyFactory.generatePublic(otherPublicKeySpec);
		    keyAgreement.doPhase(otherPublicKey, true);
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	    byte[] sharedSecret = keyAgreement.generateSecret();
	    logger.debug("Shared secret [{}]: ", sharedSecret.length, Utils.toHex(sharedSecret));
	    return sharedSecret;
	}						

	public IoBuffer getData() {
		return data;
	}

	public static RTMPEHandshake generateClientRequest1(RtmpSession session) {
		IoBuffer buf = IoBuffer.allocate(Constants.HANDSHAKE_SIZE);
        Utils.writeInt32Reverse(buf, (int) System.currentTimeMillis() & 0x7FFFFFFF);
        buf.put(new byte[] { 0x09, 0x00, 0x7c, 0x02 }); // flash player version 9.0.124.2
		byte[] randomBytes = new byte[Constants.HANDSHAKE_SIZE - 8]; // 4 + 4 bytes [time, version] done already
		Random random = new Random();
		random.nextBytes(randomBytes);
		buf.put(randomBytes);
		buf.flip();
        if (session.isEncrypted()) {
        	logger.info("creating client handshake part 1 for encryption");
	        KeyPair keyPair = generateKeyPair(session);
	        byte[] clientPublicKey = getPublicKey(keyPair);
	        byte[] dhPointer = getFourBytesFrom(buf, HANDSHAKE_SIZE - 4);
	        int dhOffset = calculateOffset(dhPointer, 632, 772);
	        buf.position(dhOffset);
	        buf.put(clientPublicKey);
	        session.setClientPublicKey(clientPublicKey);
	        logger.debug("client public key: " + Utils.toHex(clientPublicKey));

	        byte[] digestPointer = getFourBytesFrom(buf, 8);
	        int digestOffset = calculateOffset(digestPointer, 728, 12);
	        buf.rewind();
	        int messageLength = Constants.HANDSHAKE_SIZE - SHA256_DIGEST_LENGTH;
	        byte[] message = new byte[messageLength];
	        buf.get(message, 0, digestOffset);
	        int afterDigestOffset = digestOffset + SHA256_DIGEST_LENGTH;
	        buf.position(afterDigestOffset);
	        buf.get(message, digestOffset, Constants.HANDSHAKE_SIZE - afterDigestOffset);
			byte[] digest = Utils.calculateHMACSHA256(message, CLIENT_CONST);
			buf.position(digestOffset);
			buf.put(digest);
			buf.rewind();
			session.setClientDigest(digest);
        }

        RTMPEHandshake hs = new RTMPEHandshake();
        hs.data = IoBuffer.allocate(Constants.HANDSHAKE_SIZE + 1);
		if(session.isEncrypted()) {
			hs.data.put((byte) 0x06);
		} else {
			hs.data.put((byte) 0x03);
		}
		hs.data.put(buf);
		hs.data.flip();
		return hs;
	}

	public boolean decodeServerResponse(IoBuffer in, RtmpSession session) {
    	if(in.remaining() < HANDSHAKE_SIZE_SERVER) {
    		return false;
    	}
		byte[] bytes = new byte[HANDSHAKE_SIZE_SERVER];
		in.get(bytes);
		data = IoBuffer.wrap(bytes);
		
		// TODO validate bytes[0] is 0x03 or 0x06 (encryption)
		
		IoBuffer buf = IoBuffer.allocate(Constants.HANDSHAKE_SIZE);
		buf.put(bytes, 1, Constants.HANDSHAKE_SIZE);
		buf.flip();		
		logger.debug("server response part 1: " + buf);		

		if(session.isEncrypted()) {
			logger.info("processing server response for encryption");			
			// TODO validate time and version ?
			byte[] serverTime = new byte[4];
			buf.get(serverTime);
			logger.debug("server time: {}", Utils.toHex(serverTime));

			byte[] serverVersion = new byte[4];
			buf.get(serverVersion);
			logger.debug("server version: {}", Utils.toHex(serverVersion));

			byte[] digestPointer = new byte[4]; // position 8
			buf.get(digestPointer);
			int digestOffset = calculateOffset(digestPointer, 728, 12);
	        buf.rewind();

	        int messageLength = Constants.HANDSHAKE_SIZE - SHA256_DIGEST_LENGTH;
	        byte[] message = new byte[messageLength];
			buf.get(message, 0, digestOffset);
			int afterDigestOffset = digestOffset + SHA256_DIGEST_LENGTH;
			buf.position(afterDigestOffset);
			buf.get(message, digestOffset, Constants.HANDSHAKE_SIZE - afterDigestOffset);
			byte[] digest = Utils.calculateHMACSHA256(message, SERVER_CONST);
			byte[] serverDigest = new byte[SHA256_DIGEST_LENGTH];
			buf.position(digestOffset);
			buf.get(serverDigest);

			byte[] serverPublicKey = new byte[128];
			if(Arrays.equals(digest, serverDigest)) {
				logger.info("type 1 digest comparison success");
				byte[] dhPointer = getFourBytesFrom(buf, Constants.HANDSHAKE_SIZE - 4);
				int dhOffset = calculateOffset(dhPointer, 632, 772);
				buf.position(dhOffset);
				buf.get(serverPublicKey);
				session.setServerDigest(serverDigest);
			} else {
				logger.warn("type 1 digest comparison failed, trying type 2 algorithm");
				digestPointer = getFourBytesFrom(buf, 772);
				digestOffset = calculateOffset(digestPointer, 728, 776);
				message = new byte[messageLength];
				buf.rewind();
				buf.get(message, 0, digestOffset);
				afterDigestOffset = digestOffset + SHA256_DIGEST_LENGTH;
				buf.position(afterDigestOffset);
				buf.get(message, digestOffset, Constants.HANDSHAKE_SIZE - afterDigestOffset);
				digest = Utils.calculateHMACSHA256(message, SERVER_CONST);
				serverDigest = new byte[SHA256_DIGEST_LENGTH];
				buf.position(digestOffset);
				buf.get(serverDigest);
				if(Arrays.equals(digest, serverDigest)) {
					logger.info("type 2 digest comparison success");
					byte[] dhPointer = getFourBytesFrom(buf, 768);
					int dhOffset = calculateOffset(dhPointer, 632, 8);
					buf.position(dhOffset);
					buf.get(serverPublicKey);
					session.setServerDigest(serverDigest);
				} else {
					throw new RuntimeException("type 2 digest comparison failed");
				}
			}
			logger.debug("server public key: " + Utils.toHex(serverPublicKey));			
			byte[] sharedSecret = getSharedSecret(serverPublicKey, session.getKeyAgreement());
			logger.debug("shared secret: " + Utils.toHex(sharedSecret));
			//session.setServerPublicKey(serverPublicKey);

			byte[] digestOut = Utils.calculateHMACSHA256(serverPublicKey, sharedSecret);
			try {
				Cipher cipherOut = Cipher.getInstance("RC4");
				cipherOut.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(digestOut, 0, 16, "RC4"));
				session.setCipherOut(cipherOut);
			} catch(Exception e) {
				throw new RuntimeException(e);
			}

			byte[] digestIn = Utils.calculateHMACSHA256(session.getClientPublicKey(), sharedSecret);
			try {
				Cipher cipherIn = Cipher.getInstance("RC4");
				cipherIn.init(Cipher.DECRYPT_MODE, new SecretKeySpec(digestIn, 0, 16, "RC4"));
				session.setCipherIn(cipherIn);
			} catch(Exception e) {
				throw new RuntimeException(e);
			}
		}
		
		IoBuffer partTwo = IoBuffer.allocate(Constants.HANDSHAKE_SIZE);
		partTwo.put(bytes, 1 + Constants.HANDSHAKE_SIZE, Constants.HANDSHAKE_SIZE);
		partTwo.flip();	
		
		logger.debug("server response part 2: " + partTwo);
		
		// validate server response part 2, not really required for client, but just to show off ;)
		if(session.isEncrypted()) {
			byte[] firstFourBytes = getFourBytesFrom(partTwo, 0);			
			if(Arrays.equals(new byte[]{0, 0, 0, 0}, firstFourBytes)) {
				logger.warn("server response part 2 first four bytes are zero, did handshake fail ?");
			}			
			byte[] message = new byte[Constants.HANDSHAKE_SIZE - SHA256_DIGEST_LENGTH];
			partTwo.get(message);
			byte[] digest = Utils.calculateHMACSHA256(session.getClientDigest(), SERVER_CONST_CRUD);
			byte[] signature = Utils.calculateHMACSHA256(message, digest);
			byte[] serverSignature = new byte[SHA256_DIGEST_LENGTH];			
			partTwo.get(serverSignature);
			if(Arrays.equals(signature, serverSignature)) {
				logger.info("server response part 2 validation success, is Flash Player v9 handshake");
			} else {
				logger.warn("server response part 2 validation failed, not Flash Player v9 handshake");
			}			
		} else {
			// TODO validate if server echoed client request 1			
		}

		// swf verification
		if(session.getSwfHash() != null) {
			byte[] bytesFromServer = new byte[SHA256_DIGEST_LENGTH];
			buf.position(Constants.HANDSHAKE_SIZE - SHA256_DIGEST_LENGTH);
			buf.get(bytesFromServer);
			byte[] bytesFromServerHash = Utils.calculateHMACSHA256(session.getSwfHash().getBytes(), bytesFromServer);
			// construct SWF verification pong payload
			IoBuffer swfv = IoBuffer.allocate(42);
			swfv.put((byte) 0x01);
			swfv.put((byte) 0x01);
			swfv.putInt(session.getSwfSize());
			swfv.putInt(session.getSwfSize());
			swfv.put(bytesFromServerHash);
			byte[] swfvBytes = new byte[42];
			swfv.flip();
			swfv.get(swfvBytes);
			session.setSwfVerification(swfvBytes);
			logger.info("initialized swf verification response from swfSize = "
					+ session.getSwfSize() + " & swfHash = '"
					+ session.getSwfHash() + "': " + Utils.toHex(swfvBytes));
		}

		return true;
	}

	public RTMPEHandshake generateClientRequest2(RtmpSession session) {
		// TODO validate serverResponsePart2
		if(session.isEncrypted()) { // encryption
			logger.info("creating client handshake part 2 for encryption");
			byte[] randomBytes = new byte[Constants.HANDSHAKE_SIZE];
			Random random = new Random();
			random.nextBytes(randomBytes);
			IoBuffer buf = IoBuffer.wrap(randomBytes);
			byte[] digest = Utils.calculateHMACSHA256(session.getServerDigest(), CLIENT_CONST_CRUD);
			byte[] message = new byte[Constants.HANDSHAKE_SIZE - SHA256_DIGEST_LENGTH];
			buf.rewind();
			buf.get(message);
			byte[] signature = Utils.calculateHMACSHA256(message, digest);
			buf.put(signature);
			buf.rewind();

			// update 'encoder / decoder state' for the RC4 keys
			// both parties *pretend* as if handshake part 2 (1536 bytes) was encrypted
			// effectively this hides / discards the first few bytes of encrypted session
			// which is known to increase the secure-ness of RC4
			// RC4 state is just a function of number of bytes processed so far
			// that's why we just run 1536 arbitrary bytes through the keys below
			byte[] dummyBytes = new byte[Constants.HANDSHAKE_SIZE];
			session.getCipherIn().update(dummyBytes);
			session.getCipherOut().update(dummyBytes);

			RTMPEHandshake hs = new RTMPEHandshake();
			hs.data = buf;
			return hs;
		} else {
			data.get(); // skip first byte
			byte[] bytes = new byte[Constants.HANDSHAKE_SIZE];
			data.get(bytes); // copy first half of server response
			RTMPEHandshake hs = new RTMPEHandshake();
			hs.data = IoBuffer.wrap(bytes);
			return hs;
		}
	}

}
