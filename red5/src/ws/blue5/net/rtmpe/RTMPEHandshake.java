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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.mina.core.buffer.IoBuffer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.red5.server.net.IHandshake;
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
 * @author Peter Thomas (ptrthomas@gmail.com)
 * @author Paul Gregoire (mondain@gmail.com)
 */
public class RTMPEHandshake implements IHandshake {

	private static final Logger logger = LoggerFactory.getLogger(RTMPEHandshake.class);

	private static final int HANDSHAKE_SIZE = 1536;

	private static final int HANDSHAKE_SIZE_SERVER = 2 * HANDSHAKE_SIZE + 1;

	private static final int SHA256_DIGEST_LENGTH = 32;

	private static final byte[] RANDOM_CRUD = {
	    (byte) 0xf0, (byte) 0xee, (byte) 0xc2, (byte) 0x4a,
	    (byte) 0x80, (byte) 0x68, (byte) 0xbe, (byte) 0xe8, (byte) 0x2e, (byte) 0x00, (byte) 0xd0, (byte) 0xd1,
	    (byte) 0x02, (byte) 0x9e, (byte) 0x7e, (byte) 0x57, (byte) 0x6e, (byte) 0xec, (byte) 0x5d, (byte) 0x2d,
	    (byte) 0x29, (byte) 0x80, (byte) 0x6f, (byte) 0xab, (byte) 0x93, (byte) 0xb8, (byte) 0xe6, (byte) 0x36,
	    (byte) 0xcf, (byte) 0xeb, (byte) 0x31, (byte) 0xae
	};

	private static final byte[] SERVER_CONST = "Genuine Adobe Flash Media Server 001".getBytes();

	private static final byte[] CLIENT_CONST = "Genuine Adobe Flash Player 001".getBytes();

	private static final byte[] SERVER_CONST_CRUD = concat(SERVER_CONST, RANDOM_CRUD);

	private static final byte[] CLIENT_CONST_CRUD = concat(CLIENT_CONST, RANDOM_CRUD);

    private static final byte[] DH_MODULUS_BYTES = {
		(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
		(byte)0xc9, (byte)0x0f, (byte)0xda, (byte)0xa2, (byte)0x21, (byte)0x68, (byte)0xc2, (byte)0x34,
		(byte)0xc4, (byte)0xc6, (byte)0x62, (byte)0x8b, (byte)0x80, (byte)0xdc, (byte)0x1c, (byte)0xd1,
		(byte)0x29, (byte)0x02, (byte)0x4e, (byte)0x08, (byte)0x8a, (byte)0x67, (byte)0xcc, (byte)0x74,
		(byte)0x02, (byte)0x0b, (byte)0xbe, (byte)0xa6, (byte)0x3b, (byte)0x13, (byte)0x9b, (byte)0x22,
		(byte)0x51, (byte)0x4a, (byte)0x08, (byte)0x79, (byte)0x8e, (byte)0x34, (byte)0x04, (byte)0xdd,
		(byte)0xef, (byte)0x95, (byte)0x19, (byte)0xb3, (byte)0xcd, (byte)0x3a, (byte)0x43, (byte)0x1b,
		(byte)0x30, (byte)0x2b, (byte)0x0a, (byte)0x6d, (byte)0xf2, (byte)0x5f, (byte)0x14, (byte)0x37,
		(byte)0x4f, (byte)0xe1, (byte)0x35, (byte)0x6d, (byte)0x6d, (byte)0x51, (byte)0xc2, (byte)0x45,
		(byte)0xe4, (byte)0x85, (byte)0xb5, (byte)0x76, (byte)0x62, (byte)0x5e, (byte)0x7e, (byte)0xc6,
		(byte)0xf4, (byte)0x4c, (byte)0x42, (byte)0xe9, (byte)0xa6, (byte)0x37, (byte)0xed, (byte)0x6b,
		(byte)0x0b, (byte)0xff, (byte)0x5c, (byte)0xb6, (byte)0xf4, (byte)0x06, (byte)0xb7, (byte)0xed,
		(byte)0xee, (byte)0x38, (byte)0x6b, (byte)0xfb, (byte)0x5a, (byte)0x89, (byte)0x9f, (byte)0xa5,
		(byte)0xae, (byte)0x9f, (byte)0x24, (byte)0x11, (byte)0x7c, (byte)0x4b, (byte)0x1f, (byte)0xe6,
		(byte)0x49, (byte)0x28, (byte)0x66, (byte)0x51, (byte)0xec, (byte)0xe6, (byte)0x53, (byte)0x81,
		(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff
    };

    private static final BigInteger DH_MODULUS = new BigInteger(1, DH_MODULUS_BYTES);

    private static final BigInteger DH_BASE = BigInteger.valueOf(2);    

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

	private static int getServerDhOffset(byte[] bytes) {
		int offset = addBytes(bytes);
		offset %= 632;
		offset += 8;
		final int maxVal = 767 - 128;
		if(offset > maxVal) {
			throw new RuntimeException("server DH offset should be less than " + maxVal + ", is: " + offset);
		}
		return offset;
	}

	private static int getServerDigestOffset(byte[] bytes) {
		int offset = addBytes(bytes);
		offset %= 728;
		offset += 776;
		final int maxVal = 1535 - 32;
		if(offset > maxVal) {
			throw new RuntimeException("server digest offset should be less than " + maxVal + ", is: " + offset);
		}
		return offset;
	}

	private static int getClientDhOffset(byte[] bytes) {
		int offset = addBytes(bytes);
		offset %= 632;
		offset += 772;
		final int maxVal = HANDSHAKE_SIZE - 128 - 4;
		if(offset > maxVal) {
			throw new RuntimeException("client DH offset should be less than " + maxVal + ", is: " + offset);
		}
		return offset;
	}

	private static int getClientDigestOffset(byte[] bytes) {
		int offset = addBytes(bytes);
		offset %= 728;
		offset += 12;
		final int maxVal = 771 - 32;
		if(offset > maxVal) {
			throw new RuntimeException("server digest offset should be less than " + maxVal + ", is: " + offset);
		}
		return offset;
	}

	private static byte[] getFourBytesFrom(IoBuffer buf, int offset) {
		int initial = buf.position();
		buf.position(offset);
		byte[] bytes = new byte[4];
		buf.get(bytes);
		buf.position(initial);
		return bytes;
	}

	private static KeyPair generateKeyPair(RtmpSession session) {
		DHParameterSpec keySpec = new DHParameterSpec(DH_MODULUS, DH_BASE);
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
			keyGen.initialize(keySpec);
			KeyPair keyPair = keyGen.generateKeyPair();
		    KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
		    keyAgreement.init(keyPair.getPrivate());
		    session.setKeyAgreement(keyAgreement);
			return keyPair;
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static byte[] getPublicKey(KeyPair keyPair) {
		 DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
	     BigInteger	dh_Y = publicKey.getY();
	     logger.debug("public key value: " + dh_Y);
	     byte[] result = dh_Y.toByteArray();
	     logger.debug("public key as bytes, len = [" + result.length + "]: " + Utils.toHex(result));
	     byte[] temp = new byte[128];
	     if(result.length < 128) {
	    	 System.arraycopy(result, 0, temp, 128 - result.length, result.length);
	    	 result = temp;
	    	 logger.debug("padded public key length to 128");
	     } else if(result.length > 128){
	    	 System.arraycopy(result, result.length - 128, temp, 0, 128);
	    	 result = temp;
	    	 logger.debug("truncated public key length to 128");
	     }
	     return result;
	}

	private static byte[] getSharedSecret(byte[] otherPublicKeyBytes, KeyAgreement keyAgreement) {
		BigInteger otherPublicKeyInt = new BigInteger(1, otherPublicKeyBytes);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("DH");
			KeySpec otherPublicKeySpec = new DHPublicKeySpec(otherPublicKeyInt, DH_MODULUS, DH_BASE);
			PublicKey otherPublicKey = keyFactory.generatePublic(otherPublicKeySpec);
		    keyAgreement.doPhase(otherPublicKey, true);
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	    return keyAgreement.generateSecret();
	}
	
	private static byte[] calculateHMACSHA256(byte[] message, byte[] key) {
		byte[] output = null;
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(key, "HmacSHA256"));
			output = mac.doFinal(message);
		} catch (SecurityException e) {
			logger.error("Security exception when getting HMAC", e);
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			logger.error("HMAC SHA256 does not exist");			
			throw new RuntimeException(e);
		} catch (InvalidKeyException e) {
			logger.error("Invalid key", e);
		}
		return output;
	}	

	public static void main(String[] args) throws Exception {		
		DHParameterSpec paramSpecA = new DHParameterSpec(DH_MODULUS, DH_BASE);		
		KeyPairGenerator keyGenA = KeyPairGenerator.getInstance("DH");
		keyGenA.initialize(paramSpecA);
		KeyPair keyPairA = keyGenA.generateKeyPair();
	    KeyAgreement keyAgreementA = KeyAgreement.getInstance("DH");
	    keyAgreementA.init(keyPairA.getPrivate());
	    byte[] publicKeyBytesA = getPublicKey(keyPairA);
	    //==========================================================
	    BigInteger publicKeyIntFromA = new BigInteger(1, publicKeyBytesA);		
		KeySpec publicKeySpecFromA = new DHPublicKeySpec(publicKeyIntFromA, DH_MODULUS, DH_BASE);
		KeyFactory keyFactoryB = KeyFactory.getInstance("DH");
		PublicKey publicKeyFromA = keyFactoryB.generatePublic(publicKeySpecFromA);
		DHParameterSpec paramSpecB = ((DHPublicKey) publicKeyFromA).getParams();		
		KeyPairGenerator keyGenB = KeyPairGenerator.getInstance("DH");
		keyGenB.initialize(paramSpecB);
		KeyPair keyPairB = keyGenB.generateKeyPair();
        KeyAgreement keyAgreementB = KeyAgreement.getInstance("DH");
        keyAgreementB.init(keyPairB.getPrivate());
        keyAgreementB.doPhase(publicKeyFromA, true);
        byte[] publicKeyBytesB = getPublicKey(keyPairB);
        //==========================================================
        BigInteger publicKeyIntFromB = new BigInteger(1, publicKeyBytesB);        
        KeySpec publicKeySpecFromB = new DHPublicKeySpec(publicKeyIntFromB, DH_MODULUS, DH_BASE);
        KeyFactory keyFactoryA = KeyFactory.getInstance("DH");
        PublicKey publicKeyFromB = keyFactoryA.generatePublic(publicKeySpecFromB);
        keyAgreementA.doPhase(publicKeyFromB, true);    
        //==========================================================
        byte[] sharedSecretA = keyAgreementA.generateSecret();
        byte[] sharedSecretB = keyAgreementB.generateSecret();
        logger.info("A shared secret: " + Utils.toHex(sharedSecretA));
        logger.info("B shared secret: " + Utils.toHex(sharedSecretB));
        
		byte[] digestA = calculateHMACSHA256(publicKeyBytesA, sharedSecretA);		
		Cipher cipherA = Cipher.getInstance("RC4");
		cipherA.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(digestA, 0, 16, "RC4"));
		
		byte[] digestB = calculateHMACSHA256(publicKeyBytesA, sharedSecretA);		
		Cipher cipherB = Cipher.getInstance("RC4");
		cipherB.init(Cipher.DECRYPT_MODE, new SecretKeySpec(digestB, 0, 16, "RC4")); 		
		
		byte[] message = "hello world".getBytes();
		
		cipherA.update(new byte[HANDSHAKE_SIZE]);
		cipherB.update(new byte[HANDSHAKE_SIZE]);
		
		byte[] encrypted = cipherA.update(message);
		
		byte[] decrypted = cipherB.update(encrypted);
		
		logger.info("decrypted: " + new String(decrypted));
        
	}
	
	public static void main3(String[] args) throws Exception {
		byte[] client1 = Utils.readAsByteArray("client_handshake_part_1");
		IoBuffer buf = IoBuffer.allocate(HANDSHAKE_SIZE);
		buf.put(client1, 1, HANDSHAKE_SIZE);
		buf.flip();
		
		byte[] dhPointer = getFourBytesFrom(buf, HANDSHAKE_SIZE - 4);
		int dhOffset = getClientDhOffset(dhPointer);
		byte[] clientPublicKey = new byte[128];
		buf.position(dhOffset);
		buf.get(clientPublicKey);
		
		//============================================================
	    BigInteger publicKeyIntFromA = new BigInteger(1, clientPublicKey);		
		KeySpec publicKeySpecFromA = new DHPublicKeySpec(publicKeyIntFromA, DH_MODULUS, DH_BASE);
		KeyFactory keyFactoryB = KeyFactory.getInstance("DH");
		PublicKey publicKeyFromA = keyFactoryB.generatePublic(publicKeySpecFromA);
		DHParameterSpec paramSpecB = ((DHPublicKey) publicKeyFromA).getParams();		
		KeyPairGenerator keyGenB = KeyPairGenerator.getInstance("DH");
		keyGenB.initialize(paramSpecB);
		KeyPair keyPairB = keyGenB.generateKeyPair();
        KeyAgreement keyAgreementB = KeyAgreement.getInstance("DH");
        keyAgreementB.init(keyPairB.getPrivate());
        keyAgreementB.doPhase(publicKeyFromA, true);
        byte[] sharedSecret = keyAgreementB.generateSecret();
        logger.info("shared secret: " + Utils.toHex(sharedSecret));
        
		byte[] digestOut = calculateHMACSHA256(clientPublicKey, sharedSecret);		
		Cipher cipherOut = Cipher.getInstance("RC4");
		cipherOut.init(Cipher.DECRYPT_MODE, new SecretKeySpec(digestOut, 0, 16, "RC4"));    
		
		cipherOut.update(new byte[HANDSHAKE_SIZE]);
		
		byte[] connect = Utils.readAsByteArray("clinet_connect_request_encrypted");
		logger.info("connect encrypted: " + Utils.toHex(connect));
		byte[] plain = cipherOut.update(connect);
		logger.info("connect plain: " + Utils.toHex(plain));
        
        //==============================================================
		
		byte[] server1 = Utils.readAsByteArray("server_handshake_part_1");
		buf = IoBuffer.allocate(HANDSHAKE_SIZE);
		buf.put(server1, 1, HANDSHAKE_SIZE);		
		buf.flip();
		
		byte[] digestPointer = getFourBytesFrom(buf, 8);
		int digestOffset = getClientDigestOffset(digestPointer);
        buf.rewind();

        int messageLength = HANDSHAKE_SIZE - SHA256_DIGEST_LENGTH;
        byte[] message = new byte[messageLength];
		buf.get(message, 0, digestOffset);
		int afterDigestOffset = digestOffset + SHA256_DIGEST_LENGTH;
		buf.position(afterDigestOffset);
		buf.get(message, digestOffset, HANDSHAKE_SIZE - afterDigestOffset);
		byte[] digest = calculateHMACSHA256(message, SERVER_CONST);
		byte[] serverDigest = new byte[SHA256_DIGEST_LENGTH];
		buf.position(digestOffset);
		buf.get(serverDigest);	
		
		if(Arrays.equals(digest, serverDigest)) {
			logger.info("type 1 success");
		} else {
			logger.info("type 1 failed");
			throw new RuntimeException("not type 1");
		}
		
		dhPointer = getFourBytesFrom(buf, HANDSHAKE_SIZE - 4);
		dhOffset = getClientDhOffset(dhPointer);
		buf.position(dhOffset);
		byte[] serverPublicKey = new byte[128];
		buf.get(serverPublicKey);	
				
		
	}

	private IoBuffer data;

	public IoBuffer getData() {
		return data;
	}

	public static RTMPEHandshake generateClientRequest1(RtmpSession session) {
		IoBuffer buf = IoBuffer.allocate(HANDSHAKE_SIZE);
        Utils.writeInt32Reverse(buf, (int) System.currentTimeMillis() & 0x7FFFFFFF);
        buf.put(new byte[] { 0x09, 0x00, 0x7c, 0x02 }); // flash player version 9.0.124.2
		byte[] randomBytes = new byte[HANDSHAKE_SIZE - 8]; // 4 + 4 bytes [time, version] done already
		Random random = new Random();
		random.nextBytes(randomBytes);
		buf.put(randomBytes);
		buf.flip();
        if (session.isEncrypted()) {
        	logger.info("creating client handshake part 1 for encryption");
	        KeyPair keyPair = generateKeyPair(session);
	        byte[] clientPublicKey = getPublicKey(keyPair);
	        byte[] dhPointer = getFourBytesFrom(buf, HANDSHAKE_SIZE - 4);
	        int dhOffset = getClientDhOffset(dhPointer);
	        buf.position(dhOffset);
	        buf.put(clientPublicKey);
	        session.setClientPublicKey(clientPublicKey);
	        logger.debug("client public key: " + Utils.toHex(clientPublicKey));

	        byte[] digestPointer = getFourBytesFrom(buf, 8);
	        int digestOffset = getClientDigestOffset(digestPointer);
	        buf.rewind();
	        int messageLength = HANDSHAKE_SIZE - SHA256_DIGEST_LENGTH;
	        byte[] message = new byte[messageLength];
	        buf.get(message, 0, digestOffset);
	        int afterDigestOffset = digestOffset + SHA256_DIGEST_LENGTH;
	        buf.position(afterDigestOffset);
	        buf.get(message, digestOffset, HANDSHAKE_SIZE - afterDigestOffset);
			byte[] digest = calculateHMACSHA256(message, CLIENT_CONST);
			buf.position(digestOffset);
			buf.put(digest);
			buf.rewind();
        }

        RTMPEHandshake hs = new RTMPEHandshake();
        hs.data = IoBuffer.allocate(HANDSHAKE_SIZE + 1);
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
		
		IoBuffer buf = IoBuffer.allocate(HANDSHAKE_SIZE);
		buf.put(bytes, 1, HANDSHAKE_SIZE);
		buf.flip();		
		logger.debug("server response part 1: " + buf);		

		if(session.isEncrypted()) {
			logger.info("processing server response for encryption");			
			// TODO validate time and version ?
			byte[] serverTime = new byte[4];
			buf.get(serverTime);
			logger.debug("server time: " + Utils.toHex(serverTime));

			byte[] serverVersion = new byte[4];
			buf.get(serverVersion);
			logger.debug("server version: " + Utils.toHex(serverVersion));

			byte[] digestPointer = new byte[4]; // position 8
			buf.get(digestPointer);
			int digestOffset = getClientDigestOffset(digestPointer);
	        buf.rewind();

	        int messageLength = HANDSHAKE_SIZE - SHA256_DIGEST_LENGTH;
	        byte[] message = new byte[messageLength];
			buf.get(message, 0, digestOffset);
			int afterDigestOffset = digestOffset + SHA256_DIGEST_LENGTH;
			buf.position(afterDigestOffset);
			buf.get(message, digestOffset, HANDSHAKE_SIZE - afterDigestOffset);
			byte[] digest = calculateHMACSHA256(message, SERVER_CONST);
			byte[] serverDigest = new byte[SHA256_DIGEST_LENGTH];
			buf.position(digestOffset);
			buf.get(serverDigest);

			byte[] serverPublicKey = new byte[128];
			if(Arrays.equals(digest, serverDigest)) {
				logger.info("type 1 digest comparison success");
				byte[] dhPointer = getFourBytesFrom(buf, HANDSHAKE_SIZE - 4);
				int dhOffset = getClientDhOffset(dhPointer);
				buf.position(dhOffset);
				buf.get(serverPublicKey);
			} else {
				logger.warn("type 1 digest comparison failed, trying type 2 algorithm");
				digestPointer = getFourBytesFrom(buf, 772);
				digestOffset = getServerDigestOffset(digestPointer);
				message = new byte[messageLength];
				buf.rewind();
				buf.get(message, 0, digestOffset);
				afterDigestOffset = digestOffset + SHA256_DIGEST_LENGTH;
				buf.position(afterDigestOffset);
				buf.get(message, digestOffset, HANDSHAKE_SIZE - afterDigestOffset);
				digest = calculateHMACSHA256(message, SERVER_CONST);
				serverDigest = new byte[SHA256_DIGEST_LENGTH];
				buf.position(digestOffset);
				buf.get(serverDigest);
				if(Arrays.equals(digest, serverDigest)) {
					logger.info("type 2 digest comparison success");
					byte[] dhPointer = getFourBytesFrom(buf, 768);
					int dhOffset = getServerDhOffset(dhPointer);
					buf.position(dhOffset);
					buf.get(serverPublicKey);
				} else {
					throw new RuntimeException("type 2 digest comparison failed");
				}
			}
			logger.debug("server public key: " + Utils.toHex(serverPublicKey));			
			byte[] sharedSecret = getSharedSecret(serverPublicKey, session.getKeyAgreement());
			logger.debug("shared secret: " + Utils.toHex(sharedSecret));
			session.setServerPublicKey(serverPublicKey);

			byte[] digestIn = calculateHMACSHA256(serverPublicKey, sharedSecret);
			try {
				Cipher cipherIn = Cipher.getInstance("RC4");
				cipherIn.init(Cipher.DECRYPT_MODE, new SecretKeySpec(digestIn, 0, 16, "RC4"));
				session.setCipherIn(cipherIn);
			} catch(Exception e) {
				throw new RuntimeException(e);
			}

			byte[] digestOut = sha256(session.getClientPublicKey(), sharedSecret);
			try {
				Cipher cipherOut = Cipher.getInstance("RC4");
				cipherOut.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(digestOut, 0, 16, "RC4"));
				session.setCipherOut(cipherOut);
			} catch(Exception e) {
				throw new RuntimeException(e);
			}
		}
		
		IoBuffer partTwo = IoBuffer.allocate(HANDSHAKE_SIZE);
		partTwo.put(bytes, 1 + HANDSHAKE_SIZE, HANDSHAKE_SIZE);
		partTwo.flip();	
		
		logger.debug("server response part 2: " + partTwo);
		
		// validate server response part 2, not really required for client, but just to show off ;)
		if(session.isEncrypted()) {
			byte[] firstFourBytes = getFourBytesFrom(partTwo, 0);			
			if(Arrays.equals(new byte[]{0, 0, 0, 0}, firstFourBytes)) {
				logger.warn("server response part 2 first four bytes are zero, did handshake fail ?");
			}			
			byte[] message = new byte[HANDSHAKE_SIZE - SHA256_DIGEST_LENGTH];
			partTwo.get(message);
			byte[] digest = calculateHMACSHA256(session.getClientPublicKey(), SERVER_CONST_CRUD);
			byte[] signature = calculateHMACSHA256(message, digest);
			byte[] serverSignature = new byte[SHA256_DIGEST_LENGTH];			
			partTwo.get(serverSignature);
			if(Arrays.equals(signature, serverSignature)) {
				logger.info("server response part 2 validation success");
			} else {
				logger.warn("server response part 2 validation failed, probably not Flash Player v9 handshaking");
			}			
		} else {
			// TODO validate if server echoed client request 1			
		}

		// swf verification
		if(session.getSwfHash() != null) {
			byte[] bytesFromServer = new byte[SHA256_DIGEST_LENGTH];
			buf.position(HANDSHAKE_SIZE - SHA256_DIGEST_LENGTH);
			buf.get(bytesFromServer);
			byte[] bytesFromServerHash = calculateHMACSHA256(session.getSwfHash().getBytes(), bytesFromServer);
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
			byte[] randomBytes = new byte[HANDSHAKE_SIZE];
			Random random = new Random();
			random.nextBytes(randomBytes);
			IoBuffer buf = IoBuffer.wrap(randomBytes);
			byte[] digest = calculateHMACSHA256(session.getServerPublicKey(), CLIENT_CONST_CRUD);
			byte[] message = new byte[HANDSHAKE_SIZE - SHA256_DIGEST_LENGTH];
			buf.rewind();
			buf.get(message);
			byte[] signature = calculateHMACSHA256(message, digest);
			buf.put(signature);
			buf.rewind();

			// update 'encoder / decoder state' for the RC4 keys
			// both parties *pretend* as if handshake part 2 (1536 bytes) was encrypted
			// effectively this hides / discards the first few bytes of encrypted session
			// which is known to increase the secure-ness of RC4
			// RC4 state is just a function of number of bytes processed so far
			// that's why we just run 1536 arbitrary bytes through the keys below
			session.getCipherIn().update(randomBytes);
			session.getCipherOut().update(randomBytes);

			RTMPEHandshake hs = new RTMPEHandshake();
			hs.data = buf;
			return hs;
		} else {
			data.get(); // skip first byte
			byte[] bytes = new byte[HANDSHAKE_SIZE];
			data.get(bytes); // copy first half of server response
			RTMPEHandshake hs = new RTMPEHandshake();
			hs.data = IoBuffer.wrap(bytes);
			return hs;
		}
	}

}
