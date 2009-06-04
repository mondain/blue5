package ws.blue5.net.rtmpe;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.mina.core.buffer.IoBuffer;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ws.blue5.util.Utils;

public class RTMPEHandshakeTest {

	private static final Logger logger = LoggerFactory.getLogger(RTMPEHandshakeTest.class);
	
	@Test
	public void testGenerateResponse() {
		fail("Not yet implemented");
	}

	@Test
	public void testMain() throws Exception {
		DHParameterSpec paramSpecA = new DHParameterSpec(RTMPEHandshake.DH_MODULUS, RTMPEHandshake.DH_BASE);
		KeyPairGenerator keyGenA = KeyPairGenerator.getInstance("DH");
		keyGenA.initialize(paramSpecA);
		KeyPair keyPairA = keyGenA.generateKeyPair();
		KeyAgreement keyAgreementA = KeyAgreement.getInstance("DH");
		keyAgreementA.init(keyPairA.getPrivate());
		byte[] publicKeyBytesA = RTMPEHandshake.getPublicKey(keyPairA);
		// ==========================================================
		BigInteger publicKeyIntFromA = new BigInteger(1, publicKeyBytesA);
		KeySpec publicKeySpecFromA = new DHPublicKeySpec(publicKeyIntFromA,
				RTMPEHandshake.DH_MODULUS, RTMPEHandshake.DH_BASE);
		KeyFactory keyFactoryB = KeyFactory.getInstance("DH");
		PublicKey publicKeyFromA = keyFactoryB
				.generatePublic(publicKeySpecFromA);
		DHParameterSpec paramSpecB = ((DHPublicKey) publicKeyFromA).getParams();
		KeyPairGenerator keyGenB = KeyPairGenerator.getInstance("DH");
		keyGenB.initialize(paramSpecB);
		KeyPair keyPairB = keyGenB.generateKeyPair();
		KeyAgreement keyAgreementB = KeyAgreement.getInstance("DH");
		keyAgreementB.init(keyPairB.getPrivate());
		keyAgreementB.doPhase(publicKeyFromA, true);
		byte[] publicKeyBytesB = RTMPEHandshake.getPublicKey(keyPairB);
		// ==========================================================
		BigInteger publicKeyIntFromB = new BigInteger(1, publicKeyBytesB);
		KeySpec publicKeySpecFromB = new DHPublicKeySpec(publicKeyIntFromB,
				RTMPEHandshake.DH_MODULUS, RTMPEHandshake.DH_BASE);
		KeyFactory keyFactoryA = KeyFactory.getInstance("DH");
		PublicKey publicKeyFromB = keyFactoryA
				.generatePublic(publicKeySpecFromB);
		keyAgreementA.doPhase(publicKeyFromB, true);
		// ==========================================================
		byte[] sharedSecretA = keyAgreementA.generateSecret();
		byte[] sharedSecretB = keyAgreementB.generateSecret();
		logger.info("A shared secret: " + Utils.toHex(sharedSecretA));
		logger.info("B shared secret: " + Utils.toHex(sharedSecretB));

		byte[] digestA = RTMPEHandshake.calculateHMACSHA256(publicKeyBytesA, sharedSecretA);
		Cipher cipherA = Cipher.getInstance("RC4");
		cipherA.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(digestA, 0, 16,
				"RC4"));

		byte[] digestB = RTMPEHandshake.calculateHMACSHA256(publicKeyBytesA, sharedSecretA);
		Cipher cipherB = Cipher.getInstance("RC4");
		cipherB.init(Cipher.DECRYPT_MODE, new SecretKeySpec(digestB, 0, 16,
				"RC4"));

		byte[] message = "hello world".getBytes();

		cipherA.update(new byte[RTMPEHandshake.HANDSHAKE_SIZE]);
		cipherB.update(new byte[RTMPEHandshake.HANDSHAKE_SIZE]);

		byte[] encrypted = cipherA.update(message);

		byte[] decrypted = cipherB.update(encrypted);

		logger.info("decrypted: " + new String(decrypted));

	}

	@Test
	public void testMain3() throws Exception {
		byte[] client1 = Utils.readAsByteArray("client_handshake_part_1");
		IoBuffer buf = IoBuffer.allocate(RTMPEHandshake.HANDSHAKE_SIZE);
		buf.put(client1, 1, RTMPEHandshake.HANDSHAKE_SIZE);
		buf.flip();

		byte[] dhPointer = RTMPEHandshake.getFourBytesFrom(buf, RTMPEHandshake.HANDSHAKE_SIZE - 4);
		int dhOffset = RTMPEHandshake.getClientDhOffset(dhPointer);
		byte[] clientPublicKey = new byte[128];
		buf.position(dhOffset);
		buf.get(clientPublicKey);

		// ============================================================
		BigInteger publicKeyIntFromA = new BigInteger(1, clientPublicKey);
		KeySpec publicKeySpecFromA = new DHPublicKeySpec(publicKeyIntFromA,
				RTMPEHandshake.DH_MODULUS, RTMPEHandshake.DH_BASE);
		KeyFactory keyFactoryB = KeyFactory.getInstance("DH");
		PublicKey publicKeyFromA = keyFactoryB
				.generatePublic(publicKeySpecFromA);
		DHParameterSpec paramSpecB = ((DHPublicKey) publicKeyFromA).getParams();
		KeyPairGenerator keyGenB = KeyPairGenerator.getInstance("DH");
		keyGenB.initialize(paramSpecB);
		KeyPair keyPairB = keyGenB.generateKeyPair();
		KeyAgreement keyAgreementB = KeyAgreement.getInstance("DH");
		keyAgreementB.init(keyPairB.getPrivate());
		keyAgreementB.doPhase(publicKeyFromA, true);
		byte[] sharedSecret = keyAgreementB.generateSecret();
		logger.info("shared secret: " + Utils.toHex(sharedSecret));

		byte[] digestOut = RTMPEHandshake.calculateHMACSHA256(clientPublicKey, sharedSecret);
		Cipher cipherOut = Cipher.getInstance("RC4");
		cipherOut.init(Cipher.DECRYPT_MODE, new SecretKeySpec(digestOut, 0, 16,
				"RC4"));

		cipherOut.update(new byte[RTMPEHandshake.HANDSHAKE_SIZE]);

		byte[] connect = Utils
				.readAsByteArray("clinet_connect_request_encrypted");
		logger.info("connect encrypted: " + Utils.toHex(connect));
		byte[] plain = cipherOut.update(connect);
		logger.info("connect plain: " + Utils.toHex(plain));

		// ==============================================================

		byte[] server1 = Utils.readAsByteArray("server_handshake_part_1");
		buf = IoBuffer.allocate(RTMPEHandshake.HANDSHAKE_SIZE);
		buf.put(server1, 1, RTMPEHandshake.HANDSHAKE_SIZE);
		buf.flip();

		byte[] digestPointer = RTMPEHandshake.getFourBytesFrom(buf, 8);
		int digestOffset = RTMPEHandshake.getClientDigestOffset(digestPointer);
		buf.rewind();

		int messageLength = RTMPEHandshake.HANDSHAKE_SIZE - RTMPEHandshake.SHA256_DIGEST_LENGTH;
		byte[] message = new byte[messageLength];
		buf.get(message, 0, digestOffset);
		int afterDigestOffset = digestOffset + RTMPEHandshake.SHA256_DIGEST_LENGTH;
		buf.position(afterDigestOffset);
		buf.get(message, digestOffset, RTMPEHandshake.HANDSHAKE_SIZE - afterDigestOffset);
		byte[] digest = RTMPEHandshake.calculateHMACSHA256(message, RTMPEHandshake.SERVER_CONST);
		byte[] serverDigest = new byte[RTMPEHandshake.SHA256_DIGEST_LENGTH];
		buf.position(digestOffset);
		buf.get(serverDigest);

		if (Arrays.equals(digest, serverDigest)) {
			logger.info("type 1 success");
		} else {
			logger.info("type 1 failed");
			throw new RuntimeException("not type 1");
		}

		dhPointer = RTMPEHandshake.getFourBytesFrom(buf, RTMPEHandshake.HANDSHAKE_SIZE - 4);
		dhOffset = RTMPEHandshake.getClientDhOffset(dhPointer);
		buf.position(dhOffset);
		byte[] serverPublicKey = new byte[128];
		buf.get(serverPublicKey);

	}

}
