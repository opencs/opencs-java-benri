/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2021, Open Communications Security 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package br.com.opencs.benri.obfuscator;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import br.com.opencs.benri.util.Shredder;

/**
 * This class implements a very simple String obfuscator loosely based on the
 * concepts of <b>Fernet</b> from the 
 * <a href="https://cryptography.io/en/latest/fernet/">Python Cryptography Library</a>.
 * 
 * <p>It uses a PBE based key (defined by the caller application) that is used to
 * cipher the strings using an AES 256-bit key in 
 * <a href="https://en.wikipedia.org/wiki/Galois/Counter_Mode">GCM</a> cipher mode.
 * This guarantees both secrecy and integrity with a single single key.</p>
 * 
 * <h2>How to use it</h2>
 * 
 * <p>Just define a value for the IV and the password, create an instance of
 * this class and use it to obfuscate and deobfuscate the strings.</p>
 * 
 * <p>As long as the IV and the password remains the same, the obfuscator
 * will be compatible with each other.</p>
 *
 * <h2>Security hints</h2>
 * 
 * <p>For security reasons, it is up to the caller application the protection of
 * the IV and the key values used to initialize each instance. It is also important
 * to keep those 2 values separated from the obfuscated data (e.g.: IV and password
 * inside the code, obfuscated strings inside the database).</p>
 * 
 * <p>It is also recommended to change the values for IV and password for each
 * distinct application, thus the reveal of those values for a given application
 * will not immediately compromise other applications.</p>
 * 
 * <h2>Performance</h2>
 * 
 * <p>The obfuscation and deobfuscation operations are very fast and can be used
 * repeatedly with no problems. However, the initialization procedure (constructor)
 * can be very slow. Because of that, it is strongly recommended to avoid the
 * construction of this class as much as possible.</p>
 * 
 * <h2>Thread safety</h2>
 * 
 * <p>Instances of this class are guaranteed to be thread safe thus can be used
 * as a singleton if necessary.</p>
 * 
 * @author Fabio Jun Takada Chino
 * @since 2021.06.28
 */
public class StringObfuscatorImpl implements StringObfuscator {
	/**
	 * The header of this format. Always "GCM1".
	 */
	public static final String HEADER = "GCM1";
	
	private static final Charset CHARSET = Charset.forName("utf-8");
	private static final int TAG_SIZE = 128;
	private static final int CIPHER_KEY_SIZE = 256;
	private static final int CIPHER_BLOCK_SIZE = 128;
	private static final String PBE_ALG = "PBKDF2WithHmacSHA256";
	private static final String CIPHER_ALG = "AES";
	private static final String CIPHER_ALG_FULL = CIPHER_ALG + "/GCM/PKCS5Padding";

	private SecretKey cipherKey;
	
	private SecureRandom random = new SecureRandom();
	
	/**
	 * Creates a new instance of this class. By default, it sets the number of iterations to 10,000.
	 * 
	 * @param salt The PBE salt. It is recommended to have at least 32 bytes.
	 * @param password The PBE password. It should be as long as possible.
	 * @throws StringObfuscatorException In case of errors in the initialization.
	 * @throws GeneralSecurityException If the encryption operations are not supported.
	 */
	public StringObfuscatorImpl(byte [] salt, char [] password) throws StringObfuscatorException, GeneralSecurityException {
		this(salt, 10000, password);		
	}
	
	/**
	 * Creates a new instance of this class.
	 * 
	 * @param salt The PBE salt. It is recommended to have at least 32 bytes.
	 * @param iterations The number of iterations for PBE. Set it to a higher value to make the password derivation more expensive. 
	 * @param password The PBE password. It should be as long as possible.
	 * @throws StringObfuscatorException In case of errors in the initialization.
	 * @throws GeneralSecurityException If the encryption operations are not supported.
	 */
	public StringObfuscatorImpl(byte [] salt, int iterations, char [] password) throws StringObfuscatorException, GeneralSecurityException {
		generateKeys(salt, iterations, password);
	}

	private byte [] createIv() {
		byte [] salt = new byte[CIPHER_BLOCK_SIZE / 8];
		synchronized (random) {
			random.nextBytes(salt);
		}
		return salt;
	}
	
	private void generateKeys(byte [] salt, int iterations, char [] password) throws GeneralSecurityException {
		byte [] key = null;
		
		try {
			key = generateKey(salt, iterations, password, CIPHER_KEY_SIZE);
			cipherKey = new SecretKeySpec(key, CIPHER_ALG);
		} finally {
			Shredder.shred(key);
		}
	}

	/**
	 * Generates a key material using the PBE parameters.
	 * 
	 * @param salt The salt.
	 * @param iterations The number of iterations.
	 * @param password The password.
	 * @param keySize The key size in bits.
	 * @return The key material in bytes.
	 * @throws GeneralSecurityException In case of error.
	 */
	protected static byte[] generateKey(byte [] salt, int iterations, char [] password, int keySize) throws GeneralSecurityException {
		SecretKeyFactory generator = SecretKeyFactory.getInstance(PBE_ALG);
		PBEKeySpec params = new PBEKeySpec(password, salt, iterations, keySize);
		
		SecretKey key = generator.generateSecret(params);

		return key.getEncoded();
	}
	
	private byte[] toBytes(char [] value) {
		return CHARSET.encode(CharBuffer.wrap(value)).array();
	}
	
	private char[] fromBytes(byte [] value, int offset, int count) {
		ByteBuffer buff = ByteBuffer.wrap(value);
		buff.position(offset);
		buff.limit(offset + count);
		CharBuffer ret = CHARSET.decode(buff);
		try {
			return ret.array().clone();
		} finally {
			Shredder.shred(ret);
		}
	}
	
	private Cipher createCipher(boolean cipher, byte [] iv, int offset, int count) throws GeneralSecurityException {
		Cipher c = Cipher.getInstance(CIPHER_ALG_FULL);
		GCMParameterSpec params = new GCMParameterSpec(TAG_SIZE, iv, offset, count);
		c.init(cipher?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE, cipherKey, params);
		return c;
	}
	

	public String obfuscate(char [] value)  throws StringObfuscatorException{
		byte [] iv = createIv();
		byte [] raw = null;
		
		try {
			Cipher c = createCipher(true, iv, 0, iv.length);
			raw = toBytes(value);
			byte [] enc = c.doFinal(raw);
			byte [] full = new byte[iv.length + enc.length];
			System.arraycopy(iv, 0, full, 0, iv.length);
			System.arraycopy(enc, 0, full, iv.length, enc.length);
			return HEADER + Base64.getUrlEncoder().encodeToString(full);
		} catch (GeneralSecurityException e) {
			throw new StringObfuscatorException(e.getMessage(), e);
		} finally {
			Shredder.shred(raw);
		}
	}
	

	public char [] deobfuscate(String obfuscated) throws StringObfuscatorException {
		if (!obfuscated.startsWith(HEADER)) {
			throw new StringObfuscatorException("Invalid format.");
		}
		byte [] dec = null;
		try {
			byte [] bin = Base64.getUrlDecoder().decode(obfuscated);
			Cipher c = createCipher(false, bin, 3, CIPHER_BLOCK_SIZE / 8);
			int encOffset = CIPHER_BLOCK_SIZE / 8 + 3;
			dec = c.doFinal(bin, encOffset, bin.length - encOffset);
			return fromBytes(dec, 0, dec.length);			
		} catch (IllegalArgumentException e) {
			throw new StringObfuscatorException("Invalid format.", e);
		} catch (AEADBadTagException e) {
			throw new StringObfuscatorException("Invalid format/key.");
		} catch (GeneralSecurityException e) {
			throw new StringObfuscatorException(e.getMessage(), e);			
		} finally {
			Shredder.shred(dec);
		}
	}
}
