package br.com.opencs.benri.obfuscator;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.junit.Test;

public class StringObfuscatorImplTest {

	private static final byte [] SAMPLE_SALT = {(byte)0x74, (byte)0x60, (byte)0x51, (byte)0x8E, (byte)0xB1, (byte)0x74, (byte)0x1D, (byte)0x7B, (byte)0xE7, (byte)0xB2, (byte)0x91, (byte)0x48, (byte)0x28, (byte)0xB9, (byte)0x70, (byte)0x11, (byte)0xAB, (byte)0xDB, (byte)0x01, (byte)0xF2, (byte)0xE6, (byte)0xE9, (byte)0x4F, (byte)0xF9, (byte)0x54, (byte)0x49, (byte)0x0A, (byte)0x5C, (byte)0x74, (byte)0xBE, (byte)0x55, (byte)0x54};
	private static final int SAMPLE_ITERATIONS = 1000;
	private static final char [] SAMPLE_PASSWORD = "password".toCharArray();
	private static final byte [] SAMPLE_KEY_256 = {(byte)0x48, (byte)0x4A, (byte)0x24, (byte)0x28, (byte)0x6A, (byte)0xF5, (byte)0x50, (byte)0xD7, (byte)0x3D, (byte)0xF6, (byte)0x5E, (byte)0x32, (byte)0x75, (byte)0x30, (byte)0x52, (byte)0xBC, (byte)0x3C, (byte)0x39, (byte)0x01, (byte)0xD0, (byte)0x0F, (byte)0xCD, (byte)0xE1, (byte)0x06, (byte)0x16, (byte)0xAE, (byte)0xAF, (byte)0x2C, (byte)0x6E, (byte)0x14, (byte)0xC1, (byte)0xD1};
	
	@Test
	public void testStringObfuscatorImplByteArrayCharArray() throws Exception {
		StringObfuscatorImpl o = new StringObfuscatorImpl(SAMPLE_SALT, SAMPLE_PASSWORD);
		assertNotNull(o);
	}

	@Test
	public void testStringObfuscatorImplByteArrayIntCharArray() throws Exception {
		StringObfuscatorImpl o = new StringObfuscatorImpl(SAMPLE_SALT, 10000, SAMPLE_PASSWORD);
		assertNotNull(o);
	}

	@Test
	public void testGenerateKey() throws Exception {
		
		byte [] p = StringObfuscatorImpl.generateKey(SAMPLE_SALT, SAMPLE_ITERATIONS, SAMPLE_PASSWORD, 256);
		assertArrayEquals(SAMPLE_KEY_256, p);
	}

	@Test
	public void testObfuscateDeobfuscate() throws Exception {
		StringObfuscatorImpl o1 = new StringObfuscatorImpl(SAMPLE_SALT, 1000, SAMPLE_PASSWORD);
		StringObfuscatorImpl o2 = new StringObfuscatorImpl(SAMPLE_SALT, 2000, SAMPLE_PASSWORD);

		String s1 = o1.obfuscate(SAMPLE_PASSWORD);
		String s2 = o1.obfuscate(SAMPLE_PASSWORD);
		assertNotEquals(s1, s2);
		
		char [] d1 = o1.deobfuscate(s1);
		char [] d2 = o1.deobfuscate(s2);
		assertArrayEquals(SAMPLE_PASSWORD, d1);
		assertArrayEquals(SAMPLE_PASSWORD, d2);
		
		String s3 = o2.obfuscate(SAMPLE_PASSWORD);
		try {
			o1.deobfuscate(s3);
			fail();
		} catch (StringObfuscatorException e) {}
		
		try {
			o1.deobfuscate(s1.substring(1));
			fail();
		} catch (StringObfuscatorException e) {}
		
		try {
			o1.deobfuscate(s1.substring(0, s1.length() - 1));
			fail();
		} catch (StringObfuscatorException e) {}		
		
		try {
			StringBuilder sb = new StringBuilder(s1);
			sb.setCharAt(5, (char)(sb.charAt(5) + 1));
			o1.deobfuscate(sb.toString());
			fail();
		} catch (StringObfuscatorException e) {}
		
		try {
			StringBuilder sb = new StringBuilder(s1);
			int tamperIdx = sb.length() - 1;
			sb.setCharAt(tamperIdx, (char)(sb.charAt(tamperIdx) + 1));
			o1.deobfuscate(sb.toString());
			fail();
		} catch (StringObfuscatorException e) {}			
	}
}
