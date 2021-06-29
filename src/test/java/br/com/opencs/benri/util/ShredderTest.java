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
package br.com.opencs.benri.util;

import static org.junit.Assert.assertArrayEquals;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Random;

import org.junit.Test;

public class ShredderTest {
	
	private byte [] randomBytes(int count) {
		Random random = new Random();
		byte [] tmp = new byte[count];
		random.nextBytes(tmp);
		return tmp;
	}
	
	private char [] randomChars(int count) {
		Random random = new Random();
		char [] tmp = new char[count];
		for (int i = 0; i < tmp.length; i++) {
			tmp[i] = (char)(random.nextInt(127 - 32) + 32);
		}
		return tmp;
	}
	

	@Test
	public void testShredByteArray() {
		byte [] tmp = randomBytes(16);
		
		Shredder.shred(tmp);
		assertArrayEquals(new byte[tmp.length], tmp);
	
		Shredder.shred((byte [])null);		
	}

	@Test
	public void testShredCharArray() {
		char [] tmp = randomChars(16);
		
		Shredder.shred(tmp);
		assertArrayEquals(new char[tmp.length], tmp);
	
		Shredder.shred((char [])null);
	}

	@Test
	public void testShredByteBuffer() {
		ByteBuffer buff;
		
		buff = ByteBuffer.allocate(16);
		buff.put(randomBytes(16));
		Shredder.shred(buff);
		assertArrayEquals(new byte[16], buff.array());		
		
		buff = ByteBuffer.allocateDirect(16);
		buff.put(randomBytes(16));
		Shredder.shred(buff);
		
		byte [] tmp = new byte[16];
		buff.rewind();
		buff.get(tmp);
		assertArrayEquals(new byte[16], tmp);
		
		Shredder.shred((ByteBuffer)null);		
	}

	@Test
	public void testShredCharBuffer() {
		CharBuffer buff;
		
		buff = CharBuffer.allocate(16);
		buff.put(randomChars(16));
		Shredder.shred(buff);
		assertArrayEquals(new char[16], buff.array());		
		
		buff = ByteBuffer.allocate(32).asCharBuffer();
		buff.put(randomChars(16));
		Shredder.shred(buff);
		
		char [] tmp = new char[16];
		buff.rewind();
		buff.get(tmp);
		assertArrayEquals(new char[16], tmp);
		
		Shredder.shred((CharBuffer)null);	
	}

}
