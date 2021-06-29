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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * This class defines methods to clear arrays and buffers that may
 * contain critical information.
 * 
 * @author Fabio Jun Takada Chino
 * @since 2021.06.28
 */
public class Shredder {

	/**
	 * This method shreds the contents of a given byte array. It
	 * does nothing if value is null.
	 * 
	 * @param value The array to be shredded.
	 */
	public static void shred(byte [] value) {
		if (value != null) {
			for (int i = 0; i < value.length; i++) {
				value[i] = (byte)0;
			}
		}
	}

	/**
	 * This method shreds the contents of a given char array. It
	 * does nothing if value is null.
	 * 
	 * @param value The array to be shredded.
	 */
	public static void shred(char [] value) {
		if (value != null) {
			for (int i = 0; i < value.length; i++) {
				value[i] = (char)0;
			}
		}
	}

	/**
	 * This method shreds the contents of a given byte buffer. It
	 * does nothing if value is null.
	 * 
	 * @param value The buffer to be shredded.
	 */
	public static void shred(ByteBuffer buff) {
		if (buff != null) {
			if (buff.hasArray()) {
				shred(buff.array());
			} else {
				buff.rewind();
				while (buff.hasRemaining()) {
					buff.put((byte)0);
				}
			}
		}
	}
	
	/**
	 * This method shreds the contents of a given char buffer. It
	 * does nothing if value is null.
	 * 
	 * @param value The buffer to be shredded.
	 */
	public static void shred(CharBuffer buff) {
		if (buff != null) {
			if (buff.hasArray()) {
				shred(buff.array());
			} else {
				buff.rewind();
				while (buff.hasRemaining()) {
					buff.put((char)0);
				}
			}
		}
	}	
}
