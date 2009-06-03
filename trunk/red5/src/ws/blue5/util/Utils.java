package ws.blue5.util;

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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;

import org.apache.mina.core.buffer.IoBuffer;

/**
 * Utility class for manipulation of various types of data. 
 */
public class Utils {

	public static int readInt24(IoBuffer in) {
		final byte a = in.get();
		final byte b = in.get();
		final byte c = in.get();
		int val = 0;
		if (a < 0) {
			val += ((a + 256) << 16);
		} else {
			val += (a << 16);
		}
		if (b < 0) {
			val += ((b + 256) << 8);
		} else {
			val += (b << 8);
		}
		if (c < 0) {
			val += c + 256;
		} else {
			val += c;
		}
		return val;
	}

	public static void writeInt24(IoBuffer out, int value) {
		out.put((byte) (0xFF & (value >> 16)));
		out.put((byte) (0xFF & (value >> 8)));
		out.put((byte) (0xFF & (value >> 0)));
	}

	public static int readInt32Reverse(IoBuffer in) {
		final byte a = in.get();
		final byte b = in.get();
		final byte c = in.get();
		final byte d = in.get();
		int val = 0;
		val += d << 24;
		val += c << 16;
		val += b << 8;
		val += a;
		return val;
	}

	public static void writeInt32Reverse(IoBuffer out, int value) {
		out.put((byte) (0xFF & value));
		out.put((byte) (0xFF & (value >> 8)));
		out.put((byte) (0xFF & (value >> 16)));
		out.put((byte) (0xFF & (value >> 24)));
	}

	private static final char[] HEX_DIGITS = { '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	private static final char BYTE_SEPARATOR = ' ';

	public static String toHex(byte[] ba) {
		return toHex(ba, true);
	}

	public static String toHex(byte[] ba, boolean withSeparator) {
		return toHex(ba, 0, ba.length, withSeparator);
	}

	public static String toHex(byte[] ba, int offset, int length,
			boolean withSeparator) {
		char[] buf;
		if (withSeparator) {
			buf = new char[length * 3];
		} else {
			buf = new char[length * 2];
		}
		char[] chars;
		for (int i = offset, j = 0; i < offset + length;) {
			chars = toHexChars(ba[i++]);
			buf[j++] = chars[0];
			buf[j++] = chars[1];
			if (withSeparator) {
				buf[j++] = BYTE_SEPARATOR;
			}
		}
		return new String(buf);
	}

	private static char[] toHexChars(int b) {
		char left = HEX_DIGITS[(b >>> 4) & 0x0F];
		char right = HEX_DIGITS[b & 0x0F];
		return new char[] { left, right };
	}

	public static String toHex(byte b) {
		char[] chars = toHexChars(b);
		return chars[0] + "" + chars[1];
	}

	public static byte[] fromHex(char[] hex) {
		int length = hex.length / 2;
		byte[] raw = new byte[length];
		for (int i = 0; i < length; i++) {
			int high = Character.digit(hex[i * 2], 16);
			int low = Character.digit(hex[i * 2 + 1], 16);
			int value = (high << 4) | low;
			if (value > 127) {
				value -= 256;
			}
			raw[i] = (byte) value;
		}
		return raw;
	}

	public static byte[] fromHex(String s) {
		String temp = s.replace(" ", "");
		return fromHex(temp.toCharArray());
	}

	public static IoBuffer removeChunkDelimiters(final byte[] bytes,
			final int chunkSize) {
		IoBuffer buffer = IoBuffer.allocate(bytes.length);
		int i = 0;
		for (byte b : bytes) {
			if (i == chunkSize) {
				i = 0;
				continue;
			}
			buffer.put(b);
			i++;
		}
		buffer.flip();
		return buffer;
	}

	public static IoBuffer toIoBuffer(final char[] chars, final int chunkSize) {
		byte[] bytes = new byte[chars.length];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) chars[i];
		}
		return removeChunkDelimiters(bytes, chunkSize);
	}

	public static CharSequence readAsString(String fileName) {
		return readAsString(new File(fileName));
	}

	public static CharSequence readAsString(File file) {
		StringBuilder sb = new StringBuilder();
		try {
			FileInputStream fis = new FileInputStream(file);
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					fis));
			String s;
			while ((s = reader.readLine()) != null) {
				sb.append(s);
			}
			return sb;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static byte[] readAsByteArray(String fileName) {
		File file = new File(fileName);
		return readAsByteArray(file, file.length());
	}

	public static byte[] readAsByteArray(String fileName, int length) {
		return readAsByteArray(new File(fileName), length);
	}

	public static byte[] readAsByteArray(File file) {
		return readAsByteArray(file, file.length());
	}

	public static byte[] readAsByteArray(File file, long length) {
		try {
			byte[] bytes = new byte[(int) length];
			int offset = 0;
			int numRead = 0;
			FileInputStream is = new FileInputStream(file);
			while (offset < bytes.length
					&& (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
				offset += numRead;
			}
			is.close();
			return bytes;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
