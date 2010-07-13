/* Copyright (c) 2010, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package avian.ssl;

import java.util.Collection;
import java.util.ArrayList;
import java.io.IOException;
import java.io.StreamCorruptedException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

public class SSLUtil {
  private static final byte[] decodeTable = new byte[256];

  static {
    int j = 0;
    for (int i = 'A'; i <= 'Z'; ++i) decodeTable[i] = (byte) j++;
    for (int i = 'a'; i <= 'z'; ++i) decodeTable[i] = (byte) j++;
    for (int i = '0'; i <= '9'; ++i) decodeTable[i] = (byte) j++;
    decodeTable['+'] = (byte) j++;
    decodeTable['/'] = (byte) j++;
    decodeTable['='] = 0;
  }

  private static void decode(byte[] in, byte[] out) {
    int oi = 0;
    int ii = 0;
    while (ii < in.length) {
      int x = ((decodeTable[in[ii++]] << 18) |
               (decodeTable[in[ii++]] << 12) |
               (decodeTable[in[ii++]] <<  6) |
               (decodeTable[in[ii++]]));

      out[oi++] = (byte) ((x >> 16)       );
      out[oi++] = (byte) ((x >>  8) & 0xFF);
      out[oi++] = (byte) ((x      ) & 0xFF);
    }
  }

  private static ByteBuffer decode(byte[] in) {
    byte[] out = new byte[(3 * in.length) / 4];
    decode(in, out);
    int pad = 0;
    if (in[in.length - 1] == '=') {
      ++ pad;
      if (in[in.length - 2] == '=') {
        ++ pad;
      }
    }
    return ByteBuffer.wrap(out, 0, out.length - pad);
  }

  private static void skipLine(InputStream in) throws IOException {
    while (true) {
      switch (in.read()) {
      case '\n':
      case -1:
        return;
      }
    }
  }

  private static void readLine(InputStream in, OutputStream out)
    throws IOException
  {
    while (true) {
      int c = in.read();
      switch (c) {
      case ' ':
      case '\r':
      case '\t':
        break;

      case '\n':
      case -1:
        return;

      default:
        out.write(c);
      }
    }
  }

  public static ByteBuffer pemToDer(InputStream in) throws IOException {
    return pemsToDers(in, 1).iterator().next();
  }

  public static Collection<ByteBuffer> pemsToDers(InputStream in)
    throws IOException
  {
    return pemsToDers(in, Integer.MAX_VALUE);
  }

  private static Collection<ByteBuffer> pemsToDers(InputStream in, int limit)
    throws IOException
  {
    Collection<ByteBuffer> ders = new ArrayList();
    ByteArrayOutputStream der = null;

    in = new BufferedInputStream(in);
    loop: while (ders.size() < limit) {
      int c = in.read();
      switch (c) {
      case '-':
        skipLine(in);
        if (der == null) {
          der = new ByteArrayOutputStream();
        } else {
          if (der.size() > 0) {
            ders.add(decode(der.toByteArray()));
          }
          der = null;
        }
        break;

      case -1:
        if (der == null) {
          break loop;
        } else {
          throw new StreamCorruptedException();
        }

      default:
        if (der == null) {
          skipLine(in);
        } else {
          der.write(c);
          readLine(in, der);
        }
        break;
      }
    }

    return ders;
  }
}
