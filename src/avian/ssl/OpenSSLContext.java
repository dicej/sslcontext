/* Copyright (c) 2010, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package avian.ssl;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.StringTokenizer;

public class OpenSSLContext implements SSLContext {
  private long state;

  static {
    System.loadLibrary("sslcontext");
    globalInit();
  }

  public OpenSSLContext(String ciphers,
                        ByteBuffer key,
                        Collection<ByteBuffer> certificateChain,
                        Collection<ByteBuffer> trustedCertificates)
  {
    state = makeState
      (translateCiphers(ciphers), toByteArray(key), toArrays(certificateChain),
       toArrays(trustedCertificates));
  }

  public int minNetInBufferSize() {
    return 8 * 1024;
  }

  public int minAppInBufferSize() {
    return 8 * 1024;
  }

  public int minAppOutBufferSize() {
    return 8 * 1024;
  }

  public int minNetOutBufferSize() {
    // OpenSSL doesn't like a tiny network output buffer:
    return (16 * 1024) + 64;
  }

  private static byte[] toByteArray(ByteBuffer b) {
    if (b == null) {
      return null;
    } else {
      byte[] array = new byte[b.remaining()];
      System.arraycopy
        (b.array(), b.arrayOffset() + b.position(), array, 0, array.length);
      return array;
    }
  }

  private static Object[] toArrays(Collection<ByteBuffer> c) {
    if (c == null) {
      return null;
    } else {
      Object[] arrays = new Object[c.size()];
      int i = 0;
      for (ByteBuffer b: c) {
        arrays[i++] = toByteArray(b);
      }
      return arrays;
    }
  }

  private static String translateCiphers(String ciphers) {
    StringBuilder sb = new StringBuilder();
    for (StringTokenizer st = new StringTokenizer(ciphers, ":");
         st.hasMoreTokens();)
    {
      sb.append(translateCipher(st.nextToken()));
      if (st.hasMoreTokens()) {
        sb.append(":");
      }
    }
    return sb.toString();
  }

  private static String translateCipher(String cipher) {
    if (cipher.equals("TLS_DH_anon_WITH_AES_256_CBC_SHA")) {
      return "ADH-AES256-SHA";
    } else if (cipher.equals("TLS_RSA_WITH_AES_256_CBC_SHA")) {
      return "AES256-SHA";
    } else if (cipher.equals("TLS_RSA_WITH_AES_128_CBC_SHA")) {
      return "AES128-SHA";
    } else if (cipher.equals("SSL_RSA_WITH_RC4_128_SHA")) {
      return "RC4-SHA";
    } else {
      throw new RuntimeException("unknown cipher: " + cipher);
    }
  }

  public SSLMachine makeMachine(SSLMachine.Mode mode) {
    return new OpenSSLMachine(state, mode);
  }

  private static native long makeState(String ciphers,
                                       byte[] key,
                                       Object[] certificateChain,
                                       Object[] trustedCertificates);

  private static native void globalInit();

  private static native void natDispose(long state);

  public void dispose() {
    natDispose(state);
    state = 0;
  }
}
