/* Copyright (c) 2010, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package avian.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

public class SSLChannel implements ReadableByteChannel, WritableByteChannel {
  private final ReadableByteChannel in;
  private final WritableByteChannel out;
  private final SSLMachine machine;
  private final ByteBuffer netIn;
  private final ByteBuffer appIn;
  private final ByteBuffer appOut;
  private final ByteBuffer netOut;
  private boolean closedMachine;

  public SSLChannel(ReadableByteChannel in, WritableByteChannel out,
                    SSLContext context, SSLMachine.Mode mode,
                    int minBufferSize)
  {
    this.in = in;
    this.out = out;

    netIn = ByteBuffer.allocate
      (Math.max(minBufferSize, context.minNetInBufferSize()));

    appIn = ByteBuffer.allocate
      (Math.max(minBufferSize, context.minAppInBufferSize()));

    appOut = ByteBuffer.allocate
      (Math.max(minBufferSize, context.minAppOutBufferSize()));

    netOut = ByteBuffer.allocate
      (Math.max(minBufferSize, context.minNetOutBufferSize()));

    appIn.limit(0);

    this.machine = context.makeMachine(mode);
  }

  private static int copy(ByteBuffer src, ByteBuffer dst) {
    return copy(src, dst, Integer.MAX_VALUE);
  }

  private static int copy(ByteBuffer src, ByteBuffer dst, int max) {
    int oldLimit = src.limit();
    int c = Math.min(max, Math.min(dst.remaining(), src.remaining()));
    src.limit(src.position() + c);
    dst.put(src);
    src.limit(oldLimit);
    return c;
  }

  private SSLMachine.Status run(boolean wantAppRead) throws IOException {
    System.out.println("run");
    while (isOpen()) {
      System.out.println("before: netIn " + netIn.remaining()
                         + " netOut " + netOut.remaining()
                         + " appIn " + appIn.remaining()
                         + " appOut " + appOut.remaining());

      SSLMachine.Status status = machine.run(netIn, appIn, appOut, netOut);

      System.out.println("status " + status + " netIn " + netIn.remaining()
                         + " netOut " + netOut.remaining()
                         + " appIn " + appIn.remaining()
                         + " appOut " + appOut.remaining());

      if (wantAppRead && appIn.hasRemaining()) {
        return SSLMachine.Status.OK;
      }

      if (isOpen() && netOut.position() > 0) {
        netOut.flip();
        System.out.println("write " + netOut.remaining());
        int c = out.write(netOut);
        System.out.println("wrote " + c);
        netOut.compact();
        continue;
      }
      
      switch (status) {
      case OK:
        return status;

      case Closed:
        close();
        return status;

      case WantWrite:
        break;

      case WantRead: {
        if (isOpen() && netIn.hasRemaining()) {
          System.out.println("read " + netIn.remaining());
          int c = in.read(netIn);
          if (c == -1) {
            in.close();
          }
          System.out.println("did read " + c);
        }
      } break;

      default:
        throw new RuntimeException("unexpected status: " + status);
      }
    }

    return SSLMachine.Status.Closed;
  }

  public int read(ByteBuffer b) throws IOException {
    while (isOpen() && ! appIn.hasRemaining()) {
      run(true);
    }
      
    if (appIn.hasRemaining()) {
      return copy(appIn, b);
    } else {
      return -1;
    }
  }

  public int write(ByteBuffer b) throws IOException {
    int c = 0;
    while (isOpen() && b.hasRemaining()) {
      while (isOpen() && ! appOut.hasRemaining()) {
        if (run(false) != SSLMachine.Status.OK) {
          throw new IOException();
        }
      }
      
      if (appOut.hasRemaining()) {
        c += copy(b, appOut);
      } else {
        throw new IOException();
      }
    }
    return c;
  }

  public void close() throws IOException {
    if (! closedMachine) {
      closedMachine = true;
      machine.close();
      while (run(false) != SSLMachine.Status.Closed) { }
      machine.dispose();
    }
    in.close();
    out.close();
  }

  public boolean isOpen() {
    return in.isOpen() && out.isOpen();
  }
}
