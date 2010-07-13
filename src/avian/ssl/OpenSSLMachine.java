/* Copyright (c) 2010, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package avian.ssl;

import java.nio.ByteBuffer;

public class OpenSSLMachine implements SSLMachine {
  private enum State {
    ConnectOrAccept, Connected, Closed;
  }

  private static final int ReturnClosed = 0;
  private static final int ReturnWantWrite = 1;
  private static final int ReturnWantRead = 2;

  private long peer;
  private final Mode mode;
  private State state = State.ConnectOrAccept;
  private boolean inUse;
  private boolean close;

  public OpenSSLMachine(long context, Mode mode) {
    peer = natInit(context);
    this.mode = mode;
  }

  public Status run(ByteBuffer netIn, ByteBuffer appIn,
                    ByteBuffer appOut, ByteBuffer netOut)
  {
    final Context context = new Context(netIn, appIn, appOut, netOut);
    boolean progress = true;

    while (progress) {
      progress = false;

      if (state != State.ConnectOrAccept) {
        Status status;
        context.push();
        try {
          status = read(netIn, appIn, appOut, netOut);

          progress |= context.diff();
        } finally {
          context.pop();
        }

        context.handle(status);
      }

      if (state == State.ConnectOrAccept) {
        Status status;
        context.push();
        try {
          status = connectOrAccept(netIn, appIn, appOut, netOut);

          progress |= context.diff();
        } finally {
          context.pop();
        }

        if (status == Status.OK) {
          state = State.Connected;
        }

        context.handle(status);
      }

      if (state == State.Connected) {
        Status status;
        context.push();
        try {
          status = write(netIn, appIn, appOut, netOut);

          progress |= context.diff();
        } finally {
          context.pop();
        }

        context.handle(status);
      }

      System.out.println("close " + close + " appOut.position " + appOut.position() + " netOut.position " + netOut.position() + " context.wantWrite " + context.wantWrite);

      if (close
          && appOut.position() == 0
          && netOut.position() == 0
          && (! context.wantWrite))
      {
        Status status;
        context.push();
        try {
          status = closeOutbound(netIn, appIn, appOut, netOut);

          progress |= context.diff();
        } finally {
          context.pop();
        }

        System.out.println("close status " + status);

        if (status == Status.OK) {
          state = State.Closed;
          status = Status.Closed;
        }

        context.handle(status);
      }
    }

    return context.status();
  }

  public void close() {
    close = true;
  }

  public void dispose() {
    if (inUse) throw new IllegalStateException();

    if (peer != 0) {
      inUse = true;
      try {
        natDispose(peer);
        peer = 0;
      } finally {
        inUse = false;
      }
    }
  }

  // this behaves exactly the same as b.compact(), except it avoids a
  // memory copy if possible, whereas Sun's code calls
  // System.arraycopy no matter what
  private static void compact(ByteBuffer b) {
    if (b.position() != 0 && b.hasRemaining()) {
      b.compact();
    } else {
      b.position(b.remaining());
      b.limit(b.capacity());
    }
  }

  private Status connectOrAccept(ByteBuffer netIn, ByteBuffer appIn,
                                 ByteBuffer appOut, ByteBuffer netOut)
  {
    if (peer == 0) throw new IllegalStateException();
    if (inUse) throw new IllegalStateException();

    inUse = true;
    try {
      netIn.flip();

      boolean[] clearAppIn = new boolean[1];
      int[] netInBytesRead = new int[1];
      int[] netOutBytesWritten = new int[1];

      int r = natSSLConnectOrAccept
        (peer,
         mode == Mode.Client,
         netIn.array(),
         netIn.arrayOffset() + netIn.position(),
         netIn.remaining(),
         netOut.array(),
         netOut.arrayOffset() + netOut.position(),
         netOut.remaining(),
         appIn.capacity() - appIn.remaining(),
         clearAppIn,
         netInBytesRead,
         netOutBytesWritten);

      if (clearAppIn[0]) {
        appIn.position(0);
        appIn.limit(0);
      }

      netIn.position(netIn.position() + netInBytesRead[0]);
      netOut.position(netOut.position() + netOutBytesWritten[0]);

      compact(netIn);

      if (r > 0) {
        return Status.OK;
      } else {
        return translate(natSSLGetError(peer, r));
      }
    } finally {
      inUse = false;
    }
  }

  private Status read(ByteBuffer netIn, ByteBuffer appIn,
                      ByteBuffer appOut, ByteBuffer netOut)
  {
    if (peer == 0) throw new IllegalStateException();
    if (inUse) throw new IllegalStateException();

    inUse = true;
    try {
      if (appIn.remaining() == appIn.capacity()) {
        return Status.OK;
      }
      netIn.flip();
      compact(appIn);

      boolean[] clearAppIn = new boolean[1];
      int[] netInBytesRead = new int[1];
      int[] netOutBytesWritten = new int[1];

      int r = natSSLRead(peer,
                         appIn.array(),
                         appIn.arrayOffset() + appIn.position(),
                         netIn.array(),
                         netIn.arrayOffset() + netIn.position(),
                         netIn.remaining(),
                         netOut.array(),
                         netOut.arrayOffset() + netOut.position(),
                         netOut.remaining(),
                         appIn.remaining(),
                         clearAppIn,
                         netInBytesRead,
                         netOutBytesWritten);

      if (clearAppIn[0]) {
        appIn.clear();
      }

      netIn.position(netIn.position() + netInBytesRead[0]);
      netOut.position(netOut.position() + netOutBytesWritten[0]);

      appIn.flip();
      compact(netIn);

      if (r > 0) {
        appIn.limit(appIn.limit() + r);
        return Status.OK;
      } else {
        return translate(natSSLGetError(peer, r));
      }
    } finally {
      inUse = false;
    }
  }

  private Status write(ByteBuffer netIn, ByteBuffer appIn,
                       ByteBuffer appOut, ByteBuffer netOut)
  {
    if (peer == 0) throw new IllegalStateException();
    if (inUse) throw new IllegalStateException();

    inUse = true;
    try {
      if (appOut.position() == 0) {
        return Status.OK;
      }
      netIn.flip();

      boolean[] clearAppIn = new boolean[1];
      int[] netInBytesRead = new int[1];
      int[] netOutBytesWritten = new int[1];

      int r = natSSLWrite(peer,
                          appOut.array(),
                          appOut.arrayOffset(),
                          appOut.position(),
                          netIn.array(),
                          netIn.arrayOffset() + netIn.position(),
                          netIn.remaining(),
                          netOut.array(),
                          netOut.arrayOffset() + netOut.position(),
                          netOut.remaining(),
                          appIn.capacity() - appIn.remaining(),
                          clearAppIn,
                          netInBytesRead,
                          netOutBytesWritten);

      if (clearAppIn[0]) {
        appIn.position(0);
        appIn.limit(0);
      }

      netIn.position(netIn.position() + netInBytesRead[0]);
      netOut.position(netOut.position() + netOutBytesWritten[0]);

      netIn.compact();

      if (r > 0) {
        appOut.flip().position(r);
        compact(appOut);
        return Status.OK;
      } else {
        return translate(natSSLGetError(peer, r));
      }
    } finally {
      inUse = false;
    }
  }

  private Status closeOutbound(ByteBuffer netIn, ByteBuffer appIn,
                               ByteBuffer appOut, ByteBuffer netOut)
  {
    if (peer == 0) throw new IllegalStateException();
    if (inUse) throw new IllegalStateException();

    inUse = true;
    try {
      netIn.flip();

      boolean[] clearAppIn = new boolean[1];
      int[] netInBytesRead = new int[1];
      int[] netOutBytesWritten = new int[1];
      int r = natSSLShutdown
        (peer,
         netIn.array(),
         netIn.arrayOffset() + netIn.position(),
         netIn.remaining(),
         netOut.array(),
         netOut.arrayOffset() + netOut.position(),
         netOut.remaining(),
         appIn.capacity() - appIn.remaining(),
         clearAppIn,
         netInBytesRead,
         netOutBytesWritten);

      if (clearAppIn[0]) {
        appIn.position(0);
        appIn.limit(0);
      }

      netIn.position(netIn.position() + netInBytesRead[0]);
      netOut.position(netOut.position() + netOutBytesWritten[0]);

      netIn.compact();

      // NB: unlike the other cases, we consider r >= 0 to indicate
      // success here.  See the SSL_shutdown man page for details.
      if (r >= 0) {
        return Status.OK;
      } else {
        return translate(natSSLGetError(peer, r));
      }
    } finally {
      inUse = false;
    }
  }

  private Status translate(int code) {
    switch (code) {
    case ReturnClosed:
      return Status.Closed;
    case ReturnWantWrite:
      return Status.WantWrite;
    case ReturnWantRead:
      return Status.WantRead;
    default:
      throw new RuntimeException("Unknown code " + code);
    }
  }

  private static native long natInit(long context);

  private static native int natSSLGetError(long peer, int r);

  private static native int natSSLConnectOrAccept
    (long peer,
     boolean connect,
     byte[] netIn,
     int netInOffset,
     int netInLength,
     byte[] netOut,
     int netOutOffset,
     int netOutLength,
     int appInLength,
     boolean[] clearAppIn,
     int[] netInBytesRead,
     int[] netOutBytesWritten);

  private static native int natSSLWrite
    (long peer,
     byte[] appOut,
     int appOutOffset,
     int appOutLength,
     byte[] netIn,
     int netInOffset,
     int netInLength,
     byte[] netOut,
     int netOutOffset,
     int netOutLength,
     int appInLength,
     boolean[] clearAppIn,
     int[] netInBytesRead,
     int[] netOutBytesWritten);

  private static native int natSSLRead
    (long peer,
     byte[] appIn,
     int appInOffset,
     byte[] netIn,
     int netInOffset,
     int netInLength,
     byte[] netOut,
     int netOutOffset,
     int netOutLength,
     int appInLength,
     boolean[] clearAppIn,
     int[] netInBytesRead,
     int[] netOutBytesWritten);

  private static native int natSSLShutdown
    (long peer,
     byte[] netIn,
     int netInOffset,
     int netInLength,
     byte[] netOut,
     int netOutOffset,
     int netOutLength,
     int appInLength,
     boolean[] clearAppIn,
     int[] netInBytesRead,
     int[] netOutBytesWritten);

  private static native void natDispose(long peer);

  private static class Context {
    public int pushCount;

    public final ByteBuffer netIn;
    public int netInPosition;
    public final ByteBuffer netOut;
    public int netOutPosition;
    public final ByteBuffer appIn;
    public int appInPosition;
    public final ByteBuffer appOut;
    public int appOutPosition;

    public boolean wantWrite;
    public boolean wantRead;
    public boolean closed;

    public Context(ByteBuffer netIn, ByteBuffer appIn,
                   ByteBuffer appOut, ByteBuffer netOut)
    {
      this.netIn = netIn;
      this.appIn = appIn;
      this.appOut = appOut;
      this.netOut = netOut;
    }

    public void push() {
      if (pushCount != 0) throw new IllegalStateException();

      ++ pushCount;

      netInPosition = netIn.position();
      netOutPosition = netOut.position();
      appInPosition = appIn.position();
      appOutPosition = appOut.position();
    }

    public void pop() {
      if (pushCount != 1) throw new IllegalStateException();

      -- pushCount;
    }

    public boolean diff() {
      if (pushCount != 1) throw new IllegalStateException();

      return appInPosition != appIn.position()
        || appOutPosition != appOut.position()
        || netInPosition != netIn.position()
        || netOutPosition != netOut.position();
    }

    public Status status() {
      if (closed) {
        return Status.Closed;
      } else if (wantWrite) {
        return Status.WantWrite;
      } else if (wantRead) {
        return Status.WantRead;
      } else {
        return Status.OK;
      }
    }

    public void handle(Status status) {
      switch (status) {
      case OK: break;

      case WantWrite: {
        wantWrite = true;
      } break;

      case WantRead: {
        wantRead = true;
      } break;

      case Closed: {
        closed = true;
      } break;

      default: throw new IllegalArgumentException
          ("unexpected status: " + status);
      }
    }
  }

}
