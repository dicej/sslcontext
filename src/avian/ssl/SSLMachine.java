/* Copyright (c) 2010, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package avian.ssl;

import java.nio.ByteBuffer;

public interface SSLMachine {
  public enum Status {
    OK, WantWrite, WantRead, Closed;
  }

  public enum Mode {
    Client, Server;
  }

  public Status run(ByteBuffer netIn, ByteBuffer appIn,
                    ByteBuffer appOut, ByteBuffer netOut);

  public void close();

  public void dispose();
}