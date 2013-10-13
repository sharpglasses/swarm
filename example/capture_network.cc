/*-
 * Copyright (c) 2013 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <swarm.h>

class IPFlow : public swarm::Handler {
 public:
  // IPFlow::recv is called when IPv4 packet arrives
  void recv (swarm::ev_id eid, const  swarm::Property &p) {
    std::string src, dst;
    src = p.param("ipv4.src")->repr ();
    dst = p.param("ipv4.dst")->repr ();
    printf ("%s -> %s\n", src.c_str (), dst.c_str ());
  }
};


int main (int argc, char *argv[]) {
  // Check syntax
  if (argc != 2) {
    printf ("syntax) %s <network_interface>\n", argv[0]);
    return 1;
  }

  // Create NetDec object and set handler
  swarm::NetDec *nd = new swarm::NetDec ();
  nd->set_handler ("ipv4.packet", new IPFlow ());

  // Create NetCap object by CapPcapFile with file path
  swarm::NetCap *nc = new swarm::CapPcapDev (argv[1]);

 // Check status of NetCap object
  if (!nc->ready ()) {
    printf ("error: %s\n", nc->errmsg ().c_str ());
    return 1;
  }

  // Set NetDec object as decoder
  nc->bind_netdec (nd);
 
  // Start capture and blocking. If fail, it returns false
  if (!nc->start ()) {
    printf ("error: %s\n", nc->errmsg ().c_str ());
  }

  return 0;
}
