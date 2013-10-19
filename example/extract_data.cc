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

#include <iostream>
#include <swarm.h>
#include <arpa/inet.h>

class IPv4PacketHandler : public swarm::Handler {
 private:
  swarm::NetDec *nd_;

 public:
  explicit IPv4PacketHandler() : nd_(NULL) {}
  void set_netdec(swarm::NetDec *nd) {
    this->nd_ = nd;
  }

  // IPFlow::recv is called when IPv4 packet arrives
  void recv (swarm::ev_id eid, const  swarm::Property &prop) {
    swarm::NetDec *netdec = this->nd_;
    assert(this->nd_);

    // Property Basic
    // ----------------------------
    // Basic function to retrieve decoding result of property is
    // Property::param(). the method requires parameter's name or ID.
    // The following 2 method calls are same meaning.

    // 1) Param * param (const std::string &key) const;
    swarm::Param *p1 = prop.param("ipv4.src");

    // 2) Param * param (const param_id pid) const;
    // This function requires more steps than 1), however the function
    // works faster than 1).
    swarm::param_id pid = netdec->lookup_param_id("ipv4.src");
    swarm::Param *p2 = prop.param(pid);

    // They should be matched
    assert(p1 == p2);
    // Property::Param should return non null value
    assert(p1 != NULL);
    // However if invalid name/pid was passed, it returns NULL
    assert(NULL == prop.param("xxx.yyy"));
    // We can know a number of result by size()
    assert(p1->size() >= 0);


    // Convert
    // ----------------------------
    // class Param provides several format conversion interfaces. Especially
    // Param::repr() provides most apropriate representation format for the
    // data type.
    // see also src/property.h

    if (prop.param("ipv4.src")->size() > 0) {
      printf("--------------------------------------------\n");
      printf("ipv4 src (v4 address): %s\n", prop.param("ipv4.src")->ip4 ().c_str());
      printf("ipv4 src (hex): %s\n", prop.param("ipv4.src")->hex().c_str());
      printf("ipv4 src (uint32): %u\n", prop.param("ipv4.src")->uint32());
      printf("ipv4 src (repr): %s\n", prop.param("ipv4.src")->repr().c_str());

      // Param::get() provides raw pointer and data length from recieved packet
      size_t len;
      const swarm::byte_t *ptr = prop.param("ipv4.src")->get(&len);
      if (ptr) {
        printf("ipv4 src (raw): ");
        for (size_t i = 0; i < len; i++) {
          printf("%d.", ptr[i]);
        }
        printf("\n");
      }
    }

    // 5 tuple
    // ----------------------------
    // Property has 5 tuple (IP src/dst addresses, IP proto, UDP/TCP ports)
    // They can be accessed by
    //  Property::src_addr(), Property::dst_addr()
    //  Property::proto(),
    //  Property::src_port(), Property::dst_port().
    // Additionally, swarm calcurate unsigned 64bit hash value of 5 tuple 
    // that is used to manage IP/UDP/TCP flows. It can be provided by 
    // Property::hash().
    // see also src/property.h

    {
      printf("[%s]:%d -> [%s]:%d (%s) <hash:%016X>\n",
             prop.src_addr().c_str(), prop.src_port(), 
             prop.dst_addr().c_str(), prop.dst_port(),
             prop.proto().c_str(), prop.hash_value());
    
      // you can access raw IP address data also
      size_t len;
      const void * ptr = prop.src_addr(&len);
      if (len == 4) {
        char buf[32];
        ::inet_ntop (AF_INET, ptr, buf, sizeof(buf));
        printf ("ipv4 src address (form inet_ntop): %s\n", buf);
      }
    }
  }
};


int main (int argc, char *argv[]) {
  // Check syntax
  if (argc != 2) {
    printf ("syntax) %s <pcap_file>\n", argv[0]);
    return 1;
  }

  // Create NetDec object and set handler
  swarm::NetDec *nd = new swarm::NetDec ();
  IPv4PacketHandler *ipv4_hdlr = new IPv4PacketHandler ();
  ipv4_hdlr->set_netdec(nd);
  nd->set_handler ("ipv4.packet", ipv4_hdlr);

  // Create NetCap object by CapPcapFile with file path
  swarm::NetCap *nc = new swarm::CapPcapFile (argv[1]);

 // Check status of NetCap object
  if (!nc->ready ()) {
    printf ("error: %s\n", nc->errmsg ().c_str ());
  }

  // Set NetDec object as decoder
  nc->bind_netdec (nd);

  // Start capture and blocking. If fail, it returns false
  if (!nc->start ()) {
    printf ("error: %s\n", nc->errmsg ().c_str ());
  }

  return 0;
}
