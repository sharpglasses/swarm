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

class MyIcmpFlow : public swarm::Handler {
 public:
  // MyIcmpFlow::recv is called when ICMP packet arrives
  void recv (swarm::ev_id eid, const  swarm::Property &p) {
    std::string src, dst;
    src = p.param("ipv4.src")->repr ();
    dst = p.param("ipv4.dst")->repr ();

    printf ("%s -> %s type:%d\n", src.c_str (), dst.c_str (),
            p.param("my_icmp.type")->int32());
  }
};

//
// Basic workflow overview:
// 1) Install the module object to NetDec instance by NetDec::load_decoder
// 2) Call Constructor of the module in order to assing event & parameter name
// 3) Call setup() of the module in order to obtain other module's ID
// 4) Incoming packets by data input function such as NetCap::start()
// 5) Call accept() of the module in order to determine if acceptable packet
// 6) Call decode() of the module in order to parse the packet and extract 
//    parameter(s) and set event(s) to swarm::Property object.
// 7) Back to 4)
//

class MyIcmpDecoder : public swarm::Decoder {
private:
  struct icmp_header {
    u_int8_t type_;
    u_int8_t code_;
    u_int16_t checksum_;
  } __attribute__((packed));

  swarm::ev_id EV_ICMP_PKT_;
  swarm::param_id P_TYPE_, P_CODE_, P_PROTO_;
  swarm::dec_id D_IPV4_;

public:
  // The constructor of class that is extended from swarm::Decoder should
  // do 2 things:
  //  1) Assign event name and description by NetDec::assign_event()
  //  2) Assign parameter name adn description by NetDec::assign_param()
  // The assign methods return event ID (swarm::ev_id) and parameter ID
  // (swarm::param_id). They should be used to set parameter of property and
  // manage event to property (see also Property::set(), Property::push_event())
  //
  explicit MyIcmpDecoder (swarm::NetDec * nd) : swarm::Decoder (nd) {
    this->EV_ICMP_PKT_ = nd->assign_event ("my_icmp.packet", "ICMP Packet");
    this->P_TYPE_ =
      nd->assign_param ("my_icmp.type", "ICMP Type");
    this->P_CODE_ =
      nd->assign_param ("my_icmp.code", "ICMP Code");
    assert (this->EV_ICMP_PKT_ != swarm::EV_NULL);
    assert (this->P_TYPE_ != swarm::PARAM_NULL);
    assert (this->P_CODE_ != swarm::PARAM_NULL);
  }

  // Decoder::setup should be called after constructor. In the function,
  // you should lookup other module's decoder ID (swarm::dec_id) to call
  // next decoder (in this canse, IPv4 decoder is required for ICMP 
  // destination unreacable), and parameter ID (swarm::param_id) that other
  // modules manage in order to obtain already decoded parameters (in this case, 
  // extracted IPv4 protocol number is required to determine if MyIcmpDecoder
  // should decode the packet)
  // 
  void setup (swarm::NetDec * nd) {
    this->D_IPV4_  = nd->lookup_dec_id ("ipv4");
    this->P_PROTO_ = nd->lookup_param_id ("ipv4.proto");
    assert (this->P_PROTO_ != swarm::PARAM_NULL);
  };

  // Decoder::accept is called to determine if the module should decode 
  // the received packet. The argument, swarm::Property, is stored all 
  // decoded data of the recieved packet including payload data.
  // When returning true, Decoder::decode is called.
  // When returning false, the recieved packet is ignored by the module.
  // The Decoder::accept is called after decoding process of other module
  // specified by NetDec::load_decoder.
  // 
  bool accept (const swarm::Property &p) {
    size_t s = p.param (this->P_PROTO_)->size ();
    // check protocol number of most recent IP header
    if (s > 0 && p.param (this->P_PROTO_)->int32 (s - 1) == 1) {
      return true;
    } else {
      return false;
    }
  }

  // Decoder::decode is main decoding function. In a case of the module
  // installed by NetDec::load_module, the decode function is called when
  // Decoder::accept returns true.
  //
  bool decode (swarm::Property *p) {
    // Property::payload(size_t size) can retrieve remaining packet payload.
    // "remaining packet payload" means not parsed and decoded part of packet 
    // payload. If there is not enough size remaining payload, the function
    // returns NULL;
    auto hdr = reinterpret_cast <struct icmp_header *>
      (p->payload (sizeof (struct icmp_header)));
    if (hdr == NULL) {
      return false;
    }

    // The module set ICMP type/code and push event into property.
    // The type and code can be reffered in callback function such as
    // MyIcmpFlow::recv(), and the callback function registered set_handler()
    // is called by pushed event.
    // see also example/data_extract.cc 
    p->set (this->P_TYPE_, &(hdr->type_), sizeof (hdr->type_));
    p->set (this->P_CODE_, &(hdr->code_), sizeof (hdr->code_));
    p->push_event (this->EV_ICMP_PKT_);

    if (hdr->type_ == 3) {
      p->payload (4);  // adjust 4 byte
      this->emit (this->D_IPV4_, p);
    }

    return true;
  }
};


int main (int argc, char *argv[]) {
  // Check syntax
  if (argc != 2) {
    printf ("syntax) %s <pcap_file>\n", argv[0]);
    return 1;
  }

  // Create new NetDec object
  swarm::NetDec *nd = new swarm::NetDec ();

  // Register own original protocol decoder with name
  swarm::dec_id d_id = nd->load_decoder ("my-icmp", new MyIcmpDecoder (nd));

  // If DEC_NULL is returned, you can see error message
  if (d_id == swarm::DEC_NULL) {
    printf ("error: %s\n", nd->errmsg ().c_str ());
    return 1;
  }

  // Bind registered original decoder and existing decoder
  // In this case, when ipv4 decoding process exits, 
  // MyMyIcmpDecoder::accept is called to check decoding
  nd->bind_decoder (d_id, "ipv4");

  // After registering decoder, you can set handler for event defined 
  // in the own decoder
  nd->set_handler ("my_icmp.packet", new MyIcmpFlow ());

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

