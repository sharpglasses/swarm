# Swarm
C++ based lightweight and high-speed network traffic decoding library.

## Required
- libpcap
- pthread

## Install

    % cd swarm
    % ./waf configure
    % ./waf
    % sudo ./waf install

## Sample

    #include <swarm.h>
    #include <iostream>
    
    class DnsHandler : public swarm::Handler {
    public:
      void recv (swarm::ev_id ev, const swarm::Property &p) {
        // print domain name of dns query
        std::cout << p.param ("dns.qd_name")->repr () << std::endl;
      }
    };
    
    int main () {
      swarm::NetDec * nd = new swarm::NetDec ();
      nd->set_handler ("dns.packet", new DnsHandler ());
      swarm::NetCap * nc = new swarm::NetCap (nd);
      nc->capture ("eth0");
    }

