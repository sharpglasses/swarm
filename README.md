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

    // NOTE: under development
    
    #include <swarm.h>
    #include <iostream>
    
    class DnsHandler : public swarm::Handler {
    public:
      void recv (swarm::ev_id ev, const swarm::Property &p) {
        std::cout << p.param ("dns.query")->str () << std::endl;
      }
    };
    
    int main () {
      swarm::NetCap * nc = new swarm::NetCap ();
      swarm::NetDec * nd = new swarm::NetDec ();
      nd->set_handler ("dns.packet", new DnsHandler ());
      cap->start_capture_alldev ();
    }

