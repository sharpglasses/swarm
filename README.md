Swarm
===========================
Swarm is the **C++ based lightweight and high-speed network traffic decoding library**.

Features
---------------------------

- Extracting parameters of network protocol ([example](./example/extract_data.cc))
- Zero-copy based high-speed decoding of packet
- Extendable protocol decoding module ([example](./example/original_decoder.cc))

Required libraries
---------------------------

- libpcap
- pthread

Install
---------------------------

    % cd swarm
    % cmake . && make
    % sudo make install

Sample
---------------------------

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
      swarm::NetCap * nc = new swarm::CapPcapDev ("eth0");
      nc->bind_netdec (nd);
      nc->start ();
    }

More examples are available in [exaple directory](https://github.com/m-mizutani/swarm/tree/master/example).
