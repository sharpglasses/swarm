/**********************************************************************
Copyright (c) 2012 Masa Mizutani <mizutani@sfc.wide.ad.jp>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

***********************************************************************/

#include <deque>
#include "swarm.h"

#ifndef __DECIO_DUMP_H__
#define __DECIO_DUMP_H__

namespace swarm {
#ifdef __ENABLE_PROTOBUF__

    class DecIODumper {
    private:
        std::string dump_file_name_;
        std::string dump_orig_name_;
        void dump ();
        const int save_limit_ ;
        int save_count_;
        int file_count_;

    public:
        DecIODumper () ;
        ~DecIODumper ();
        void set_dump_file (std::string &fname) ;
        void save_request (Property &prop, Payload &p) ;
        void save_emit (Protocol next, Property &prop, Payload &p);
        void save_dispatch (Event ev, Property &prop, Record &r);
    };

    class DecIOReader {
    public:
        DecIOReader (std::string &fname, Decoder * dec);
        ~DecIOReader ();
    };

#else // __ENABLE_PROTOBUF__
    class DecIODumper {
    public:
        DecIODumper (std::string &fname) {}
        ~DecIODumper () {}
    };

    class DecIOReader {
    public:
        DecIOReader (std::string &fname, Decoder * dec) {}
        ~DecIOReader () {}
    };
#endif // __ENABLE_PROTOBUF__

}

#endif // __DECIO_DUMP_H__
