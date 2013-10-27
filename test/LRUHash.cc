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


#include "./gtest.h"
#include "../src/utils/lru-hash.h"

namespace LRUHashTest {
  class TestNode : public swarm::LRUHash::Node {
  private:
    uint64_t hv_;
  public:
    TestNode(uint64_t hv) : hv_(hv) {}
    ~TestNode() {}
    uint64_t hash() { return this->hv_; }
  };

  TEST(LRUHash, basic) {
  }

  TEST(LRUHash, expire_test) {
    swarm::LRUHash *lru = new swarm::LRUHash(10);
    TestNode *node1 = new TestNode(100);
    TestNode *node2 = new TestNode(200);
    TestNode *node3 = new TestNode(300);
    TestNode *node4 = new TestNode(400);

    lru->put(1, node1);
    lru->put(2, node2);
    lru->put(4, node2);

#define __TEST(n1,n2,n3,n4)                                   \
    {                                                         \
      if (n1) { EXPECT_EQ(node1, lru->get(node1->hash())); }  \
      else    { EXPECT_EQ(NULL,  lru->get(node1->hash())); }  \
      if (n2) { EXPECT_EQ(node2, lru->get(node2->hash())); }  \
      else    { EXPECT_EQ(NULL,  lru->get(node2->hash())); }  \
      if (n3) { EXPECT_EQ(node3, lru->get(node3->hash())); }  \
      else    { EXPECT_EQ(NULL,  lru->get(node3->hash())); }  \
      if (n4) { EXPECT_EQ(node4, lru->get(node4->hash())); }  \
      else    { EXPECT_EQ(NULL,  lru->get(node4->hash())); }  \
    }

    __TEST(true, true, true, true);
    EXPECT_EQ(NULL,  lru->pop());  // no expired node

    lru->prog(1);

    __TEST(true, true, true, true);
    EXPECT_EQ(node1, lru->pop());  // no expired node  

#undef __TEST

  }

}  // namespace LRUHashTest
