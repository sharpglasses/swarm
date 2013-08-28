#include <gtest/gtest.h>
#include <string.h>

#include "swarm.h"

TEST (Property, basic) {
  swarm::NetDec * nd = new swarm::NetDec ();
  swarm::Property * p = new swarm::Property (nd);
  char * a = const_cast <char *> (static_cast <const char *> ("0123456789"));

  struct timeval tv = {10, 20};
  p->init (reinterpret_cast <swarm::byte_t *> (a), strlen (a), strlen (a), tv);

  swarm::byte_t *b;

  b = p->payload (4);
  ASSERT_TRUE (NULL != b);
  EXPECT_EQ (a[0], b[0]);
  b = p->payload (4);
  ASSERT_TRUE (NULL != b);
  EXPECT_EQ (a[4], b[0]);
  b = p->payload (1);
  ASSERT_TRUE (NULL != b);
  EXPECT_EQ (a[8], b[0]);
  b = p->payload (5);
  EXPECT_TRUE (NULL == b);

  delete p;
  delete nd;
}


TEST (Property, length) {
  swarm::NetDec * nd = new swarm::NetDec ();
  swarm::Property * p = new swarm::Property (nd);
  char * a = const_cast <char *> (static_cast <const char *> ("0123456789"));
  struct timeval tv = {10, 20};
  p->init (reinterpret_cast <swarm::byte_t *> (a), sizeof (a), 5, tv);

  swarm::byte_t *b;

  b = p->payload (4);
  // EXPECT_EQ (&a[0], reinterpret_cast<char*> (b));
  EXPECT_EQ (a[0], b[0]);
  b = p->payload (4);
  EXPECT_EQ (NULL, reinterpret_cast<char*> (b)); 
  b = p->payload (4);
  EXPECT_EQ (NULL, reinterpret_cast<char*> (b));

  delete p;
  delete nd;
}
