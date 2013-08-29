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
  EXPECT_EQ (a[0], b[0]);
  b = p->payload (4);
  EXPECT_EQ (NULL, reinterpret_cast<char*> (b)); 
  b = p->payload (4);
  EXPECT_EQ (NULL, reinterpret_cast<char*> (b));

  delete p;
  delete nd;
}


TEST (Property, param) {
  const std::string p1_name = "blue";
  const std::string p2_name = "orange";
  const std::string p3_name = "red";
  swarm::NetDec * nd = new swarm::NetDec ();
  swarm::param_id p1_id = nd->assign_param (p1_name);
  swarm::param_id p2_id = nd->assign_param (p2_name);
  swarm::Property * p = new swarm::Property (nd);

  char * w1 = const_cast <char *> (static_cast <const char *> ("not sane"));
  char * w2 = const_cast <char *> (static_cast <const char *> ("all is right"));
  char * w3 = const_cast <char *> (static_cast <const char *> ("the order has fallen"));

  // macro for check consistency of looking up by id and string name
#define CHECK_CONS()                                      \
  do {                                                    \
    EXPECT_TRUE (p->param (p1_id) == p->param (p1_name)); \
    EXPECT_TRUE (p->param (p2_id) == p->param (p2_name)); \
  } while (0);

  CHECK_CONS ();
  EXPECT_TRUE (NULL == p->param (p1_id));
  EXPECT_TRUE (NULL == p->param (p2_id));

  {
    EXPECT_EQ (true, p->set (p1_name, w1, strlen (w1)));
    CHECK_CONS ();
    EXPECT_TRUE (NULL != p->param (p1_id));
    EXPECT_TRUE (NULL == p->param (p2_id));

    EXPECT_EQ (true, p->set (p1_name, w2, strlen (w2)));
    CHECK_CONS ();
    EXPECT_TRUE (NULL != p->param (p1_id));
    EXPECT_TRUE (NULL == p->param (p2_id));

    EXPECT_EQ (true, p->set (p1_id, w3, strlen (w3)));
    CHECK_CONS ();
    EXPECT_TRUE (NULL != p->param (p1_id));
    EXPECT_TRUE (NULL == p->param (p2_id));

    const swarm::Param * p1 = p->param (p1_id);
    ASSERT_TRUE (NULL != p1);
    EXPECT_EQ (p1->str (), w1);
    EXPECT_EQ (p1->str (0), w1);
    EXPECT_EQ (p1->str (1), w2);
    EXPECT_EQ (p1->str (2), swarm::Param::errmsg_);
  }

  {
    EXPECT_EQ (true, p->copy (p2_name, w1, strlen (w1)));
    CHECK_CONS ();
    EXPECT_TRUE (NULL != p->param (p1_id));
    EXPECT_TRUE (NULL != p->param (p2_id));

    EXPECT_EQ (true, p->copy (p2_name, w2, strlen (w2)));
    CHECK_CONS ();
    EXPECT_TRUE (NULL != p->param (p1_id));
    EXPECT_TRUE (NULL != p->param (p2_id));

    const swarm::Param * p1 = p->param (p1_id);
    ASSERT_TRUE (NULL != p1);
    EXPECT_EQ (p1->str (), w1);
    EXPECT_EQ (p1->str (0), w1);
    EXPECT_EQ (p1->str (1), w2);
    EXPECT_EQ (p1->str (2), swarm::Param::errmsg_);

    const swarm::Param * p2 = p->param (p2_id);
    ASSERT_TRUE (NULL != p2);
    EXPECT_EQ (p2->str (), w1);
    EXPECT_EQ (p2->str (0), w1);
    EXPECT_EQ (p2->str (1), w2);
    EXPECT_EQ (p2->str (2), swarm::Param::errmsg_);
  }  
}
