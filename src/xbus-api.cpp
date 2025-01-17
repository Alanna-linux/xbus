/**
 * xbus-api.cpp
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Sep 25, 2021
 *
 */

#include <iostream>
#include <cstring>

#include <uapi/xbus.hpp>
#include <uapi/xbus.h>

/** Visibility attribute */
#if defined(__GNUC__) && __GNUC__ >= 4
#define XBUS_EXPORT __attribute__ ((visibility("default")))
#else
#define XBUS_EXPORT
#endif

namespace xbus {

static int msg_handler(void *buf, int len, void *p)
{
  CallbackHelper *helper = (CallbackHelper *)p;

  helper->call(buf, len);

  return 0;
}

XBUS_EXPORT int Subscriber::_init(const std::string &topic, int32_t queue_len)
{
  int ret;

  ret = xbus_subscribe(topic.c_str(), queue_len, msg_handler, helper.get());
  if (ret < 0) {
    std::cout << "xbus_subscribe error" << std::endl;
  }
  
  return ret;
}

XBUS_EXPORT Publisher::Publisher(const std::string &topic, int queue_len)
  : _enableShm(false)
{
  int ret;

  ret = _init(topic, queue_len);
  if (ret < 0)
    throw ret;
}

XBUS_EXPORT Publisher::Publisher(const std::string &topic, int queue_len, int size, int count)
  : _enableShm(true)
{
  int ret;

  ret = _init(topic, queue_len);
  if (ret < 0)
    throw ret;

  ret = xbus_pub_create_shm(&_pub, size, count);
  if (ret < 0)
    throw ret;
}

XBUS_EXPORT int Publisher::_init(const std::string &topic, int queue_len)
{
  int ret;

  ret = xbus_pub_init(&_pub, topic.c_str(), queue_len);
  if (ret < 0)
    std::cout << "xbus_pub_init error" << std::endl;

  return ret;
}

XBUS_EXPORT Request::Request(const std::string &srv)
{
  int ret;

  memset(&_req, 0, sizeof(_req));
  ret = xbus_request_init(srv.c_str(), &_req);
  if (ret < 0) {
    std::cout << "xbus_request_init error" << std::endl;
    throw ret;
  }
}

static int service_callback(struct xbus_request *req, void *p)
{
  ServiceCallbackHelper *helper = (ServiceCallbackHelper *)p;

  helper->call(req);

  return 0;
}

XBUS_EXPORT int Service::_init(const std::string &srv)
{
  return xbus_service(srv.c_str(), service_callback, helper.get());
}

}
