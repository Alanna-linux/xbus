/**
 * xbus.hpp
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Sep 23, 2021
 *
 */

#ifndef _UAPI_XBUS_HPP
#define _UAPI_XBUS_HPP

#include <iostream>

#include "xbus.h"
#include <memory>
#include <functional>

namespace xbus {

template<typename M>
struct ParameterAdapter
{
  typedef typename std::remove_reference<typename std::remove_const<M>::type>::type Message;
  typedef M Parameter;

  static Parameter getParameter(void *data)
  {
     return (*((Message *)data));
  }
};

class CallbackHelper
{
public:
  virtual ~CallbackHelper() { }
  virtual void call(void *data, int len) = 0;
  virtual bool isConst() = 0;
};

typedef std::shared_ptr<CallbackHelper> CallbackHelperPtr;

template <typename P>
class CallbackHelperT: public CallbackHelper
{
public:
  typedef ParameterAdapter<P> Adapter;
  typedef std::function<int(typename Adapter::Parameter)> Callback;

  CallbackHelperT(const Callback &callback)
  : _callback(callback)
  { }

  Callback _callback;

  virtual void call(void *data, int len)
  {
    _callback(ParameterAdapter<P>::getParameter(data));
  }

  virtual bool isConst()
  {
    std::cout << "isConst" << std::endl;
    return true;
  }
};

class ServiceCallbackHelper {
public:
  virtual ~ServiceCallbackHelper() {}
  virtual bool call(struct xbus_request *req) = 0;
};
typedef std::shared_ptr<ServiceCallbackHelper> ServiceCallbackHelperPtr;

template<typename MReq, typename MRsp>
class ServiceCallbackHelperT: public ServiceCallbackHelper {
public:
  typedef MReq RequestType;
  typedef MRsp ResponseType;
  typedef std::function<bool(RequestType&, ResponseType&)> Callback;
  typedef std::function<bool(RequestType&, int, ResponseType&, int)> Callback1;

  ServiceCallbackHelperT(const Callback &callback)
  : _callback(callback), _callback1(NULL)
  { }

  ServiceCallbackHelperT(const Callback1 &callback)
  : _callback1(callback), _callback(NULL)
  { }

  Callback _callback;
  Callback1 _callback1;

  virtual bool call(struct xbus_request *req)
  {
    if (_callback)
      return _callback(*((RequestType *)req->req), *((ResponseType *)req->resp));
    else
      return _callback1(*((RequestType *)req->req), req->req_len, *((ResponseType *)req->resp), req->resp_len);
  }
};

class Subscriber {
public:
  Subscriber(void) { };

  template<class T>
  Subscriber(const std::string &topic, int32_t queue_len, int (*fp)(T))
  {
    int ret;

    helper = std::make_shared<CallbackHelperT<T>>(fp);

    ret = _init(topic, queue_len);
    if (ret < 0)
      throw ret;
  }

  template <class M, class T>
  Subscriber(const std::string &topic, int32_t queue_len, int (M::*fp)(T), std::shared_ptr<M> &obj)
  {
    int ret;
    std::function<int (T)> callback;

    callback = std::bind(fp, obj.get(), std::placeholders::_1);
    helper = std::make_shared<CallbackHelperT<T> >(callback);

    ret = _init(topic, queue_len);
    if (ret < 0)
      throw ret;
  }

  template <class M, class T>
  Subscriber(const std::string &topic, int32_t queue_len, int (M::*fp)(T), M *obj)
  {
    int ret;
    std::function<int (T)> callback;

    callback = std::bind(fp, obj, std::placeholders::_1);
    helper = std::make_shared<CallbackHelperT<T> >(callback);

    ret = _init(topic, queue_len);
    if (ret < 0)
      throw ret;
  }

  int sub_call(void *buf, int len, void *p)
  {
    helper->call(buf, len);
    return 0;
  }

  CallbackHelperPtr helper;

private:
  int _init(const std::string &topic, int queue_len);
};

class ShmMsg {
public:
  ShmMsg() { };

  ShmMsg(const struct xbus_shm_buf *shm)
  : _shmbuf(shm)
  { }

  template<class T>
  T *getPtr(void)
  {
    return ((T *)_shmbuf->data);
  }

  const struct xbus_shm_buf *getShmBuf(void)
  {
    return _shmbuf;
  }

private:
  const struct xbus_shm_buf *_shmbuf;
};

class Publisher {
public:
  Publisher() { };

  Publisher(const std::string &topic, int queue_len);
  Publisher(const std::string &topic, int queue_len, int size, int count);

  template<class T>
  T *getShmMsg(uint32_t flag)
  {
    _curShmbuf = xbus_pub_get_shmbuf(&_pub, flag);
    if (_curShmbuf == NULL)
      return NULL;

    return ((T *)_curShmbuf->data);
  }

  template<class T>
  int publish(T &msg)
  {
    int ret;
    if (_enableShm) {
      ret = xbus_publish(&_pub, _curShmbuf, sizeof(struct xbus_shm_buf));
      _curShmbuf = NULL;

      return ret;
    }

    return xbus_publish(&_pub, &msg, sizeof(T));
  }

private:
  int _init(const std::string &topic, int queue_len);

  bool _enableShm = false;
  const struct xbus_shm_buf *_curShmbuf = NULL;
  struct xbus_pub _pub;
};

class Request {
public:
  Request() { };
  Request(const std::string &srv);

  template<class M, class T>
  int call(M &req, T &rsp)
  {
    _req.req = &req;
    _req.req_len = sizeof(M);
    _req.resp = &rsp;
    _req.resp_len = sizeof(T);

    return xbus_request(&_req);
  }

private:
  struct xbus_request _req;
};

class Service {
public:
  Service(void) { };

  template<class MReq, class MRsp>
  Service(const std::string &srv, int (*fp)(MReq &, MRsp &))
  {
    int ret;

    helper = std::make_shared<ServiceCallbackHelperT<MReq, MRsp>>(fp);

    ret = _init(srv);
    if (ret < 0)
      throw ret;
  }

  template <class M, class MReq, class MRsp>
  Service(const std::string &srv, int (M::*fp)(MReq &, MRsp &), std::shared_ptr<M> &obj)
  {
    int ret;
    std::function<int (MReq &, MRsp &)> callback;

    callback = std::bind(fp, obj.get(), std::placeholders::_1, std::placeholders::_2);
    helper = std::make_shared<ServiceCallbackHelperT<MReq, MRsp> >(callback);

    ret = _init(srv);
    if (ret < 0)
      throw ret;
  }

  template <class M, class MReq, class MRsp>
  Service(const std::string &srv, int (M::*fp)(MReq &, MRsp &), M *obj)
  {
    int ret;
    std::function<int (MReq &, MRsp &)> callback;

    callback = std::bind(fp, obj, std::placeholders::_1, std::placeholders::_2);
    helper = std::make_shared<ServiceCallbackHelperT<MReq, MRsp> >(callback);

    ret = _init(srv);
    if (ret < 0)
      throw ret;
  }

  ServiceCallbackHelperPtr helper;

private:
  int _init(const std::string &srv);
};

}

#endif
