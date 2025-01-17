/**
 * sub-cpp.cpp
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Sep 23, 2021
 *
 */

#include <unistd.h>
#include <uapi/xbus.hpp>
#include <iostream>

using namespace std;

struct msg_test {
	struct timespec	ts;
	int32_t id;
	char buf[256];
};

class cpp_msg {
public:
	int32_t seq;
	int32_t frameid;
	char buf[256];
};

class cpp_req {
public:
	int cmd;
};

class cpp_resp {
public:
	int ack;
	char buf[128];
};

class msg_controller {
public:
	msg_controller() { }
	class xbus::Subscriber sub;
	class xbus::Service srv;
	int msg_callback(cpp_msg &msg);
	int service_handler(cpp_req &req, cpp_resp &resp);
};

int msg_controller::msg_callback(cpp_msg &msg)
{
	/* printf("seq %d %s\n", msg.seq, msg.buf); */

	return 0;
}

int msg_controller::service_handler(cpp_req &req, cpp_resp &resp)
{
	std::cout << "req cmd " << req.cmd << std::endl;

	sprintf(resp.buf, "ack%d", resp.ack++);

	return 0;
}

int main(int argc, char **argv)
{
	class msg_controller msgc;
	/* class xbus::Subscriber sub; */

	xbus_init("sub-cpp", 1);

	msgc = msg_controller();
	msgc.sub = xbus::Subscriber("ptopic0", 16, &msg_controller::msg_callback, &msgc);
	msgc.srv = xbus::Service("service01", &msg_controller::service_handler, &msgc);

	cout << "hello" << endl;

	xbus_spin();

	return 0;
}
