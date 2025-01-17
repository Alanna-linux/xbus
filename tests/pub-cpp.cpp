/**
 * pub-cpp.cpp
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Sep 24, 2021
 *
 */

#include <unistd.h>
#include <uapi/xbus.hpp>
#include <iostream>
#include <cstring>

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

int main(int argc, char **argv)
{
	class cpp_msg msg;
	class cpp_req req_msg;
	class cpp_resp resp_msg;
	class xbus::Request req;
	int seq = 0;

	xbus_init("pub-cpp", 1);

	class xbus::Publisher pub("ptopic0", 16);

	req = xbus::Request("service01");
	cout << "hello" << endl;
	memset(&msg, 0, sizeof(msg));

	req_msg.cmd = 0;
	while (1) {
		msg.seq = seq;
		sprintf(msg.buf, "pub %d", seq++);
		pub.publish(msg);

		req_msg.cmd++;
		/* std::cout << "reqs cmd " << req_msg.cmd << std::endl; */
		req.call(req_msg, resp_msg);
		/* std::cout << resp_msg.ack << ":" << resp_msg.buf << std::endl; */
		usleep(10000);
	}

	return 0;
}
