LOCAL_PATH := $(objtree)
XBUS_TOP_PATH := $(LOCAL_PATH)

include $(clear-vars)
module := xbus
subdirs-$(CONFIG_XBUS)		+= src/
module_subdirs			:= $(subdirs-y)
module_version			:= $(CONFIG_VERSION)
ifeq ($(CONFIG_XBUS_SHARED), y)
include $(build-shared)
else
include $(build-static)
endif

LOCAL_PATH := $(XBUS_TOP_PATH)
CONFIG_XBUS_DAEMON := y
include $(clear-vars)
module := xbus-daemon
module_cobjs := src/xbus-daemon.o
module_depencies := xbus
module_link_libs := xbus pthread
include $(build-execute)

LOCAL_PATH := $(XBUS_TOP_PATH)
include $(srctree)/tools/Makefile
include $(srctree)/tests/Makefile
