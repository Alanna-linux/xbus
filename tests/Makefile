LOCAL_PATH := $(call my-dir)
RPC_PATH := $(LOCAL_PATH)

CONFIG_PUB_CLIENT := y
include $(clear-vars)
module := pub-client
module_cobjs := pub-client.o
module_depencies := xbus
module_link_libs := xbus pthread
include $(build-execute)

CONFIG_SUB_CLIENT := y
include $(clear-vars)
module := sub-client
module_cobjs := sub-client.o
module_depencies := xbus
module_link_libs := xbus pthread
include $(build-execute)

CONFIG_SUB_CPP := n
include $(clear-vars)
module := sub-cpp
module_cxxobjs := sub-cpp.o
module_depencies := xbus
module_link_libs := xbus pthread
include $(build-execute)

CONFIG_PUB_CPP := n
include $(clear-vars)
module := pub-cpp
module_cxxobjs := pub-cpp.o
module_depencies := xbus
module_link_libs := xbus pthread
include $(build-execute)
