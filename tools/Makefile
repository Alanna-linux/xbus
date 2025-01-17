LOCAL_PATH := $(call my-dir)
TOOLS_PATH := $(LOCAL_PATH)

include $(clear-vars)
module := xbustool
module_cobjs := xbus-tool.o
module_depencies := xbus
module_link_libs := xbus pthread
include $(build-execute)
