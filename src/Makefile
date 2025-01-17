LOCAL_PATH := $(call my-dir)
XBUS_CORE_PATH := $(LOCAL_PATH)

include $(clear-vars)
module := xbus-core
module_cobjs := completion.o event-loop.o idr.o linux-thread.o \
		log.o  notifier.o os.o sche.o sche-trigger.o wrapper.o \
		xbus-conn.o xbus.o xbus-node.o fifo.o vref.o
module_cxxobjs := xbus-api.o
module_link_libs := pthread

$(addprefix $(LOCAL_PATH)/,$(module_cobjs)): include/generated/compile.h

       chk_compile.h = :
 quiet_chk_compile.h = echo '  CHK     $@'
silent_chk_compile.h = :
include/generated/compile.h: $(objtree)/.version FORCE
	@$($(quiet)chk_compile.h)
	$(Q)$(CONFIG_SHELL) $(srctree)/scripts/mkcompile_h $@ \
	"$(CC)" $(realpath $(objtree))

cmd_update-version = $(CONFIG_SHELL) $< $(realpath $(objtree))
quiet_cmd_update-version = UPDATE  $@
$(objtree)/.version: $(srctree)/scripts/mkversion $(objtree)/.config FORCE
	+$(call if_changed,update-version)

$(objtree)/.version-clean: FORCE
	-$(Q)$(RM) -rf $(objtree)/.version $(objtree)/.old_version $(objtree)/..version.cmd
	-$(Q)$(RM) -rf $(objtree)/include/generated/compile.h
$(objtree)/.version-install: ;

TARGETS_ALL += $(objtree)/.version

include $(wildcard $(objtree)/..version.cmd)

include $(build-in)
