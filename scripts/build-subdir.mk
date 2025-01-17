#
# Author: zhujiongfu(zhujiongfu@live.cn)
# Date: Wed Apr 10 14:33:46 CST 2019
#

_dirs_y := $(addprefix $(LOCAL_PATH)/, $(dir-y))
_dirs_y := $(sort $(_dirs_y))
_dir_files_y := $(addsuffix Makefile, $(_dirs_y))

_dirs_m := $(addprefix $(LOCAL_PATH)/, $(dir-m))
_dir_files_m := $(addsuffix Makefile, $(_dirs_m))

ifneq ($(_dirs_y),)

_dir_objs := $(addsuffix built-in.o,$(_dirs_y))
$(LOCAL_PATH)/built-in.o-var := $(foreach s,$(addsuffix -flag,$(_dir_objs)),$(s))

$(LOCAL_PATH)/built-in.o: $(_dir_objs) FORCE
	$(call if_changed,link_o_target)

_target := $(LOCAL_PATH)/built-in.o
cmd_files := $(wildcard $(foreach f,\
	$(_target),\
	$(dir $(f)).$(notdir $(f)).cmd))
include $(cmd_files)

_cleanobjs := $(cmd_files) $(_target)
$(_target)-clean: cleanobjs:=$(_cleanobjs)
$(_target)-clean: FORCE
	-$(Q)$(RM) -rf $(cleanobjs)

TARGETS_ALL += $(LOCAL_PATH)/built-in.o

endif

_dir_files := $(_dir_files_y) $(_dir_files_m)
_dir_files := $(sort $(_dir_files))

include $(_dir_files)
