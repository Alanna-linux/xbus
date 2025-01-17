#
# Author: zhujiongfu(zhujiongfu@live.cn)
# Date: Sat Dec 22 09:42:34 CST 2018
#

MODULE := $(call UPPERCASE,$(module))

ifneq ($(filter $(module),$(MODULES_ALL)),)
  $(error Package '$(module)' defined a second time in '$(LOCAL_PATH)';\
	  Previous definition was in '$(_$(module)_path)')
endif

ifneq ($(_clear_vars_inc), 1)
  $(error "$$(clear-vars) is not inclued in module $(module)")
endif
_clear_vars_inc := 0

_$(module)_path := $(LOCAL_PATH)
MODULES_ALL += $(module)

_build := y
ifeq ($(strip $(module_cobjs) $(module_cxxobjs) $(module_subdirs)),)
_build := n
endif

ifeq ($(_build)$(CONFIG_$(MODULE)),yy)

ifneq ($(KBUILD_SRC),)
_dummy := $(shell [ -d $(LOCAL_PATH) ] || mkdir -p $(LOCAL_PATH))
endif

_cobjs := $(addprefix $(LOCAL_PATH)/,$(module_cobjs))
_cobjs := $(filter-out %/,$(_cobjs))

_cxxobjs := $(addprefix $(LOCAL_PATH)/, $(module_cxxobjs))
_cxxobjs := $(filter-out %/,$(_cxxobjs))

_subdirs := $(addprefix $(LOCAL_PATH)/,$(module_subdirs))
_subdir_targets := $(addsuffix built-in.o,$(_subdirs))

module_depencies := $(addprefix $(STAMP_DIR)/.stamp_, $(module_depencies))
module_depencies := $(addsuffix -installed, $(module_depencies))

$(LOCAL_PATH)/built-in.o-var := $(foreach s,$(addsuffix -flag,$(_subdir_targets)),$(s))
ifeq ($($(LOCAL_PATH)/built-in.o-flag),)
$(LOCAL_PATH)/built-in.o-flag := $(addprefix -l,$(module_link_libs)) \
				   $(addprefix -L$(LOCAL_PATH)/,$(module_link_path))
else
$(LOCAL_PATH)/built-in.o-flag += $(addprefix -l,$(module_link_libs)) \
				   $(addprefix -L$(LOCAL_PATH)/,$(module_link_path))
endif

_target := $(LOCAL_PATH)/$(module)-in.o

module_cflags += $(addprefix -I,$(filter /%,$(module_c_includes)))
module_c_includes := $(filter-out /%,$(module_c_includes))
module_cflags += $(addprefix -I$(srctree)/$(LOCAL_PATH)/,$(module_c_includes))
$(_cobjs): _cflags:=$(module_cflags) $(_shared_flags)
$(_cobjs): %.o: %.c FORCE
	$(Q)[ -d $(@D) ] || mkdir $(@D)
	$(call if_changed_dep,cobjs)

_targets += $(_cobjs)

module_cxxflags += $(addprefix -I,$(filter /%,$(module_cxx_includes)))
module_cxx_includes := $(filter-out /%,$(module_cxx_includes))
module_cxxflags += $(addprefix -I$(srctree)/$(LOCAL_PATH)/,$(module_cxx_includes))
$(_cxxobjs): _cxxflags:=$(module_cxxflags) $(_shared_flags)
$(_cxxobjs): %.o: %.cpp FORCE
	$(Q)[ -d $(@D) ] || mkdir $(@D)
	$(call if_changed_dep,cxxobjs)

_targets += $(_cxxobjs)

$(_target): $(_cobjs) $(_cxxobjs) $(_subdir_targets) FORCE
	$(call if_changed,link_o_target)

_targets += $(_target)

$(LOCAL_PATH)/built-in.o: $(module_depencies) $(_target) FORCE

ifeq ($($(LOCAL_PATH)-builin),)

$(LOCAL_PATH)-builin := 1
$(LOCAL_PATH)/built-in.o: test_flag=$(foreach var,$($@-var),$($(var)))
$(LOCAL_PATH)/built-in.o:
	$(call if_changed,link_o_target)

$(LOCAL_PATH)/built-in.o-clean: cleanobjs:=$(LOCAL_PATH)/built-in.o 
$(LOCAL_PATH)/built-in.o-clean: FORCE
	-$(Q)$(RM) -rf $(cleanobjs)

TARGETS_ALL += $(LOCAL_PATH)/built-in.o

endif

cmd_files := $(wildcard $(foreach f,\
	$(_targets) $(LOCAL_PATH)/built-in.o,\
	$(dir $(f)).$(notdir $(f)).cmd))
include $(cmd_files)

_cleanobjs := $(cmd_files) $(_targets)
$(_target)-clean: cleanobjs:=$(_cleanobjs)
$(_target)-clean: FORCE
	-$(Q)$(RM) -rf $(cleanobjs)

$(LOCAL_PATH)/built-in.o-clean: $(_target)-clean

endif

$(foreach var, $(_subdirs), $(if $($(var).inc), ,\
	$(eval $(call include-submakefile, $(var)))))
