#
# Author: zhujiongfu<zhujiongfu@live.cn>
# Date: Sat Dec 22 10:47:01 CST 2018
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

ifeq ($(CONFIG_$(MODULE)),y)

ifneq ($(KBUILD_SRC),)
_dummy := $(shell [ -d $(LOCAL_PATH) ] || mkdir -p $(LOCAL_PATH))
endif

_cobjs := $(addprefix $(LOCAL_PATH)/,$(module_cobjs))
_cobjs := $(filter-out %/,$(_cobjs))

_cxxobjs := $(addprefix $(LOCAL_PATH)/, $(module_cxxobjs))
_cxxobjs := $(filter-out %/,$(_cxxobjs))

_subdirs := $(addprefix $(LOCAL_PATH)/,$(module_subdirs))
_subdir_targets := $(addsuffix built-in.o,$(_subdirs))

_target := $(LOCAL_PATH)/lib$(module).so
ifneq ($(module_version),)
_target := $(addsuffix .$(module_version), $(_target))
_major := $(word 1, $(subst ., , $(module_version)))
endif
_target := $(patsubst ./%,%,$(_target))

module_depencies := $(addprefix $(STAMP_DIR)/.stamp_, $(module_depencies))
module_depencies := $(addsuffix -installed, $(module_depencies))

module_cflags += $(addprefix -I,$(filter /%,$(module_c_includes)))
module_c_includes := $(filter-out /%,$(module_c_includes))
module_cflags += $(addprefix -I$(srctree)/$(LOCAL_PATH)/,$(module_c_includes))
_shared_flags := -fPIC
$(_cobjs): _cflags:=$(module_cflags) $(_shared_flags)
$(_cobjs): %.o: %.c FORCE
	$(Q)[ -d $(@D) ] || mkdir $(@D)
	$(call if_changed_dep,cobjs)

_targets += $(_cobjs)

module_cxxflags += $(addprefix -I,$(filter /%,$(module_cxx_includes)))
module_cxx_includes := $(filter-out /%,$(module_cxx_includes))
module_cxxflags += $(addprefix -I$(srctree)/$(LOCAL_PATH)/,$(module_cxx_includes))
module_cxxflags += -fPIC
$(_cxxobjs): _cxxflags:=$(module_cxxflags) $(_shared_flags)
$(_cxxobjs): %.o: %.cpp FORCE
	$(Q)[ -d $(@D) ] || mkdir $(@D)
	$(call if_changed_dep,cxxobjs)

_targets += $(_cxxobjs)

module_link_path := $(addprefix -L$(srctree)/$(LOCAL_PATH)/,$(module_link_path))
module_link_path += $(addprefix -l,$(patsubst lib%,%,$(module_link_libs)))
$(_target)-unstripped := $(patsubst ./%,%,$(_subdir_targets))
$(_target)-unstripped: _linkflags:=$(module_link_path)
$(_target)-unstripped: _builinflags=$(sort $(foreach var,\
			          $(foreach s,$($@),$($(s)-var)),$($(var))) \
				$(foreach var,$(foreach f,$($@),$($(f)-flag)),$(var)))

$(_target)-unstripped: $(_cobjs) $(_cxxobjs) $(_subdir_targets) $(module_depencies) FORCE
	$(call if_changed,shared)

_targets += $(_target)-unstripped

$(_target): $(_target)-unstripped
	$(call if_changed,strip)

_targets += $(_target)

$(STAMP_DIR)/.stamp_$(module)-installed: _install_path:=$(OUT_LIB)
$(STAMP_DIR)/.stamp_$(module)-installed: _version:=$(module_version)
$(STAMP_DIR)/.stamp_$(module)-installed: _module:=$(module)
$(STAMP_DIR)/.stamp_$(module)-installed: _major:=$(_major)
$(STAMP_DIR)/.stamp_$(module)-installed: $(_target) FORCE
	$(call if_changed,install)
	$(Q)cd $(_install_path); $(call if_changed_v,symlink,$(notdir $<),lib$(_module).so)
	$(Q)cd $(_install_path); $(call if_changed_v,symlink,$(notdir $<),lib$(_module).so.$(_major))
	$(Q)$(call if_changed_1,touch)

_targets += $(STAMP_DIR)/.stamp_$(module)-installed

cmd_files := $(wildcard $(foreach f,$(_targets),\
		$(dir $(f)).$(notdir $(f)).cmd))
include $(cmd_files)

_cleanobjs := $(cmd_files) $(_targets)
$(module)-clean: cleanobjs:=$(_cleanobjs)
$(module)-clean: FORCE
	-$(Q)$(RM) -rf $(cleanobjs)

$(module)-install: $(STAMP_DIR)/.stamp_$(module)-installed
	@:

ifneq ($(module), $(_target))
$(module): $(_target)
	@:

PHONY := $(PHONY) $(module) $(module)-install
else
PHONY := $(PHONY) $(module)-install
endif

TARGETS_ALL += $(module)

endif

$(foreach var, $(_subdirs), $(if $($(var).inc), ,\
	$(eval $(call include-submakefile, $(var)))))
