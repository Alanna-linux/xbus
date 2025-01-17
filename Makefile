#
# based on linux Makefile
# Author: zhujiongfu<zhujiongfu@live.cn>
# Date: Sat Dec 22 09:42:55 CST 2018
#

VERSION = 1
PATCHLEVEL = 0

MAKEFLAGS += --include-dir=$(CURDIR)

CONFIG_SHELL := $(shell if [ -x "$$BASH" ]; then echo $$BASH; \
	  else if [ -x /bin/bash ]; then echo /bin/bash; \
	  else echo sh; fi ; fi)

ifeq ("$(origin V)", "command line")
  BUILD_VERBOSE = $(V) 
endif

ifndef BUILD_VERBOSE
  BUILD_VERBOSE = 0
endif
  
ifeq ($(strip $(BUILD_VERBOSE)),1)
  quiet =
  Q =
else
  quiet=quiet_
  Q = @
endif

# KBUILD_SRC is set in the invocation of make
# if KBUILD_SRC is not null, that is mean now it is
# involed by another Makefile
ifeq ($(KBUILD_SRC),)
ifeq ("$(origin O)", "command line")
  KBUILD_OUTPUT = $(O)
endif

PHONY := _all
_all:

$(CURDIR)/Makefile Makefile: ;

ifneq ($(words $(subst :, ,$(CURDIR))), 1)
  $(error main directory cannot contain spaces nor colons)
endif

endif

ifneq ($(KBUILD_OUTPUT),)
saved-output := $(KBUILD_OUTPUT)
KBUILD_OUTPUT := $(shell mkdir -p $(KBUILD_OUTPUT) && cd $(KBUILD_OUTPUT) \
							&& /bin/pwd)
$(if $(KBUILD_OUTPUT),, \
	$(error failed to create output directory "$(saved-output)"))

$(filter-out _all sub-make $(CURDIR)/Makefile, $(MAKECMDGOALS)) _all: sub-make
	@:

sub-make:
	$(Q)$(MAKE) -C $(KBUILD_OUTPUT) KBUILD_SRC=$(CURDIR) \
	-f $(CURDIR)/Makefile $(filter-out sub-make _all,$(MAKECMDGOALS))

skip-makefile := 1
endif

ifeq ($(KBUILD_SRC),)
        srctree = .
else
        ifeq ($(KBUILD_SRC)/,$(dir $(CURDIR)))
                srctree := ..
        else
                srctree := $(KBUILD_SRC)
        endif
endif

objtree := .
VPATH   := $(srctree)
REGENERATE_PARSERS := 1

export srctree objtree VPATH REGENERATE_PARSERS

INSTALL_DIR ?= $(objtree)/out
OUT_BIN := $(INSTALL_DIR)/usr/bin
OUT_LIB := $(INSTALL_DIR)/usr/lib
STAMP_DIR := $(objtree)/stamp

$(shell [ -d $(LOCAL_PATH) ] || mkdir -p $(OUT_BIN))
$(shell [ -d $(LOCAL_PATH) ] || mkdir -p $(OUT_LIB))

ifeq ($(skip-makefile),)

include $(srctree)/version.mk

$(shell [ ! -e $(STAMP_DIR) ] && mkdir $(STAMP_DIR))

# do not print "Entering directory ..."
MAKEFLAGS += --no-print-directory

KCONFIG_CONFIG	:= $(CURDIR)/.config
export KCONFIG_CONFIG

RM = rm
CC = $(CROSS_COMPILE)gcc $(KCFLAGS)
CXX = $(CROSS_COMPILE)g++ $(KCFLAGS)
LD = $(CROSS_COMPILE)ld $(KCFLAGS)
STRIP = $(CROSS_COMPILE)strip
INSTALL = install

HOSTCC = gcc
HOSTCXX = g++
HOSTCFLAGS   := -Wall -Wmissing-prototypes -Wstrict-prototypes -O2 -fomit-frame-pointer -std=gnu89
HOSTCXXFLAGS = -O2

export srctree quiet CC CXX HOSTCC HOSTCXX HOSTCFLAGS HOSTCXXFLAGS

TARGETS_ALL :=
MODULES_ALL :=

LINUXINCLUDE    := -include $(objtree)/include/generated/autoconf.h \
			-I$(objtree)/include \
			-I$(srctree)/include -I$(srctree)/include/uapi

ifneq ($(TARGET_SYSROOT),)
LINUXINCLUDE += -I$(TARGET_SYSROOT)/usr/include
LINUXLIBS := -L$(TARGET_SYSROOT)/usr/lib -Wl,-rpath-link=$(TARGET_SYSROOT)/usr/lib
endif

c_flags := $(LINUXINCLUDE) -Wall \
	-DCONFIG_VERSION=\"$(CONFIG_VERSION)\" \
	-Werror=implicit-function-declaration -Werror=incompatible-pointer-types \
	-fvisibility=hidden \
	-Wl,-rpath-link=$(OUT_LIB)
cxx_flags := $(LINUXINCLUDE) -Wall -std=c++11 \
	-DCONFIG_VERSION=$(CONFIG_VERSION) \
	-fvisibility=hidden \
	-Werror=implicit-function-declaration -Werror=incompatible-pointer-types \
	-Wl,-rpath-link=$(OUT_LIB)
linkflags := $(LINUXLIBS) -L$(OUT_LIB)/ -L$(srctree)/3rd/lib \
	-fvisibility=hidden \
	-Wl,-rpath-link=$(srctree)/3rd/lib \
	-Wl,-rpath-link=$(OUT_LIB)

# ifneq ($(BUILD_DEBUG),)
c_flags := $(c_flags) -g
cxx_flags := $(cxx_flags) -g
linkflags := $(linkflags) -g
# endif

all:

include scripts/Kbuild.include
include scripts/pkg-util.mk

# include $(sort $(wildcard */Makefile))

config-targets 	:= 0
dot-config 	:= 1

no-dot-config-targets := clean mrproper distclean \
			cscope gtags TAGS tags help% %docs check% coccicheck \
			headers_% archheaders archscripts %src-pkg

ifneq ($(filter $(no-dot-config-targets), $(MAKECMDGOALS)),)
	ifeq ($(filter-out $(no-dot-config-targets), $(MAKECMDGOALS)),)
		dot-config := 0
	endif
endif

ifneq ($(filter config %config,$(MAKECMDGOALS)),)
	config-targets := 1
endif

ifeq ($(config-targets),1)
config: scripts_basic
	$(Q)$(MAKE) $(build)=scripts/kconfig $@
%config: scripts_basic
	$(Q)$(MAKE) $(build)=scripts/kconfig $@

else

PHONY += scripts
scripts: scripts_basic $(objtree)/include/config/auto.conf include/config/tristate.conf
	$(Q)$(MAKE) $(build)=$(@)

ifeq ($(dot-config),1)

-include $(objtree)/include/config/auto.conf
-include $(objtree)/include/config/auto.conf.cmd

$(KCONFIG_CONFIG) $(objtree)/include/config/auto.conf.cmd: ;

$(objtree)/include/config/%.conf: $(KCONFIG_CONFIG) $(objtree)/include/config/auto.conf.cmd
	$(Q)$(MAKE) -f $(srctree)/Makefile silentoldconfig

else
-include $(objtree)/include/config/auto.conf
-include $(objtree)/include/config/auto.conf.cmd
$(objtree)/include/config/auto.conf: ;
endif

endif # config-targets

ifeq ($(CONFIG_SANITIZE_ADDRESS),y)
c_flags += -fsanitize=address
cxx_flags += -fsanitize=address
linkflags += -fsanitize=address
endif

scripts_basic: outputmakefile
	$(Q)$(MAKE) $(build)=scripts/basic

scripts/basic/%: scripts_basic

PHONY += outputmakefile

outputmakefile:
ifneq ($(KBUILD_SRC),)
	$(Q)ln -fsn $(srctree) source
	$(Q)$(CONFIG_SHELL) $(srctree)/scripts/mkmakefile \
	    $(srctree) $(objtree) $(VERSION) $(PATCHLEVEL)
endif

# include example/Makefile

include $(srctree)/top.mk

_all: all
PHONY += all
all: $(objtree)/include/config/auto.conf scripts_basic scripts $(TARGETS_ALL)

install_objs := $(addsuffix -install,$(filter-out %/built-in.o,$(TARGETS_ALL)))
PHONY += install
install: $(install_objs)

clean := -f $(if $(KBUILD_SRC),$(srctree)/)scripts/Makefile.clean obj
clean_objs := $(addsuffix -clean,$(TARGETS_ALL))
clean_dirs := $(addprefix _clean_, scripts/basic scripts/kconfig)
PHONY += clean $(clean_dirs)
$(clean_dirs):
	$(Q)$(MAKE) $(clean)=$(patsubst _clean_%,%,$@)
clean: $(clean_dirs) $(clean_objs)
	@$(RM) -rf $(INSTALL_DIR)
	@$(RM) -rf $(STAMP_DIR)
	@$(RM) -rf $(objtree)/include/config
	@$(RM) -rf $(objtree)/include/generated
	@find scripts \
		\( -name '*.orig' -o -name '*.rej' -o -name '*~' \
		-o -name '*.bak' -o -name '#*#' -o -name '.*.orig' \
		-o -name '*_shipped' \
		-o -name '*.so' \
		-o -name '*.so.*' \
		-o -name '.*.rej' -o -size 0 -o -name '*.o' \
		-o -name '*%' -o -name '.*.cmd' -o -name 'core' \) \
		-type f -print | xargs rm -f

distclean: clean
	@$(RM) -rf .config*

PHONY += FORCE
FORCE: scripts_basic $(objtree)/include/config/auto.conf

endif 	# skip-makefile

.PHONY: $(PHONY)

