VERBOSE = @

SRCFOLDER = src
BUILDDIR ?= .build
LIBS := capstone dlh

CFLAGS ?= -Og -g
CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -fno-builtin -fno-exceptions -fno-stack-protector -fno-pic -mno-red-zone

CXXFLAGS ?= -std=c++17 $(CFLAGS)
CXXFLAGS += -I include -I elfo/include/ $(foreach LIB,$(LIBS),-I $(LIB)/include)
CXXFLAGS += -I dlh/legacy -DUSE_DLH
CXXFLAGS += -fno-rtti -fno-use-cxa-atexit -no-pie
CXXFLAGS += -nostdlib -nostdinc
CXXFLAGS += -Wall -Wextra -Wno-switch -Wno-unused-variable -Wno-comment

BUILDFLAGS_capstone := CFLAGS="$(CFLAGS) -Iinclude -DCAPSTONE_DIET -DCAPSTONE_X86_ATT_DISABLE -DCAPSTONE_HAS_X86" CAPSTONE_DIET=yes CAPSTONE_X86_ATT_DISABLE=yes CAPSTONE_ARCHS="x86" CAPSTONE_USE_SYS_DYN_MEM=yes CAPSTONE_STATIC=yes CAPSTONE_SHARED=no

LDFLAGS = $(foreach LIB,$(LIBS),-L $(LIB)/ -l$(LIB)) -Wl,--gc-sections
SOURCES := $(wildcard $(SRCFOLDER)/*.cpp)
TARGETS := $(notdir $(SOURCES:%.cpp=%))
DEPFILES := $(addprefix $(BUILDDIR)/,$(addsuffix .d,$(TARGETS)))

all: $(TARGETS)

$(BUILDDIR)/%.d: $(SRCFOLDER)/%.cpp $(BUILDDIR) $(MAKEFILE_LIST)
	@echo "DEP		$<"
	$(VERBOSE) $(CXX) $(CXXFLAGS) -MM -MP -MT $* -MF $@ $<

%: $(SRCFOLDER)/%.cpp $(MAKEFILE_LIST) | $(foreach LIB,$(LIBS),$(LIB)/lib$(LIB).a) $(BUILDDIR)
	@echo "CXX		$@"
	$(VERBOSE) $(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

define LIB_template =
$(1)/lib$(1).a:
	@echo "BUILD		$$@"
	@test -d $1 || git submodule update --init
	$$(VERBOSE) $$(MAKE) $$(BUILDFLAGS_$(1)) -j4 -C $1 $$(notdir $$@)

clean::
	@test -d $1 && $$(MAKE) -C $1 $$@

mrproper::
	@test -d $1 && $$(MAKE) -C $1 $$@ || true
	@rm -f $(1)/lib$(1).a
endef

$(foreach lib,$(LIBS),$(eval $(call LIB_template,$(lib))))

clean::
	$(VERBOSE) rm -f $(DEPFILES)
	$(VERBOSE) test -d $(BUILDDIR) && rmdir $(BUILDDIR) || true

mrproper:: clean
	$(VERBOSE) rm -f $(TARGETS)

$(BUILDDIR): ; @mkdir -p $@

$(DEPFILES):

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPFILES)
endif

.PHONY: all clean mrproper
