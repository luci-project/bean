DEPDIR := .deps
LIBS := capstone dlh

CFLAGS ?= -Og -g
CFLAGS += -fno-exceptions -fno-stack-protector -fno-pic  -mno-red-zone

CXXFLAGS ?= -std=c++17 $(CFLAGS)
CXXFLAGS += -MT $@ -MMD -MP -MF $(DEPDIR)/$@.d
CXXFLAGS += -I include -I elfo/include/ $(foreach LIB,$(LIBS),-I $(LIB)/include)
CXXFLAGS += -I dlh/legacy -DUSE_DLH
CXXFLAGS += -fno-rtti -fno-use-cxa-atexit -no-pie
CXXFLAGS += -nostdlib -nostdinc
CXXFLAGS += -Wall -Wextra -Wno-switch -Wno-unused-variable -Wno-comment

LDFLAGS = $(foreach LIB,$(LIBS),-L $(LIB)/ -l$(LIB) )
SOURCES := $(wildcard src/*.cpp)
TARGETS := $(notdir $(SOURCES:%.cpp=%))
DEPFILES := $(addprefix $(DEPDIR)/,$(addsuffix .d,$(TARGETS)))

all: $(TARGETS)

%: src/%.cpp Makefile | dlh/libdlh.a  # | $(foreach LIB,$(LIBS),$(LIB)/lib$(LIB).a) $(DEPDIR)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

capstone/libcapstone.a:
	test -d $(dir $@) || git submodule update --init
	$(MAKE) -C capstone clean
	#$(MAKE) CAPSTONE_DIET=no CAPSTONE_ARCHS="x86" -C capstone -j 4
	#$(MAKE) CAPSTONE_DIET=yes CAPSTONE_X86_REDUCE=yes CAPSTONE_X86_ATT_DISABLE=yes CAPSTONE_ARCHS="x86" CAPSTONE_USE_SYS_DYN_MEM=no CAPSTONE_STATIC=yes CAPSTONE_SHARED=no -C $(dir $@) -j 4
	# CAPSTONE_X86_REDUCE does not support endbr64 yet
	$(MAKE) CFLAGS="$(CFLAGS) -Iinclude -DCAPSTONE_DIET -DCAPSTONE_X86_ATT_DISABLE -DCAPSTONE_HAS_X86" CAPSTONE_DIET=yes CAPSTONE_X86_ATT_DISABLE=yes CAPSTONE_ARCHS="x86" CAPSTONE_USE_SYS_DYN_MEM=yes CAPSTONE_STATIC=yes CAPSTONE_SHARED=no -C $(dir $@) -j 4 $(notdir $@)

dlh/libdlh.a:
	test -d $(dir $@) || git submodule update --init
	$(MAKE) -C $(dir $@)

$(DEPDIR): ; @mkdir -p $@

$(DEPFILES):

clean::
	rm -f $(DEPFILES)
	rmdir $(DEPDIR) || true

include $(wildcard $(DEPFILES))
