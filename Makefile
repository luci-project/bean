VERBOSE = @

SRCFOLDER = src
EXAMPLEDIR = examples
BUILDDIR ?= .build
LIBS := capstone dlh

AR ?= ar
CXX ?= g++

CFLAGS ?= -Og -g
CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -fno-builtin -fno-exceptions -fno-stack-protector -fno-pic -mno-red-zone

CXXFLAGS ?= -std=c++17 $(CFLAGS)
CXXFLAGS += -I include -I bean/include/ -I elfo/include/ $(foreach LIB,$(LIBS),-I $(LIB)/include)
CXXFLAGS += -I dlh/legacy -DUSE_DLH
CXXFLAGS += -fno-rtti -fno-use-cxa-atexit -no-pie
CXXFLAGS += -nostdlib -nostdinc
CXXFLAGS += -Wall -Wextra -Wno-switch -Wno-unused-variable -Wno-comment

BUILDFLAGS_capstone := CFLAGS="$(CFLAGS) -Iinclude -DCAPSTONE_X86_ATT_DISABLE -DCAPSTONE_HAS_X86" CAPSTONE_X86_ATT_DISABLE=yes CAPSTONE_ARCHS="x86" CAPSTONE_USE_SYS_DYN_MEM=no CAPSTONE_STATIC=yes CAPSTONE_SHARED=no

LIBNAME = bean
SOURCES = $(shell find $(SRCFOLDER)/ -name "*.cpp")
OBJECTS = $(patsubst $(SRCFOLDER)/%,$(BUILDDIR)/%,$(SOURCES:.cpp=.o))
DEPFILES = $(patsubst $(SRCFOLDER)/%,$(BUILDDIR)/%,$(SOURCES:.cpp=.d)) $(patsubst %.cpp,$(BUILDDIR)/%.d,$(wildcard example/*.cpp))
TARGET = lib$(LIBNAME).a
COMBINED = lib$(LIBNAME)-pack.a
EXAMPLES := $(patsubst $(EXAMPLEDIR)/%.cpp,example-%,$(wildcard $(EXAMPLEDIR)/*.cpp))

LDFLAGS = -L. -l$(LIBNAME) $(foreach LIB,$(LIBS),-L $(LIB)/ -l$(LIB)) -Wl,--gc-sections
EXTLIBS = $(foreach LIB,$(LIBS),$(LIB)/lib$(LIB).a)



all: $(TARGET) $(COMBINED) $(EXAMPLES)

$(BUILDDIR)/%.d: $(SRCFOLDER)/%.cpp $(BUILDDIR) $(MAKEFILE_LIST)
	@echo "DEP		$<"
	$(VERBOSE) $(CXX) $(CXXFLAGS) -MM -MP -MT $* -MF $@ $<

$(BUILDDIR)/%.o: $(SRCFOLDER)/%.cpp $(BUILDDIR) $(EXTLIBS) $(MAKEFILE_LIST)
	@echo "CXX		$<"
	@mkdir -p $(@D)
	$(VERBOSE) $(CXX) $(CXXFLAGS) -c -o $@ $<

$(TARGET): $(OBJECTS) $(MAKEFILE_LIST)
	@echo "AR		$@"
	$(VERBOSE) $(AR) rcs $@ $^

$(COMBINED): $(TARGET) $(EXTLIBS)
	@echo "AR		$@"
	$(VERBOSE) echo 'create $@\n$(foreach FILE,$^,addlib $(FILE)\n)save\nend\n' | ar -M

example-%: $(EXAMPLEDIR)/%.cpp $(MAKEFILE_LIST) $(TARGET) $(EXTLIBS) | $(BUILDDIR)
	@echo "CXX		$@"
	$(VERBOSE) $(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

examples: $(EXAMPLES)
	echo $^

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
	$(VERBOSE) rm -f $(DEPFILES) $(OBJECTS)
	$(VERBOSE) test -d $(BUILDDIR) && rmdir $(BUILDDIR) || true

mrproper:: clean
	$(VERBOSE) rm -f $(TARGET) $(COMBINED) $(EXAMPLES)

$(BUILDDIR): ; @mkdir -p $@

$(DEPFILES):

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPFILES)
endif

.PHONY: all examples clean mrproper
