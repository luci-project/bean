VERBOSE = @

SRCFOLDER = src
EXAMPLEDIR = examples
UTILPREFIX = bean-
LIBNAME = bean
LIBS := capstone dlh

CPPLINT ?= cpplint
CPPLINTIGNORE := $(LIBS) elfo
TIDY ?= clang-tidy
TIDYCONFIG ?= .clang-tidy
TIDYIGNORE := capstone

TOOLSDIR := tools
TOOLS = $(filter-out __pycache__,$(wildcard $(TOOLSDIR)/*))

ifeq ($(HOME),/root)
	INSTALLDIR ?= /usr/local/bin
else
	INSTALLDIR ?= $(HOME)/.local/bin
endif

AR ?= ar
CXX ?= g++

DWARFVERSION ?= 5

ifeq ($(OPTIMIZE), 1)
	CFLAGS := -O3 -DNDEBUG
	BUILDDIR ?= .build-optimize
	LIBDIR ?= libs-optimize
else
	CFLAGS := -Og -g -gdwarf-$(DWARFVERSION)
	BUILDDIR ?= .build
	LIBDIR ?= libs
endif

CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -fno-builtin -fno-exceptions -fno-stack-protector -mno-red-zone -fPIE
CFLAGS += -nostdlib -fno-jump-tables -fno-plt

CXXFLAGS := -std=c++17 $(CFLAGS) -Wall -Wextra -Wno-switch -Wno-unused-variable -Wno-comment
CXXFLAGS += -I include -I bean/include/ -I elfo/include/ $(foreach LIB,$(LIBS),-I $(LIB)/include)
CXXFLAGS += -I dlh/legacy -DVIRTUAL -DUSE_DLH
CXXFLAGS += -fno-rtti -fno-use-cxa-atexit
CXXFLAGS += -nostdlib -nostdinc

VERBOSE_MODE ?= 1
ifeq ($(VERBOSE_MODE), 1)
	CXXFLAGS += -DBEAN_VERBOSE
endif

BUILDFLAGS_capstone = CAPSTONE_X86_ATT_DISABLE=yes CAPSTONE_ARCHS="x86" CAPSTONE_USE_SYS_DYN_MEM=no CAPSTONE_STATIC=yes CAPSTONE_SHARED=no
BUILDFLAGS_capstone += CFLAGS="-I include $(CFLAGS) -DCAPSTONE_HAS_X86 -DCAPSTONE_X86_ATT_DISABLE"
BUILDFLAGS_dlh += CXXFLAGS="$(CXXFLAGS)"

BUILDINFO = $(BUILDDIR)/.build_$(LIBNAME).o
SOURCES = $(shell find $(SRCFOLDER)/ -name "*.cpp")
OBJECTS = $(patsubst $(SRCFOLDER)/%,$(BUILDDIR)/%,$(SOURCES:.cpp=.o)) $(BUILDINFO)
EXAMPLESRC = $(wildcard $(EXAMPLEDIR)/*.cpp)
EXAMPLES = $(patsubst $(EXAMPLEDIR)/%.cpp,$(UTILPREFIX)%,$(EXAMPLESRC))
DEPFILES = $(patsubst $(SRCFOLDER)/%,$(BUILDDIR)/%,$(SOURCES:.cpp=.d)) $(patsubst $(EXAMPLEDIR)/%.cpp,$(BUILDDIR)/$(UTILPREFIX)%.d,$(wildcard $(EXAMPLEDIR)/*.cpp))
TARGET = lib$(LIBNAME).a

LDFLAGS = -L$(LIBDIR) -l$(LIBNAME) $(foreach LIB,$(LIBS),-l$(LIB)) -Wl,--gc-sections
EXTLIBS = $(foreach LIB,$(LIBS),$(LIBDIR)/lib$(LIB).a)

all: $(TARGET) $(COMBINED) $(EXAMPLES)

$(BUILDDIR)/%.d: $(SRCFOLDER)/%.cpp $(MAKEFILE_LIST) | $(BUILDDIR)
	@echo "DEP		$<"
	$(VERBOSE) $(CXX) $(CXXFLAGS) -MM -MP -MT $(BUILDDIR)/$*.o -MF $@ $<

$(BUILDDIR)/$(UTILPREFIX)%.d: $(EXAMPLEDIR)/%.cpp $(MAKEFILE_LIST) | $(BUILDDIR)
	@echo "DEP		$<"
	$(VERBOSE) $(CXX) $(CXXFLAGS) -MM -MP -MT $(UTILPREFIX)$* -MF $@ $<

$(BUILDDIR)/%.o: $(SRCFOLDER)/%.cpp $(MAKEFILE_LIST) | $(BUILDDIR)
	@echo "CXX		$<"
	@mkdir -p $(@D)
	$(VERBOSE) $(CXX) $(CXXFLAGS) -D__MODULE__="$(LIBNAME)" -c -o $@ $<

$(BUILDINFO): FORCE
	@echo "CXX		$@"
	@echo 'const char * build_elfo_version() { return "$(shell cd elfo ; git describe --dirty --always --tags 2>/dev/null || echo unknown)"; } ' \
	'const char * build_capstone_version() { return "$(shell cd capstone ; git describe --dirty --always --tags 2>/dev/null || echo unknown)"; } ' \
	'const char * build_capstone_flags() { return "$(subst ",',$(BUILDFLAGS_capstone))"; } ' \
	'const char * build_$(LIBNAME)_version() { return "$(shell git describe --dirty --always --tags 2>/dev/null || echo unknown)"; } ' \
	'const char * build_$(LIBNAME)_date() { return "$(shell date -R)"; }' \
	'const char * build_$(LIBNAME)_flags() { return "$(CXXFLAGS)"; }' | $(CXX) $(CXXFLAGS) -x c++ -c -o $@ -

$(LIBDIR)/$(TARGET): $(OBJECTS) $(MAKEFILE_LIST)
	@echo "AR		$@"
	@mkdir -p $(@D)
	@rm -f $@
	$(VERBOSE) $(AR) rcs $@ $(OBJECTS)

$(TARGET): $(LIBDIR)/$(TARGET) $(EXTLIBS) | $(MAKEFILE_LIST)
	@echo "PKG		$@"
	@rm -f $@
	$(VERBOSE) /bin/echo -e 'create $@\n$(foreach FILE,$(LIBDIR)/$(TARGET) $(EXTLIBS),addlib $(FILE)\n)save\nend\n' | ar -M

$(UTILPREFIX)%: $(EXAMPLEDIR)/%.cpp $(MAKEFILE_LIST) $(TARGET) $(EXTLIBS) |
	@echo "CXX		$@"
	$(VERBOSE) $(CXX) $(CXXFLAGS) -static -o $@ $< $(LDFLAGS)

examples: $(EXAMPLES)
	@echo "Examples: $^"

lint::
	@if $(CPPLINT) --quiet --recursive $(addprefix --exclude=,$(CPPLINTIGNORE)) . ; then \
		echo "Congratulations, coding style obeyed!" ; \
	else \
		echo "Coding style violated -- see CPPLINT.cfg for details" ; \
		exit 1 ; \
	fi

tidy: $(TIDYCONFIG)
	$(VERBOSE) $(TIDY) --config-file=$(TIDYCONFIG) --header-filter="^(?!.*(/capstone/))" --system-headers $(SOURCES) $(EXAMPLESRC) -- -stdlib=libc++  $(CXXFLAGS)

install: $(EXAMPLES)
	$(VERBOSE) install -Dm755 $^ $(INSTALLDIR)
	$(VERBOSE) $(foreach TOOL,$(TOOLS),ln -f -s $(realpath $(TOOL)) $(INSTALLDIR)/$(UTILPREFIX)$(basename $(notdir $(TOOL))) ; )
	$(VERBOSE) if ! echo "$(PATH)" | egrep '(^|:)$(INSTALLDIR)(:|$$)' >/dev/null 2>&1 ; then \
		echo "You have to add '$(INSTALLDIR)' to PATH!" ; \
	fi

define LIB_template =
$(1)/lib$(1).a:
	@echo "BUILD		$$@"
	@test -d $1 || git submodule update --init
	$$(VERBOSE) $$(MAKE) $$(BUILDFLAGS_$(1)) -j4 -C $(1) $$(notdir $$@)

$$(LIBDIR)/lib$(1).a: $(1)/lib$(1).a
	@echo "CPY		$$@"
	@mkdir -p $$(@D)
	$$(VERBOSE) cp $$< $$@

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

FORCE:

.PHONY: all examples clean mrproper
