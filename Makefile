DEPDIR := .deps
CXXFLAGS = -std=c++2a -MT $@ -MMD -MP -MF $(DEPDIR)/$@.d -Og -g -I elfo/include/ -I xxhash/ -I capstone/include/
LIBCAPSTONE = capstone/libcapstone.a
LDFLAGS = -lcapstone -Lcapstone
SOURCES := $(wildcard src/*.cpp)
TARGETS := $(notdir $(SOURCES:%.cpp=%))
DEPFILES := $(addprefix $(DEPDIR)/,$(addsuffix .d,$(TARGETS)))

all: $(TARGETS)

%: src/%.cpp Makefile | $(LIBCAPSTONE) $(DEPDIR)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

$(LIBCAPSTONE):
	git submodule update --init
	$(MAKE) CAPSTONE_ARCHS="x86" -C capstone -j 4

$(DEPDIR): ; @mkdir -p $@

$(DEPFILES):

clean::
	rm -f $(DEPFILES)
	rmdir $(DEPDIR) || true

include $(wildcard $(DEPFILES))
