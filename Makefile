#CXX=clang++
CXX = g++

DEP_FLAGS = -DTESTING

FIN_FLAGS =

PRINT_FLAGS = -DPRINT_TIME

HOSTDIR = ../Host

# ***************** YOU SHOULD NOT SET CXXFLAGS IN THIS FILE *****************

MCXXFLAGS := -g -std=c++17 -Wall -O2 $(DEP_FLAGS) $(FIN_FLAGS) $(PRINT_FLAGS) $(CXXFLAGS) $(TARGET_ARCH) -U__STRICT_ANSI__

LDLIBS =
IDIR = -I $(HOSTDIR)/ -I $(HOSTDIR)/util/
HOSTSRCS = RecOnlyHost.C 
LINUXSRCS = WinConsumer.C WinParser.C main.C

SRCS = $(HOSTSRCS) $(LINUXSRCS)
HOSTOBJS = $(HOSTSRCS:%.C=%.o)
LINUXOBJS = $(LINUXSRCS:%.C=%.o)

DEPDIR := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
COMPILE.C = $(CXX) $(DEPFLAGS) $(MCXXFLAGS) -c
POSTCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

# Disable default rules. It seems hard to ensure that our patterns rules
# fire, instead of the default rules.
.SUFFIXES:

%.o: %.c $(DEPDIR)/%.d
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o: %.C cxx_flags $(DEPDIR)/%.d 
	$(COMPILE.C)  $(IDIR) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o: $(HOSTDIR)/%.C $(DEPDIR)/%.d cxx_flags
	$(COMPILE.C) $(IDIR) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

$(DEPDIR)/%.d: ;
.PRECIOUS: $(DEPDIR)/%.d

.PHONY: force

cxx_flags: force
	echo '$(MCXXFLAGS)' | tr " " '\n' | grep -v '^$$' | sort -u | diff -q $@ - || echo '$(MCXXFLAGS)' | tr " " '\n' | grep -v '^$$' | sort -u  > $@

main: $(HOSTOBJS) $(LINUXOBJS)
	$(CXX) $(LDFLAGS) -o $@ $^  $(IDIR) $(LDLIBS)

include $(wildcard $(patsubst %,$(DEPDIR)/%.d,$(basename $(SRCS))))

clean:
	rm -f cxx_flags main *.o .d/*.d
