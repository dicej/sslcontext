build-arch = $(shell uname -m)
ifeq ($(build-arch),i586)
	build-arch = i386
endif
ifeq ($(build-arch),i686)
	build-arch = i386
endif
ifeq ('$(build-arch)','Power Macintosh')
	build-arch = powerpc
endif

build-platform = $(shell uname -s | tr [:upper:] [:lower:])

build-platform = \
	$(shell uname -s | tr [:upper:] [:lower:] \
		| sed 's/^mingw32.*$$/mingw32/' \
		| sed 's/^cygwin.*$$/cygwin/')

arch = $(build-arch)
platform = $(subst cygwin,windows,$(subst mingw32,windows,$(build-platform)))

mode = fast

ifneq ($(mode),fast)
	options := $(options)-$(mode)
endif

bld = build/$(platform)-$(arch)$(options)

cc = gcc
cxx = g++
strip = strip --strip-all
javac = "$(JAVA_HOME)/bin/javac"
jar = "$(JAVA_HOME)/bin/jar"

common-cflags = -Wextra -Werror -Wunused-parameter -Winit-self \
	"-I$(JAVA_HOME)/include" -I$(src) \
	-fno-rtti -fno-exceptions \
	-D__STDC_LIMIT_MACROS -D_JNI_IMPLEMENTATION_

cflags = $(common-cflags) \
	-I$(JAVA_HOME)/include/linux -fvisibility=hidden -fPIC

common-lflags =

lflags = -Wl,--as-needed $(common-lflags) -rdynamic -lpthread -lssl -lcrypto

shared = -shared

so-prefix = lib
so-suffix = .so

ifeq ($(mode),debug)
	cflags += -O0 -g3
	strip = :
endif
ifeq ($(mode),fast)
	cflags += -O3 -g3 -DNDEBUG
endif
ifeq ($(mode),small)
	cflags += -Os -g3 -DNDEBUG
endif

sources := $(shell find src -name '*.java')
classes-dep = build/classes.dep

test-sources := $(shell find test -name '*.java')
test-classes-dep = build/test-classes.dep

test-resources-src := $(shell find test -type f -not -name '*.java')
test-resources-dep = build/test-resources.dep

sslcontext-objects = $(bld)/avian-ssl.o

define dynamic-link
	$(cc) $(^) $(shared) $(shared-lib) $(ssl-dynamic-lflags) $(lflags) \
		-o $(@)
	cp $(@) $(@).dbg
	$(strip) $(@)
endef

.PHONY: build
build: \
	build/sslcontext.jar \
	$(bld)/$(so-prefix)sslcontext$(so-suffix) \
	$(test-classes-dep) \
	$(test-resources-dep)

build/sslcontext.jar: $(classes-dep)
	(cd build/classes && $(jar) cf ../sslcontext.jar $$(find . -name '*.class'))

$(classes-dep): $(sources)
	@mkdir -p build/classes
	$(javac) -d build/classes $(^)
	@touch $(@)

$(test-classes-dep): $(test-sources) build/sslcontext.jar
	@mkdir -p build/test
	$(javac) -classpath build/sslcontext.jar -d build/test $(test-sources)
	@touch $(@)

$(test-resources-dep): $(test-resources-src)
	@mkdir -p build/test
	cp $(test-resources-src) build/test
	@touch $(@)

$(bld)/%.o: src/%.cpp
	@mkdir -p $(dir $(@))
	$(cxx) $(cflags) -c $(<) -o $(@)

$(bld)/$(so-prefix)sslcontext$(so-suffix): $(sslcontext-objects)
	$(dynamic-link)

.PHONY: clean
clean:
	rm -rf build
