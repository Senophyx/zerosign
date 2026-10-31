# zerosign build system.
#
#   make                  auto-detect the host OS and build the standalone binary
#   make compile mac      build ./zerosign with clang++ (macOS)
#   make compile linux    build ./zerosign with g++ (Linux)
#   make compile win      build ./zerosign.exe with g++ (MSYS2/MinGW-w64)
#   make deps             build the static third-party archives only
#   make clean            remove the binary and the whole build directory
#
# Every host links the third-party libraries statically, so the result is one
# file with no companion .dylib, .so, or .dll. OpenSSL is built from source
# here because the packaged archives ship the "legacy" provider as a loadable
# module, and a module is an external file. Built with no-module it lives
# inside libcrypto.a and older .p12 files unlock on a clean machine.

SOURCES := zerosign.cpp

BUILD_DIR   := build
DEPS_SRC    := $(BUILD_DIR)/src
DEPS_PREFIX := $(BUILD_DIR)/prefix
DEPS_STAMP  := $(DEPS_PREFIX)/.built
DEPS_ABS    := $(abspath $(DEPS_PREFIX))

OPENSSL_VERSION  ?= 3.5.9
LIBZIP_VERSION   ?= 1.12.1
LIBPLIST_VERSION ?= 2.8.0

OPENSSL_URL  := https://github.com/openssl/openssl/releases/download/openssl-$(OPENSSL_VERSION)/openssl-$(OPENSSL_VERSION).tar.gz
LIBZIP_URL   := https://github.com/nih-at/libzip/releases/download/v$(LIBZIP_VERSION)/libzip-$(LIBZIP_VERSION).tar.gz
LIBPLIST_URL := https://github.com/libimobiledevice/libplist/releases/download/$(LIBPLIST_VERSION)/libplist-$(LIBPLIST_VERSION).tar.bz2

BREW_PREFIX       ?= /opt/homebrew
BREW_PREFIX_INTEL ?= /usr/local

PKGS := libcrypto libssl libimobiledevice-1.0 libplist-2.0 libzip zlib

UNAME_S := $(shell uname -s 2>/dev/null)
UNAME_M := $(shell uname -m 2>/dev/null)
JOBS    ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)

# Host detection. uname covers macOS and the POSIX-like Windows shells; the
# Windows_NT variable covers environments where uname is unavailable.
ifeq ($(UNAME_S),Darwin)
HOST ?= mac
else ifneq (,$(filter MINGW% MSYS% CYGWIN%,$(UNAME_S)))
HOST ?= win
else ifdef Windows_NT
HOST ?= win
else
HOST ?= linux
endif

# Explicit goals win over host auto-detection.
ifneq (,$(filter mac,$(MAKECMDGOALS)))
override HOST := mac
endif
ifneq (,$(filter linux,$(MAKECMDGOALS)))
override HOST := linux
endif
ifneq (,$(filter win,$(MAKECMDGOALS)))
override HOST := win
endif

# OpenSSL's Configure target name differs per host and architecture.
ifeq ($(HOST),mac)
OPENSSL_TARGET := $(if $(filter arm64 aarch64,$(UNAME_M)),darwin64-arm64-cc,darwin64-x86_64-cc)
else ifeq ($(HOST),win)
OPENSSL_TARGET := mingw64
else
OPENSSL_TARGET := $(if $(filter arm64 aarch64,$(UNAME_M)),linux-aarch64,linux-x86_64)
endif

# no-dso and no-module compile the legacy provider into libcrypto.a instead of
# installing it as a separate module. no-asm keeps the build free of a NASM
# dependency, and nothing here needs the command line tools.
OPENSSL_OPTIONS := no-shared no-module no-dso no-tests no-apps no-docs no-zlib no-asm enable-legacy

# IPAs use deflate or stored entries only, so libzip's optional compression and
# encryption backends would only drag more static archives into the link.
LIBZIP_OPTIONS := -DBUILD_SHARED_LIBS=OFF -DBUILD_TOOLS=OFF -DBUILD_REGRESS=OFF \
                  -DBUILD_EXAMPLES=OFF -DBUILD_DOC=OFF -DENABLE_BZIP2=OFF \
                  -DENABLE_LZMA=OFF -DENABLE_ZSTD=OFF -DENABLE_OPENSSL=OFF \
                  -DENABLE_GNUTLS=OFF -DENABLE_MBEDTLS=OFF \
                  -DENABLE_COMMONCRYPTO=OFF -DENABLE_WINDOWS_CRYPTO=OFF

ifeq ($(HOST),mac)
TARGET   := zerosign
CXX      := clang++
PKG_SEP  := :
CMAKE_GENERATOR :=
PKG_PATH := $(DEPS_ABS)/lib/pkgconfig:$(BREW_PREFIX)/lib/pkgconfig:$(BREW_PREFIX_INTEL)/lib/pkgconfig:/usr/lib/pkgconfig
EXTRA_CXXFLAGS := -I$(DEPS_ABS)/include
EXTRA_LDFLAGS  :=
EXTRA_LDLIBS   :=
else ifeq ($(HOST),win)
TARGET   := zerosign.exe
CXX      := g++
PKG_SEP  := ;
CMAKE_GENERATOR := -G Ninja
PKG_PATH := $(DEPS_ABS)/lib/pkgconfig
# The static archives were built without __declspec(dllimport) stubs.
EXTRA_CXXFLAGS := -I$(DEPS_ABS)/include -DLIBIMOBILEDEVICE_STATIC -DLIBUSBMUXD_STATIC -DLIBPLIST_STATIC -DZIP_STATIC
EXTRA_LDFLAGS  := -static -static-libgcc -static-libstdc++
EXTRA_LDLIBS   := -lws2_32 -lcrypt32 -liphlpapi -lbcrypt -lgdi32 -luserenv -ladvapi32 -lole32
else
TARGET   := zerosign
CXX      := g++
PKG_SEP  := :
CMAKE_GENERATOR :=
PKG_PATH := $(DEPS_ABS)/lib/pkgconfig:/usr/local/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig
EXTRA_CXXFLAGS := -I$(DEPS_ABS)/include
EXTRA_LDFLAGS  := -static-libgcc -static-libstdc++
EXTRA_LDLIBS   := -ldl -lpthread -lm
endif

# Debian and Ubuntu ship no libplist archive, so Linux builds it here. Every
# host builds OpenSSL and libzip, which keeps all three platforms identical.
DEPS_TARGETS := $(DEPS_PREFIX)/.openssl-$(OPENSSL_VERSION) $(DEPS_PREFIX)/.libzip-$(LIBZIP_VERSION)
ifeq ($(HOST),linux)
DEPS_TARGETS += $(DEPS_PREFIX)/.libplist-$(LIBPLIST_VERSION)
endif

# Kept apart from CXXFLAGS so a value from the environment cannot drop the
# language standard this project needs.
CXXSTD   ?= -std=c++17
CXXFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter

.PHONY: all compile mac linux win deps clean

all: $(TARGET)

compile: $(TARGET)

$(TARGET): $(SOURCES) $(DEPS_STAMP)
	@mkdir -p $(BUILD_DIR)
	@export PKG_CONFIG_PATH="$(PKG_PATH)$${PKG_CONFIG_PATH:+$(PKG_SEP)$$PKG_CONFIG_PATH}"; \
	set -e; \
	cflags=$$(pkg-config --cflags $(PKGS)); \
	libs=$$(pkg-config --static --libs $(PKGS)); \
	dirs="$(DEPS_ABS)/lib"; \
	tokens=""; \
	for tok in $$libs; do \
	  case "$$tok" in -L*) dirs="$$dirs $${tok#-L}";; *) tokens="$$tokens $$tok";; esac; \
	done; \
	archives=""; \
	for tok in $$tokens; do \
	  case "$$tok" in \
	    -l*) name=$${tok#-l}; found=""; \
	         for d in $$dirs; do \
	           if [ -f "$$d/lib$$name.a" ]; then found="$$d/lib$$name.a"; break; fi; \
	         done; \
	         if [ -z "$$found" ]; then found=$$tok; fi; \
	         case " $$archives " in *" $$found "*) ;; *) archives="$$archives $$found";; esac;; \
	    *) archives="$$archives $$tok";; \
	  esac; \
	done; \
	echo "$(CXX) -o $(TARGET)"; \
	for a in $$archives; do echo "  $$a"; done; \
	$(CXX) $(CXXSTD) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $$cflags -o $(TARGET) $(SOURCES) $$archives $(EXTRA_LDFLAGS) $(EXTRA_LDLIBS)

deps: $(DEPS_STAMP)

$(DEPS_STAMP): $(DEPS_TARGETS)
	@touch $@

$(DEPS_PREFIX)/.openssl-$(OPENSSL_VERSION):
	@mkdir -p $(DEPS_SRC) $(DEPS_PREFIX)
	curl -fsSL $(OPENSSL_URL) | tar -xz -C $(DEPS_SRC)
	cd $(DEPS_SRC)/openssl-$(OPENSSL_VERSION) && ./Configure $(OPENSSL_TARGET) $(OPENSSL_OPTIONS) --prefix=$(DEPS_ABS) --openssldir=$(DEPS_ABS)/ssl
	$(MAKE) -C $(DEPS_SRC)/openssl-$(OPENSSL_VERSION) -j$(JOBS) > $(BUILD_DIR)/openssl.log 2>&1 || { tail -n 40 $(BUILD_DIR)/openssl.log; exit 1; }
	$(MAKE) -C $(DEPS_SRC)/openssl-$(OPENSSL_VERSION) install_sw >> $(BUILD_DIR)/openssl.log 2>&1
	@touch $@

$(DEPS_PREFIX)/.libzip-$(LIBZIP_VERSION):
	@mkdir -p $(DEPS_SRC) $(DEPS_PREFIX)
	curl -fsSL $(LIBZIP_URL) | tar -xz -C $(DEPS_SRC)
	cmake -S $(DEPS_SRC)/libzip-$(LIBZIP_VERSION) -B $(BUILD_DIR)/libzip $(CMAKE_GENERATOR) \
	    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$(DEPS_ABS) $(LIBZIP_OPTIONS) \
	    > $(BUILD_DIR)/libzip.log 2>&1
	cmake --build $(BUILD_DIR)/libzip --parallel $(JOBS) >> $(BUILD_DIR)/libzip.log 2>&1 || { tail -n 40 $(BUILD_DIR)/libzip.log; exit 1; }
	cmake --install $(BUILD_DIR)/libzip >> $(BUILD_DIR)/libzip.log 2>&1
	@touch $@

$(DEPS_PREFIX)/.libplist-$(LIBPLIST_VERSION):
	@mkdir -p $(DEPS_SRC) $(DEPS_PREFIX)
	curl -fsSL $(LIBPLIST_URL) | tar -xj -C $(DEPS_SRC)
	cd $(DEPS_SRC)/libplist-$(LIBPLIST_VERSION) && ./configure --prefix=$(DEPS_ABS) \
	    --disable-shared --enable-static --without-cython > $(BUILD_DIR)/libplist.log 2>&1
	$(MAKE) -C $(DEPS_SRC)/libplist-$(LIBPLIST_VERSION) -j$(JOBS) >> $(BUILD_DIR)/libplist.log 2>&1 || { tail -n 40 $(BUILD_DIR)/libplist.log; exit 1; }
	$(MAKE) -C $(DEPS_SRC)/libplist-$(LIBPLIST_VERSION) install >> $(BUILD_DIR)/libplist.log 2>&1
	@touch $@

# No-op goal markers so the explicit compile targets stay clean.
mac:
	@:

linux:
	@:

win:
	@:

clean:
	rm -rf $(TARGET) zerosign zerosign.exe *.o $(BUILD_DIR)
