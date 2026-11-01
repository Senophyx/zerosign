# zerosign build system.
#
#   make                  auto-detect the host OS and build the standalone binary
#   make compile mac      build ./zerosign with clang++ (macOS)
#   make compile linux    build ./zerosign with g++ (Linux)
#   make compile win      build ./zerosign.exe with g++ (MSYS2 UCRT64)
#   make deps             build the static third-party archives only
#   make clean            remove the binary and the whole build directory
#
# Every host links the third-party libraries statically, so the result is one
# file with no companion .dylib, .so, or .dll. OpenSSL is always built from
# source because the packaged archives ship the "legacy" provider as a loadable
# module, and a module is an external file. Built with no-module it lives inside
# libcrypto.a, so older .p12 files unlock on a clean machine.

SOURCES := zerosign.cpp

BUILD_DIR   := build
DEPS_SRC    := $(BUILD_DIR)/src
DEPS_PREFIX := $(BUILD_DIR)/prefix
DEPS_STAMP  := $(DEPS_PREFIX)/.built
DEPS_ABS    := $(abspath $(DEPS_PREFIX))
# Native Windows tools in the msys2 shell reject the /d/a/... mount form, so
# the prefix is also kept in D:/a/... form for CMake and pkg-config there.
DEPS_NATIVE := $(DEPS_ABS)
# pkg-config needs the opposite: /d/a/... has no inner colon, so a ':' separated
# list is not cut at the drive letter by the msys2 runtime.
DEPS_MSYS   := $(DEPS_ABS)
LOG_DIR     := $(abspath $(BUILD_DIR))

OPENSSL_VERSION          ?= 3.5.9
LIBZIP_VERSION           ?= 1.12.1
LIBPLIST_VERSION         ?= 2.8.0
LIMD_GLUE_VERSION        ?= 1.3.3
LIBUSBMUXD_VERSION       ?= 2.1.1
LIBIMOBILEDEVICE_VERSION ?= 1.3.0

OPENSSL_URL := https://github.com/openssl/openssl/releases/download/openssl-$(OPENSSL_VERSION)/openssl-$(OPENSSL_VERSION).tar.gz
LIBZIP_URL  := https://github.com/nih-at/libzip/releases/download/v$(LIBZIP_VERSION)/libzip-$(LIBZIP_VERSION).tar.gz
# libimobiledevice and friends share one release layout.
# One release layout shared by every libimobiledevice project.
imd_release = https://github.com/libimobiledevice/$(1)/releases/download/$(2)/$(1)-$(2).tar.bz2
LIBPLIST_URL         := $(call imd_release,libplist,$(LIBPLIST_VERSION))
LIMD_GLUE_URL        := $(call imd_release,libimobiledevice-glue,$(LIMD_GLUE_VERSION))
LIBUSBMUXD_URL       := $(call imd_release,libusbmuxd,$(LIBUSBMUXD_VERSION))
LIBIMOBILEDEVICE_URL := $(call imd_release,libimobiledevice,$(LIBIMOBILEDEVICE_VERSION))

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
LIBZIP_OPTIONS := -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_TOOLS=OFF -DBUILD_REGRESS=OFF \
                  -DBUILD_EXAMPLES=OFF -DBUILD_DOC=OFF -DENABLE_BZIP2=OFF \
                  -DENABLE_LZMA=OFF -DENABLE_ZSTD=OFF -DENABLE_OPENSSL=OFF \
                  -DENABLE_GNUTLS=OFF -DENABLE_MBEDTLS=OFF \
                  -DENABLE_COMMONCRYPTO=OFF -DENABLE_WINDOWS_CRYPTO=OFF

PKG_SEP := :

ifeq ($(HOST),mac)
TARGET   := zerosign
CXX      := clang++
PKG_PATH := $(DEPS_ABS)/lib/pkgconfig:$(BREW_PREFIX)/lib/pkgconfig:$(BREW_PREFIX_INTEL)/lib/pkgconfig:/usr/lib/pkgconfig
EXTRA_CXXFLAGS := -I$(DEPS_ABS)/include
EXTRA_LDFLAGS  :=
EXTRA_LDLIBS   :=
# ld64 re-scans an archive until nothing new resolves, so no linker group.
ARCHIVE_OPEN   :=
else ifeq ($(HOST),win)
TARGET   := zerosign.exe
CXX      := g++
CMAKE_GENERATOR := -G Ninja
# UCRT64 only: libimobiledevice is packaged for UCRT64, CLANG64 and CLANGARM64,
# and mixing the MINGW64 archives into a UCRT64 link breaks the link.
#
# mingw32-make is a native binary, so $(abspath) already yields D:/a/..., and a
# ':' separated list starting with a drive letter is cut there by pkgconf. The
# /d/a/... form has no inner colon and is translated back to D:\ on spawn.
DEPS_MSYS   := $(shell cygpath -u "$(DEPS_ABS)" 2>/dev/null || echo "$(DEPS_ABS)")
PKG_PATH    := $(DEPS_MSYS)/lib/pkgconfig:/ucrt64/lib/pkgconfig:/ucrt64/share/pkgconfig
# Native CMake and the OpenSSL Configure script run under native perl and need
# the D:/a/... form instead, which both the shell and the tools still accept.
DEPS_NATIVE := $(shell cygpath -m "$(DEPS_ABS)" 2>/dev/null || echo "$(DEPS_ABS)")
# The static archives carry no __declspec(dllimport) stubs. gcc here is native,
# so its -I path uses the D:/a/... form. ZIP_STATIC is left out on purpose:
# the libzip we build writes it into zipconf.h already.
EXTRA_CXXFLAGS := -I$(DEPS_NATIVE)/include -DLIBIMOBILEDEVICE_STATIC -DLIBUSBMUXD_STATIC -DLIBPLIST_STATIC
EXTRA_LDFLAGS  := -static -static-libgcc -static-libstdc++
EXTRA_LDLIBS   := -lws2_32 -lcrypt32 -liphlpapi -lbcrypt -lgdi32 -luserenv -ladvapi32 -lole32
ARCHIVE_OPEN   := -Wl,--start-group
ARCHIVE_CLOSE  := -Wl,--end-group
else
TARGET   := zerosign
CXX      := g++
CMAKE_GENERATOR :=
PKG_PATH := $(DEPS_ABS)/lib/pkgconfig:/usr/local/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig
EXTRA_CXXFLAGS := -I$(DEPS_ABS)/include
EXTRA_LDFLAGS  := -static-libgcc -static-libstdc++
EXTRA_LDLIBS   := -ldl -lpthread -lm
# GNU ld walks the link line once, so archives that reference each other need a
# group to be rescanned.
ARCHIVE_OPEN   := -Wl,--start-group
ARCHIVE_CLOSE  := -Wl,--end-group
endif

# Debian and Ubuntu build libimobiledevice against GnuTLS and ship no static
# archive for it, so Linux compiles the whole device stack here against the
# OpenSSL built below. macOS and Windows take the packaged archives, which are
# already OpenSSL based and already static.
DEPS_TARGETS := $(DEPS_PREFIX)/.openssl-$(OPENSSL_VERSION) $(DEPS_PREFIX)/.libzip-$(LIBZIP_VERSION)
# The whole device stack is compiled here on Windows and Linux: the packaged
# MSYS2 archives are built for DLL import (they reference __imp_* symbols) and
# carry no static libraries for plist/usbmuxd, so linking them statically fails.
# macOS takes the Homebrew archives, which are built for static linking.
ifeq ($(filter $(HOST),linux win),$(HOST))
DEPS_TARGETS += $(DEPS_PREFIX)/.libimobiledevice-$(LIBIMOBILEDEVICE_VERSION)
endif

# Configures, builds and installs one release tarball as static archives.
#   $(1) log and stamp name, $(2) source url, $(3) extra configure arguments
#   $(4) optional fixup run inside the extracted tree
# The log path is absolute because the recipe changes directory first.
define build_autotools_deps
	@mkdir -p $(DEPS_SRC) $(DEPS_PREFIX)
	curl -fsSL $(2) | tar -xj -C $(DEPS_SRC)
	$(4)
	cd $(DEPS_SRC)/$(basename $(basename $(notdir $(2)))) && \
	    lt_cv_deplibs_check_method=pass_all PKG_CONFIG_PATH=$(DEPS_MSYS)/lib/pkgconfig ./configure --prefix=$(DEPS_NATIVE) \
	    --disable-shared --enable-static $(3) > $(LOG_DIR)/$(1).log 2>&1
	$(MAKE) -C $(DEPS_SRC)/$(basename $(basename $(notdir $(2)))) -j$(JOBS) >> $(LOG_DIR)/$(1).log 2>&1 || { tail -n 40 $(LOG_DIR)/$(1).log; exit 1; }
	$(MAKE) -C $(DEPS_SRC)/$(basename $(basename $(notdir $(2)))) install >> $(LOG_DIR)/$(1).log 2>&1
	@touch $(DEPS_PREFIX)/.$(1)
endef

# libimobiledevice 1.3.0 still declares its own plist_format_t, which libplist
# now ships in plist.h, so the declaration is dropped and the shipped type used.
# Upstream fixed this by moving the helpers into libimobiledevice-glue.
IMD_FIXUP := cd $(DEPS_SRC)/libimobiledevice-$(LIBIMOBILEDEVICE_VERSION) && \
	    sed -i '/^enum plist_format_t {$$/,/^};$$/d' common/utils.h && \
	    sed -i 's/enum plist_format_t format/plist_format_t format/' common/utils.h common/utils.c

# Kept apart from CXXFLAGS so a value from the environment cannot drop the
# language standard this project needs.
CXXSTD   ?= -std=c++17
CXXFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter

.PHONY: all compile mac linux win deps clean test

all: $(TARGET)

compile: $(TARGET)

$(TARGET): $(SOURCES) $(DEPS_STAMP)
	@mkdir -p $(BUILD_DIR)
	@export PKG_CONFIG_PATH="$(PKG_PATH)$${PKG_CONFIG_PATH:+$(PKG_SEP)$$PKG_CONFIG_PATH}"; \
	set -e; \
	cflags=$$(pkg-config --cflags $(PKGS)); \
	libs=$$(pkg-config --static --libs $(PKGS)); \
	dirs="$(DEPS_MSYS)/lib"; \
	for p in $(PKGS); do dirs="$$dirs $$(pkg-config --variable=libdir $$p)"; done; \
	archives=""; \
	for tok in $$libs; do \
	  case "$$tok" in \
	    -L*) dirs="$$dirs $${tok#-L}";; \
	    -l*) name=$${tok#-l}; found=""; \
	         for d in $$dirs; do \
	           if [ -f "$$d/lib$$name.a" ]; then found="$$d/lib$$name.a"; break; fi; \
	         done; \
	         if [ -z "$$found" ]; then found=$$tok; fi; \
	         archives="$$archives $$found";; \
	    *) archives="$$archives $$tok";; \
	  esac; \
	done; \
	echo "$(CXX) -o $(TARGET)"; \
	for a in $$archives; do echo "  $$a"; done; \
	$(CXX) $(CXXSTD) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $$cflags -o $(TARGET) $(SOURCES) \
	    $(ARCHIVE_OPEN) $$archives $(ARCHIVE_CLOSE) $(EXTRA_LDFLAGS) $(EXTRA_LDLIBS)

deps: $(DEPS_STAMP)

$(DEPS_STAMP): $(DEPS_TARGETS)
	@touch $@

$(DEPS_PREFIX)/.openssl-$(OPENSSL_VERSION):
	@mkdir -p $(DEPS_SRC) $(DEPS_PREFIX)
	curl -fsSL $(OPENSSL_URL) | tar -xz -C $(DEPS_SRC)
	cd $(DEPS_SRC)/openssl-$(OPENSSL_VERSION) && ./Configure $(OPENSSL_TARGET) $(OPENSSL_OPTIONS) --prefix=$(DEPS_NATIVE) --libdir=lib --openssldir=$(DEPS_NATIVE)/ssl
	$(MAKE) -C $(DEPS_SRC)/openssl-$(OPENSSL_VERSION) -j$(JOBS) > $(BUILD_DIR)/openssl.log 2>&1 || { tail -n 40 $(BUILD_DIR)/openssl.log; exit 1; }
	$(MAKE) -C $(DEPS_SRC)/openssl-$(OPENSSL_VERSION) install_sw >> $(BUILD_DIR)/openssl.log 2>&1
	@touch $@

$(DEPS_PREFIX)/.libzip-$(LIBZIP_VERSION):
	@mkdir -p $(DEPS_SRC) $(DEPS_PREFIX)
	curl -fsSL $(LIBZIP_URL) | tar -xz -C $(DEPS_SRC)
	cmake -S $(DEPS_SRC)/libzip-$(LIBZIP_VERSION) -B $(BUILD_DIR)/libzip $(CMAKE_GENERATOR) \
	    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$(DEPS_NATIVE) $(LIBZIP_OPTIONS) \
	    > $(BUILD_DIR)/libzip.log 2>&1
	cmake --build $(BUILD_DIR)/libzip --parallel $(JOBS) >> $(BUILD_DIR)/libzip.log 2>&1 || { tail -n 40 $(BUILD_DIR)/libzip.log; exit 1; }
	cmake --install $(BUILD_DIR)/libzip >> $(BUILD_DIR)/libzip.log 2>&1
	@touch $@

LIBPLIST_STAMP         := $(DEPS_PREFIX)/.libplist-$(LIBPLIST_VERSION)
LIMD_GLUE_STAMP        := $(DEPS_PREFIX)/.libimobiledevice-glue-$(LIMD_GLUE_VERSION)
LIBUSBMUXD_STAMP       := $(DEPS_PREFIX)/.libusbmuxd-$(LIBUSBMUXD_VERSION)
LIBIMOBILEDEVICE_STAMP := $(DEPS_PREFIX)/.libimobiledevice-$(LIBIMOBILEDEVICE_VERSION)

$(LIBPLIST_STAMP):
	$(call build_autotools_deps,libplist-$(LIBPLIST_VERSION),$(LIBPLIST_URL),--without-cython)

$(LIMD_GLUE_STAMP): $(LIBPLIST_STAMP)
	$(call build_autotools_deps,libimobiledevice-glue-$(LIMD_GLUE_VERSION),$(LIMD_GLUE_URL),)

$(LIBUSBMUXD_STAMP): $(LIBPLIST_STAMP) $(LIMD_GLUE_STAMP)
	$(call build_autotools_deps,libusbmuxd-$(LIBUSBMUXD_VERSION),$(LIBUSBMUXD_URL),)

$(LIBIMOBILEDEVICE_STAMP): $(LIBPLIST_STAMP) $(LIMD_GLUE_STAMP) $(LIBUSBMUXD_STAMP) $(DEPS_PREFIX)/.openssl-$(OPENSSL_VERSION)
	$(call build_autotools_deps,libimobiledevice-$(LIBIMOBILEDEVICE_VERSION),$(LIBIMOBILEDEVICE_URL),--without-cython,$(IMD_FIXUP))

# No-op goal markers so the explicit compile targets stay clean.
mac:
	@:

linux:
	@:

win:
	@:

test: $(TARGET)
	python3 tests/test_zerosign.py

clean:
	rm -rf $(TARGET) zerosign zerosign.exe *.o $(BUILD_DIR)
