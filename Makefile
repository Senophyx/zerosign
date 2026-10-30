# zerosign build system.
#
#   make                  auto-detect the host OS and build the binary
#   make compile mac      build ./zerosign with clang++ and Homebrew paths
#   make compile linux    build ./zerosign with g++ and system paths
#   make compile win      build ./zerosign.exe with g++ (MSYS2/MinGW-w64)
#   make clean            remove build artifacts

SOURCES := zerosign.cpp

BREW_PREFIX       ?= /opt/homebrew
BREW_PREFIX_INTEL ?= /usr/local

PKGS := libcrypto libssl libimobiledevice-1.0 libplist-2.0 libzip zlib

# Host detection. uname covers macOS and the POSIX-like Windows shells; the
# Windows_NT variable covers environments where uname is unavailable.
UNAME_S := $(shell uname -s 2>/dev/null)
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

ifeq ($(HOST),mac)
TARGET   := zerosign
CXX      := clang++
PKG_PATH := $(BREW_PREFIX)/opt/openssl@3/lib/pkgconfig:$(BREW_PREFIX)/lib/pkgconfig:$(BREW_PREFIX_INTEL)/opt/openssl@3/lib/pkgconfig:$(BREW_PREFIX_INTEL)/lib/pkgconfig:/usr/lib/pkgconfig
# $(BREW_PREFIX)/include/openssl is a symlink to whichever OpenSSL the prefix
# currently links. The OpenSSL 3 keg therefore comes first, otherwise a newer
# header set would be paired with the OpenSSL 3 libraries. Paths are added only
# when they exist, so an unused Homebrew prefix does not produce link warnings.
MAC_INCLUDES := $(wildcard $(BREW_PREFIX)/opt/openssl@3/include) \
                $(wildcard $(BREW_PREFIX_INTEL)/opt/openssl@3/include) \
                $(wildcard $(BREW_PREFIX)/include) \
                $(wildcard $(BREW_PREFIX_INTEL)/include)
MAC_LIBS     := $(wildcard $(BREW_PREFIX)/opt/openssl@3/lib) \
                $(wildcard $(BREW_PREFIX_INTEL)/opt/openssl@3/lib) \
                $(wildcard $(BREW_PREFIX)/lib) \
                $(wildcard $(BREW_PREFIX_INTEL)/lib)
EXTRA_CXXFLAGS := $(addprefix -I,$(MAC_INCLUDES))
EXTRA_LDFLAGS  := $(addprefix -L,$(MAC_LIBS))
else ifeq ($(HOST),win)
TARGET   := zerosign.exe
CXX      := g++
PKG_PATH := /ucrt64/lib/pkgconfig:/ucrt64/share/pkgconfig:/mingw64/lib/pkgconfig:/mingw64/share/pkgconfig:/usr/local/lib/pkgconfig:/usr/lib/pkgconfig
EXTRA_CXXFLAGS :=
EXTRA_LDFLAGS  :=
else
TARGET   := zerosign
CXX      := g++
PKG_PATH := /usr/local/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig
EXTRA_CXXFLAGS :=
EXTRA_LDFLAGS  :=
endif

# GNU Make 3.81, still shipped as /usr/bin/make on macOS, does not pass an
# exported variable into $(shell ...) while the makefile is being read. The
# search path therefore has to be given inline, or pkg-config finds nothing and
# both flag lists come back empty.
#
# On Windows the path list uses ';' as separator and pkgconf already defaults to
# the MSYS2 prefix, so the variable is left untouched there.
ifeq ($(HOST),win)
PKG_CFLAGS := $(shell pkg-config --cflags $(PKGS) 2>/dev/null)
PKG_LIBS   := $(shell pkg-config --libs $(PKGS) 2>/dev/null)
else
PKG_CFLAGS := $(shell PKG_CONFIG_PATH="$(PKG_PATH):$$PKG_CONFIG_PATH" pkg-config --cflags $(PKGS) 2>/dev/null)
PKG_LIBS   := $(shell PKG_CONFIG_PATH="$(PKG_PATH):$$PKG_CONFIG_PATH" pkg-config --libs $(PKGS) 2>/dev/null)
endif

# Kept apart from CXXFLAGS so a value from the environment cannot drop the
# language standard this project needs.
CXXSTD   ?= -std=c++17
CXXFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
LDLIBS   := $(PKG_LIBS)

.PHONY: all compile mac linux win clean

all: $(TARGET)

compile: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXSTD) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $(PKG_CFLAGS) -o $@ $(SOURCES) $(EXTRA_LDFLAGS) $(LDLIBS)

# No-op goal markers so the explicit compile targets stay clean.
mac:
	@:

linux:
	@:

win:
	@:

clean:
	rm -f zerosign zerosign.exe *.o
