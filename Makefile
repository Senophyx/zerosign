# csign build system.
#
#   make                  auto-detect the host OS and build the binary
#   make compile mac      build ./csign with clang++ and Homebrew paths
#   make compile linux    build ./csign with g++ and system paths
#   make compile win      build ./csign.exe with g++ (MSYS2/MinGW-w64)
#   make clean            remove build artifacts

SOURCES := csign.cpp

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
TARGET   := csign
CXX      := clang++
PKG_PATH := $(BREW_PREFIX)/lib/pkgconfig:$(BREW_PREFIX)/opt/openssl@3/lib/pkgconfig:$(BREW_PREFIX)/opt/openssl/lib/pkgconfig:$(BREW_PREFIX_INTEL)/lib/pkgconfig:$(BREW_PREFIX_INTEL)/opt/openssl@3/lib/pkgconfig:/usr/lib/pkgconfig
EXTRA_CXXFLAGS := -I$(BREW_PREFIX)/include -I$(BREW_PREFIX_INTEL)/include
EXTRA_LDFLAGS  := -L$(BREW_PREFIX)/lib -L$(BREW_PREFIX_INTEL)/lib
else ifeq ($(HOST),win)
TARGET   := csign.exe
CXX      := g++
PKG_PATH := /mingw64/lib/pkgconfig:/mingw64/share/pkgconfig:/usr/local/lib/pkgconfig:/usr/lib/pkgconfig
EXTRA_CXXFLAGS :=
EXTRA_LDFLAGS  :=
else
TARGET   := csign
CXX      := g++
PKG_PATH := /usr/local/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig
EXTRA_CXXFLAGS :=
EXTRA_LDFLAGS  :=
endif

export PKG_CONFIG_PATH := $(PKG_PATH):$(PKG_CONFIG_PATH)

PKG_CFLAGS := $(shell pkg-config --cflags $(PKGS) 2>/dev/null)
PKG_LIBS   := $(shell pkg-config --libs $(PKGS) 2>/dev/null)

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
	rm -f csign csign.exe *.o
