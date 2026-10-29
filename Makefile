# csign build system.
#
#   make                  auto-detect the host OS and build ./csign
#   make compile mac      build with clang++ and Homebrew library paths
#   make compile linux    build with g++ and system library paths
#   make clean            remove build artifacts

TARGET  := csign
SOURCES := csign.cpp

BREW_PREFIX       ?= /opt/homebrew
BREW_PREFIX_INTEL ?= /usr/local

PKGS := libcrypto libssl libimobiledevice-1.0 libplist-2.0 libzip zlib

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
HOST ?= mac
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

ifeq ($(HOST),mac)
CXX      := clang++
PKG_PATH := $(BREW_PREFIX)/lib/pkgconfig:$(BREW_PREFIX)/opt/openssl@3/lib/pkgconfig:$(BREW_PREFIX)/opt/openssl/lib/pkgconfig:$(BREW_PREFIX_INTEL)/lib/pkgconfig:$(BREW_PREFIX_INTEL)/opt/openssl@3/lib/pkgconfig:/usr/lib/pkgconfig
EXTRA_CXXFLAGS := -I$(BREW_PREFIX)/include -I$(BREW_PREFIX_INTEL)/include
EXTRA_LDFLAGS  := -L$(BREW_PREFIX)/lib -L$(BREW_PREFIX_INTEL)/lib
else
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

.PHONY: all compile mac linux clean

all: $(TARGET)

compile: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXSTD) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $(PKG_CFLAGS) -o $@ $(SOURCES) $(EXTRA_LDFLAGS) $(LDLIBS)

# No-op goal markers so "make compile mac" and "make compile linux" stay clean.
mac:
	@:

linux:
	@:

clean:
	rm -f $(TARGET) *.o
