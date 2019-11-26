TARGET = iphone:clang:11.2:4.3
ARCHS = arm64
GO_EASY_ON_ME = 1

include $(THEOS)/makefiles/common.mk

TOOL_NAME = qd
qd_FILES = $(wildcard *.c)
qd_CODESIGN_FLAGS = -S../tweaks/platform.plist

include $(THEOS_MAKE_PATH)/tool.mk