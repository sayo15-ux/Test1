LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := fancy-bypass
LOCAL_SRC_FILES := ../fancy_bypass.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/..
LOCAL_CPPFLAGS := -std=c++17 -Wall -Wextra -fexceptions
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)
