LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := ScKitShieldV1
LOCAL_SRC_FILES := loader.cpp payload.cpp ../../../../app/src/main/cpp/archive.cpp ../../../../app/src/main/cpp/bytes.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../../../app/src/main/cpp
LOCAL_CPPFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -fexceptions -frtti -ffunction-sections -fdata-sections -fvisibility=hidden -fvisibility-inlines-hidden
LOCAL_LDLIBS := -lz
LOCAL_LDFLAGS := -Wl,--gc-sections -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384
include $(BUILD_SHARED_LIBRARY)
