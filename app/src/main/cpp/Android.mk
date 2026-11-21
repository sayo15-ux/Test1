LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := dexprotection
LOCAL_SRC_FILES := bytes.cpp dex_read.cpp dex_write.cpp strings.cpp signature.cpp payloads.cpp shield_stub.cpp archive.cpp manifest.cpp engine.cpp jni_bridge.cpp ../../../build/generated/shield/shield_payloads.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_CPPFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -fexceptions -frtti
LOCAL_CFLAGS := -D_FILE_OFFSET_BITS=64
LOCAL_LDLIBS := -lz -llog
LOCAL_LDFLAGS := -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384
include $(BUILD_SHARED_LIBRARY)
