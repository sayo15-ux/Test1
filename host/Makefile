CXX ?= c++
.DEFAULT_GOAL := dexpack
CPP := ../app/src/main/cpp
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Wpedantic
GENERATED := ../app/build/generated/shield/shield_payloads.cpp
FANCY_GENERATED := ../app/build/generated/fancy/fancy_payloads.cpp
SOURCES := $(CPP)/bytes.cpp $(CPP)/dex_read.cpp $(CPP)/dex_write.cpp $(CPP)/strings.cpp $(CPP)/signature.cpp $(CPP)/payloads.cpp $(CPP)/shield_stub.cpp $(GENERATED) $(FANCY_GENERATED) $(CPP)/archive.cpp $(CPP)/manifest.cpp $(CPP)/engine.cpp main.cpp

$(GENERATED):
	cd .. && ./gradlew :app:generateShieldPayloads

$(FANCY_GENERATED):
	cd .. && ./gradlew :app:generateFancyPayloads

dexpack: $(SOURCES) $(wildcard $(CPP)/*.hpp)
	$(CXX) $(CXXFLAGS) -I$(CPP) $(SOURCES) -lz -o $@

clean:
	rm -f dexpack native-tests shield-tests

native-tests: $(filter-out main.cpp,$(SOURCES)) tests.cpp $(wildcard $(CPP)/*.hpp)
	$(CXX) $(CXXFLAGS) -I$(CPP) $(filter-out main.cpp,$(SOURCES)) tests.cpp -lz -o $@

test: native-tests
	./native-tests

shield-tests: $(filter-out main.cpp,$(SOURCES)) ../shield/src/main/cpp/payload.cpp shield_tests.cpp
	$(CXX) $(CXXFLAGS) -I$(CPP) -I../shield/src/main/cpp $(filter-out main.cpp,$(SOURCES)) ../shield/src/main/cpp/payload.cpp shield_tests.cpp -lz -o $@

.PHONY: clean test
