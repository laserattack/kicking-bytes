CXX = g++
CXXFLAGS = -m64 -std=c++17

TEST_NAME = test
HM_NAME = hm

TEST_SOURCE = $(TEST_NAME).cpp
TEST_OBJECT = $(TEST_NAME).o
TEST_BIN = $(TEST_NAME).exe

HM_SOURCE = $(HM_NAME).c
HM_OBJECT = $(HM_NAME).o
HM_HEADER = $(HM_NAME).h

.PHONY: all test clean

all: $(TEST_BIN)

$(TEST_BIN): $(TEST_OBJECT) $(HM_OBJECT)
	$(CXX) $(TEST_OBJECT) $(HM_OBJECT) -o $(TEST_BIN)

$(TEST_OBJECT): $(TEST_SOURCE) $(HM_HEADER)
	$(CXX) $(CXXFLAGS) -c $(TEST_SOURCE) -o $(TEST_OBJECT)

$(HM_OBJECT): $(HM_SOURCE) $(HM_HEADER)
	$(CXX) $(CXXFLAGS) -c $(HM_SOURCE) -o $(HM_OBJECT)

test: all
	./$(TEST_BIN)

clean:
	del $(TEST_BIN) $(TEST_OBJECT) $(HM_OBJECT) 2>nul || true