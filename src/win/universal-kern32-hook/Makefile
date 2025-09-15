CXX = g++
CXXFLAGS = -m64 -std=c++17
SOURCE = hook-app.cpp
BIN = hook-app.exe

.PHONY: all run clean test

all: $(BIN)

$(BIN): $(SOURCE)
	$(CXX) $(CXXFLAGS) $(SOURCE) -o $(BIN)

run: all
	./$(BIN)

clean:
	del $(BIN) *.o 2>nul
	
test: all run clean