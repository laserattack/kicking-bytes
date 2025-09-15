# Compiler and flags
CXX = g++
CXXFLAGS = -m64 -std=c++17

# DLL configuration
DLL_NAME = inject
DLL_SOURCE = $(DLL_NAME).cpp
DLL_OBJECT = $(DLL_NAME).o
DLL_BIN = $(DLL_NAME).dll

# Injector configuration  
INJECTOR_NAME = injector
INJECTOR_SOURCE = $(INJECTOR_NAME).cpp
INJECTOR_OBJECT = $(INJECTOR_NAME).o
INJECTOR_BIN = $(INJECTOR_NAME).exe

# Default target
all: $(DLL_BIN) $(INJECTOR_BIN)

# Build DLL
$(DLL_BIN): $(DLL_SOURCE)
	$(CXX) $(CXXFLAGS) -shared -o $(DLL_BIN) $(DLL_SOURCE)

# Build injector
$(INJECTOR_BIN): $(INJECTOR_SOURCE)
	$(CXX) $(CXXFLAGS) -o $(INJECTOR_BIN) $(INJECTOR_SOURCE)

# Clean
clean:
	del $(DLL_BIN) $(INJECTOR_BIN) $(DLL_OBJECT) $(INJECTOR_OBJECT) 2>nul || true

.PHONY: all clean