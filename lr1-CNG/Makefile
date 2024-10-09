CC = gcc
ERRORS = -Wall
# -Wall
# -Wextra
# -Werror
# -Wpedantic
# -Wno-unused-variable
# -Wfatal-errors
CFLAGS = -c $(ERRORS) -fPIC -std=c11
# CFLAGS += -D _DEBUG
BUILD_DIR = build
EXE_NAME = cifs
SOURCES = $(wildcard *.c)
HEADERS = $(wildcard *.h)
C_INCLUDE_PATH = -I. -I./src/ -I./src/libkcapi/lib/
C_LIBS =

# include sources in subdirectories
KCAPI_DIR = ./src/libkcapi/lib/
KCAPI_INCLUDE_PATH = -I$(KCAPI_DIR)
KCAPI_SOURCES = $(wildcard $(KCAPI_DIR)*.c)

# add ./ to the beginning of the sources
KCAPI_HEADERS = $(wildcard $(KCAPI_DIR)*.h)
KCAPI_FLAGS = -D KCAPI_PATCHLEVEL=1 -D KCAPI_MAJVERSION=1 -D KCAPI_MINVERSION=1 -D CLOCK_REALTIME=0
KCAPI_FLAGS += -Wno-implicit-function-declaration


KCAPI_OBJECTS = $(KCAPI_SOURCES:$(KCAPI_DIR)%.c=$(BUILD_DIR)/%.o)

TARGET = 
ifeq ($(OS),Windows_NT)
TARGET = windows
else
TARGET = linux
endif

ifeq ($(TARGET),windows)
RM = rm
COPY = copy
SYS_FLAGS = -D _WIN32
EXE_EXTENSION = .exe
ARCHIVE_EXTENSION = .lib
OBJECT_EXTENSION = .obj
ECHO = @echo
SYS_MSG = "Windows_NT detected!"
C_LIBS += -lbcrypt
else
RM = rm -rf
COPY = cp
SYS_FLAGS = -D  
EXE_EXTENSION =
ARCHIVE_EXTENSION = .a
OBJECT_EXTENSION = .o
ECHO = @echo
SYS_MSG = "Linux detected!"
C_LIBS += -lkcapi
endif



all: clean_build

# libkcapi ---==================================================================

$(BUILD_DIR)/libkcapi$(ARCHIVE_EXTENSION): platform $(KCAPI_OBJECTS)
	$(ECHO) "Building libkcapi$(ARCHIVE_EXTENSION)"
	$(AR) rcs $(BUILD_DIR)/libkcapi$(ARCHIVE_EXTENSION) $(KCAPI_OBJECTS)

$(BUILD_DIR)/%$(OBJECT_EXTENSION): $(KCAPI_DIR)%.c | build_dir platform
# $(ECHO) "Compiling $<"
	$(CC) $(CFLAGS) $(KCAPI_FLAGS) $(SYS_FLAGS) $(KCAPI_INCLUDE_PATH) $(C_LIBS) -c ./$< -o $@

libkcapi: platform $(BUILD_DIR)/libkcapi$(ARCHIVE_EXTENSION)
	$(ECHO) "libkcapi$(ARCHIVE_EXTENSION) built!"
# remove the object files
	$(RM) $(KCAPI_OBJECTS)

# /libkcapi ---==================================================================

build_full: platform build_dir $(SOURCES) $(HEADERS) libkcapi
	$(CC) $(CFLAGS) $(SYS_FLAGS) $(C_INCLUDE_PATH) $(C_LIBS) -c $(SOURCES) -o $(BUILD_DIR)/$(EXE_NAME)$(OBJECT_EXTENSION)
	$(CC) -o $(BUILD_DIR)/$(EXE_NAME)$(EXE_EXTENSION) $(BUILD_DIR)/$(EXE_NAME)$(OBJECT_EXTENSION) $(BUILD_DIR)/libkcapi$(ARCHIVE_EXTENSION)
ifeq ($(TARGET),linux)
	chmod +x $(BUILD_DIR)/$(EXE_NAME)$(EXE_EXTENSION)
endif
	$(ECHO) "Build complete!"
	$(ECHO) "=========> $(BUILD_DIR)/$(EXE_NAME)$(EXE_EXTENSION)"

build: platform	build_dir $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(SYS_FLAGS) $(C_INCLUDE_PATH) $(C_LIBS) -c $(SOURCES) -o $(BUILD_DIR)/$(EXE_NAME)$(OBJECT_EXTENSION)
	$(CC) -o $(BUILD_DIR)/$(EXE_NAME)$(EXE_EXTENSION) $(BUILD_DIR)/$(EXE_NAME)$(OBJECT_EXTENSION) $(C_LIBS)
ifeq ($(TARGET),linux)
	chmod +x $(BUILD_DIR)/$(EXE_NAME)$(EXE_EXTENSION)
endif
	$(ECHO) "Build complete!"
	$(ECHO) "=========> $(BUILD_DIR)/$(EXE_NAME)$(EXE_EXTENSION)"

# clean_build: build
# 	$(ECHO) "Cleaning up..."
# 	$(RM) $(BUILD_DIR)/$(EXE_NAME)$(OBJECT_EXTENSION)
# $(RM) $(BUILD_DIR)/libkcapi$(ARCHIVE_EXTENSION)

# %.$(OBJECT_EXTENSION): %.c
# 	$(CC) $(CFLAGS) $(SYS_FLAGS) $(C_INCLUDE_PATH) -c $< -o $@

build_dir:
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)

run: build
	$(BUILD_DIR)/$(EXE_NAME)$(EXE_EXTENSION)

run_full: build_full 
	$(BUILD_DIR)/$(EXE_NAME)$(EXE_EXTENSION)

time:
ifeq ($(TARGET),windows)
	pwsh -noprofile -command "Measure-Command {make build}"
else
	time make build
endif

platform:
	$(ECHO) $(SYS_MSG)

clean:
	if [ -d "$(BUILD_DIR)" ] && [ "$(wildcard $(BUILD_DIR)/*)" ]; then $(RM) $(BUILD_DIR)/*; fi
	if [ -d "temp" ] && [ "$(wildcard temp/*)" ]; then $(RM) temp/*; fi
	if [ -d "tmp" ] && [ "$(wildcard tmp/*)" ]; then $(RM) tmp/*; fi

help:
	$(ECHO) "make build - build the project"
	$(ECHO) "make build_dev - build the project with libkcapi"
	$(ECHO) "make run - build & run the project"
	$(ECHO) "make run_dev - build & run the project with libkcapi"
	$(ECHO) "make clean - clean the build directory"
	$(ECHO) "make help - display this help message"