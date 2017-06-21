# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/vladimir/Documents/MPUDP

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/vladimir/Documents/MPUDP

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "No interactive CMake dialog available..."
	/usr/bin/cmake -E echo No\ interactive\ CMake\ dialog\ available.
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/vladimir/Documents/MPUDP/CMakeFiles /home/vladimir/Documents/MPUDP/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/vladimir/Documents/MPUDP/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named reciever

# Build rule for target.
reciever: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 reciever
.PHONY : reciever

# fast build rule for target.
reciever/fast:
	$(MAKE) -f CMakeFiles/reciever.dir/build.make CMakeFiles/reciever.dir/build
.PHONY : reciever/fast

#=============================================================================
# Target rules for targets named sender

# Build rule for target.
sender: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 sender
.PHONY : sender

# fast build rule for target.
sender/fast:
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/build
.PHONY : sender/fast

# target to build an object file
src/network.o:
	$(MAKE) -f CMakeFiles/reciever.dir/build.make CMakeFiles/reciever.dir/src/network.o
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/network.o
.PHONY : src/network.o

# target to preprocess a source file
src/network.i:
	$(MAKE) -f CMakeFiles/reciever.dir/build.make CMakeFiles/reciever.dir/src/network.i
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/network.i
.PHONY : src/network.i

# target to generate assembly for a file
src/network.s:
	$(MAKE) -f CMakeFiles/reciever.dir/build.make CMakeFiles/reciever.dir/src/network.s
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/network.s
.PHONY : src/network.s

# target to build an object file
src/reciever.o:
	$(MAKE) -f CMakeFiles/reciever.dir/build.make CMakeFiles/reciever.dir/src/reciever.o
.PHONY : src/reciever.o

# target to preprocess a source file
src/reciever.i:
	$(MAKE) -f CMakeFiles/reciever.dir/build.make CMakeFiles/reciever.dir/src/reciever.i
.PHONY : src/reciever.i

# target to generate assembly for a file
src/reciever.s:
	$(MAKE) -f CMakeFiles/reciever.dir/build.make CMakeFiles/reciever.dir/src/reciever.s
.PHONY : src/reciever.s

# target to build an object file
src/segmenter.o:
	$(MAKE) -f CMakeFiles/reciever.dir/build.make CMakeFiles/reciever.dir/src/segmenter.o
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/segmenter.o
.PHONY : src/segmenter.o

# target to preprocess a source file
src/segmenter.i:
	$(MAKE) -f CMakeFiles/reciever.dir/build.make CMakeFiles/reciever.dir/src/segmenter.i
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/segmenter.i
.PHONY : src/segmenter.i

# target to generate assembly for a file
src/segmenter.s:
	$(MAKE) -f CMakeFiles/reciever.dir/build.make CMakeFiles/reciever.dir/src/segmenter.s
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/segmenter.s
.PHONY : src/segmenter.s

# target to build an object file
src/sender.o:
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/sender.o
.PHONY : src/sender.o

# target to preprocess a source file
src/sender.i:
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/sender.i
.PHONY : src/sender.i

# target to generate assembly for a file
src/sender.s:
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/sender.s
.PHONY : src/sender.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... rebuild_cache"
	@echo "... edit_cache"
	@echo "... reciever"
	@echo "... sender"
	@echo "... src/network.o"
	@echo "... src/network.i"
	@echo "... src/network.s"
	@echo "... src/reciever.o"
	@echo "... src/reciever.i"
	@echo "... src/reciever.s"
	@echo "... src/segmenter.o"
	@echo "... src/segmenter.i"
	@echo "... src/segmenter.s"
	@echo "... src/sender.o"
	@echo "... src/sender.i"
	@echo "... src/sender.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

