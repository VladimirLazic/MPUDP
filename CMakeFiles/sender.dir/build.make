# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


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

# Include any dependencies generated for this target.
include CMakeFiles/sender.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/sender.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/sender.dir/flags.make

CMakeFiles/sender.dir/src/segmenter.o: CMakeFiles/sender.dir/flags.make
CMakeFiles/sender.dir/src/segmenter.o: src/segmenter.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vladimir/Documents/MPUDP/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/sender.dir/src/segmenter.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/sender.dir/src/segmenter.o   -c /home/vladimir/Documents/MPUDP/src/segmenter.c

CMakeFiles/sender.dir/src/segmenter.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sender.dir/src/segmenter.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/vladimir/Documents/MPUDP/src/segmenter.c > CMakeFiles/sender.dir/src/segmenter.i

CMakeFiles/sender.dir/src/segmenter.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sender.dir/src/segmenter.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/vladimir/Documents/MPUDP/src/segmenter.c -o CMakeFiles/sender.dir/src/segmenter.s

CMakeFiles/sender.dir/src/segmenter.o.requires:

.PHONY : CMakeFiles/sender.dir/src/segmenter.o.requires

CMakeFiles/sender.dir/src/segmenter.o.provides: CMakeFiles/sender.dir/src/segmenter.o.requires
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/segmenter.o.provides.build
.PHONY : CMakeFiles/sender.dir/src/segmenter.o.provides

CMakeFiles/sender.dir/src/segmenter.o.provides.build: CMakeFiles/sender.dir/src/segmenter.o


CMakeFiles/sender.dir/src/network.o: CMakeFiles/sender.dir/flags.make
CMakeFiles/sender.dir/src/network.o: src/network.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vladimir/Documents/MPUDP/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/sender.dir/src/network.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/sender.dir/src/network.o   -c /home/vladimir/Documents/MPUDP/src/network.c

CMakeFiles/sender.dir/src/network.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sender.dir/src/network.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/vladimir/Documents/MPUDP/src/network.c > CMakeFiles/sender.dir/src/network.i

CMakeFiles/sender.dir/src/network.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sender.dir/src/network.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/vladimir/Documents/MPUDP/src/network.c -o CMakeFiles/sender.dir/src/network.s

CMakeFiles/sender.dir/src/network.o.requires:

.PHONY : CMakeFiles/sender.dir/src/network.o.requires

CMakeFiles/sender.dir/src/network.o.provides: CMakeFiles/sender.dir/src/network.o.requires
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/network.o.provides.build
.PHONY : CMakeFiles/sender.dir/src/network.o.provides

CMakeFiles/sender.dir/src/network.o.provides.build: CMakeFiles/sender.dir/src/network.o


CMakeFiles/sender.dir/src/sender.o: CMakeFiles/sender.dir/flags.make
CMakeFiles/sender.dir/src/sender.o: src/sender.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vladimir/Documents/MPUDP/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/sender.dir/src/sender.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/sender.dir/src/sender.o   -c /home/vladimir/Documents/MPUDP/src/sender.c

CMakeFiles/sender.dir/src/sender.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sender.dir/src/sender.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/vladimir/Documents/MPUDP/src/sender.c > CMakeFiles/sender.dir/src/sender.i

CMakeFiles/sender.dir/src/sender.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sender.dir/src/sender.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/vladimir/Documents/MPUDP/src/sender.c -o CMakeFiles/sender.dir/src/sender.s

CMakeFiles/sender.dir/src/sender.o.requires:

.PHONY : CMakeFiles/sender.dir/src/sender.o.requires

CMakeFiles/sender.dir/src/sender.o.provides: CMakeFiles/sender.dir/src/sender.o.requires
	$(MAKE) -f CMakeFiles/sender.dir/build.make CMakeFiles/sender.dir/src/sender.o.provides.build
.PHONY : CMakeFiles/sender.dir/src/sender.o.provides

CMakeFiles/sender.dir/src/sender.o.provides.build: CMakeFiles/sender.dir/src/sender.o


# Object files for target sender
sender_OBJECTS = \
"CMakeFiles/sender.dir/src/segmenter.o" \
"CMakeFiles/sender.dir/src/network.o" \
"CMakeFiles/sender.dir/src/sender.o"

# External object files for target sender
sender_EXTERNAL_OBJECTS =

sender: CMakeFiles/sender.dir/src/segmenter.o
sender: CMakeFiles/sender.dir/src/network.o
sender: CMakeFiles/sender.dir/src/sender.o
sender: CMakeFiles/sender.dir/build.make
sender: CMakeFiles/sender.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/vladimir/Documents/MPUDP/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable sender"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sender.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/sender.dir/build: sender

.PHONY : CMakeFiles/sender.dir/build

CMakeFiles/sender.dir/requires: CMakeFiles/sender.dir/src/segmenter.o.requires
CMakeFiles/sender.dir/requires: CMakeFiles/sender.dir/src/network.o.requires
CMakeFiles/sender.dir/requires: CMakeFiles/sender.dir/src/sender.o.requires

.PHONY : CMakeFiles/sender.dir/requires

CMakeFiles/sender.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/sender.dir/cmake_clean.cmake
.PHONY : CMakeFiles/sender.dir/clean

CMakeFiles/sender.dir/depend:
	cd /home/vladimir/Documents/MPUDP && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/vladimir/Documents/MPUDP /home/vladimir/Documents/MPUDP /home/vladimir/Documents/MPUDP /home/vladimir/Documents/MPUDP /home/vladimir/Documents/MPUDP/CMakeFiles/sender.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/sender.dir/depend
