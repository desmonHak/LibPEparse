CC 			  = gcc
ARR			  = ar

VESRION_C     = 11

PATH_SRC 	      = src
PATH_INCLUDE      = include
PATH_EXAMPLES	  = example

LINKER_FLAGS  	    = 									\
	-L. 			 -lPEparse_c

INCLUDE_FLAGS = 										\
	-I. 												\
	-I$(PATH_INCLUDE)									\

GLOBAL_CFLAGS = -std=c$(VESRION_C) $(INCLUDE_FLAGS) -masm=intel \
				-D_ExceptionHandler -fdiagnostics-color=always -D_GNU_SOURCE $(DEBUG_LINUX)

CFLAGS 		  =  $(GLOBAL_CFLAGS) -O3 -Wno-unused-parameter \
				-Wno-implicit-fallthrough -Wno-type-limits  \
				-Wno-unused-variable -Wno-pointer-sign

CFLAGS_DEBUG  =  $(GLOBAL_CFLAGS) -ggdb -fno-asynchronous-unwind-tables  	    	\
				-Wall -Wextra -pipe -O0 -D DEBUG_ENABLE      	          			\
				-fstack-protector-strong -Wpedantic -fno-omit-frame-pointer       	\
				-fno-inline -fno-optimize-sibling-calls -fdiagnostics-show-option 	\
				-fPIC 
				

ARR_FLAGS     = -rc

CFLAGS_EXAMPLES 		= $(CFLAGS) $(LINKER_FLAGS)
CFLAGS_EXAMPLES_DEBUG 	= $(CFLAGS_DEBUG) $(LINKER_FLAGS)

OBJECTS 	  = LibPEparse.o LibCOFFparse.o CreatePe.o
OBJECTS_DEBUG = LibPEparse_debug.o LibCOFFparse_debug.o CreatePe_debug.o