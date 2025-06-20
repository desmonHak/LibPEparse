include config.mk

generate_lib: $(TARGET).a
	ar -t $(TARGET).a

generate_lib_debug: $(TARGET)_debug.a
	ar -t $(TARGET).a

all: generate_lib
	$(MAKE) -C . -f $(MAKE_NAME) examples

examples: generate_lib
	$(CC) $(PATH_EXAMPLES)/main.c  $(CFLAGS_EXAMPLES) -o main.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/code1.c $(CFLAGS_EXAMPLES) -o code1.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/code2.c $(CFLAGS_EXAMPLES) -o code2.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/coff1.c $(CFLAGS_EXAMPLES) -o coff1.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/coff2.c $(CFLAGS_EXAMPLES) -o coff2.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/coff3.c $(CFLAGS_EXAMPLES) -o coff3.$(EXTENSION)

	$(CC) $(PATH_EXAMPLES)/elf1.c $(CFLAGS_EXAMPLES) -o elf1.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/elf2.c $(CFLAGS_EXAMPLES) -o elf2.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/elf3.c $(CFLAGS_EXAMPLES) -o elf3.$(EXTENSION)

examples_debug: generate_lib
	$(CC) $(PATH_EXAMPLES)/main.c  $(CFLAGS_EXAMPLES_DEBUG) -o main.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/code1.c $(CFLAGS_EXAMPLES_DEBUG) -o code1.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/code2.c $(CFLAGS_EXAMPLES_DEBUG) -o code2.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/coff1.c $(CFLAGS_EXAMPLES_DEBUG) -o coff1.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/coff2.c $(CFLAGS_EXAMPLES_DEBUG) -o coff2.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/coff3.c $(CFLAGS_EXAMPLES_DEBUG) -o coff3.$(EXTENSION)

	$(CC) $(PATH_EXAMPLES)/elf1.c $(CFLAGS_EXAMPLES_DEBUG) -o elf1.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/elf2.c $(CFLAGS_EXAMPLES_DEBUG) -o elf2.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/elf3.c $(CFLAGS_EXAMPLES_DEBUG) -o elf3.$(EXTENSION)

$(TARGET).a: $(OBJECTS)
	echo "generando librerias estatica... $@"
	$(ARR) $(ARR_FLAGS) $@ $^
	ranlib $@

$(TARGET)_debug.a: $(OBJECTS_DEBUG)
	$(ARR) $(ARR_FLAGS) $(TARGET).a $^
	ranlib $(TARGET).a

LibPEparse.o: $(PATH_SRC)/LibPEparse.c CreatePe.o CreateELF.o
	$(CC) $(CFLAGS) -c $(PATH_SRC)/LibPEparse.c -o $@

LibCOFFparse.o: $(PATH_SRC)/LibCOFFparse.c
	$(CC) $(CFLAGS) -c $^ -o $@

LibELFparse.o: $(PATH_SRC)/LibELFparse.c
	$(CC) $(CFLAGS) -c $^ -o $@

CreatePe.o: $(PATH_SRC)/CreatePe.c
	$(CC) $(CFLAGS) -c $^ -o $@


CreateELF.o: $(PATH_SRC)/CreateELF.c
	$(CC) $(CFLAGS) -c $^ -o $@

UtilsC.o: $(PATH_SRC)/UtilsC.c
	$(CC) $(CFLAGS) -c $^ -o $@

LibPEparse_debug.o: $(PATH_SRC)/LibPEparse.c CreatePe_debug.o CreateELF_debug.o
	$(CC) $(CFLAGS_DEBUG) -c $(PATH_SRC)/LibPEparse.c -o $@

LibELFparse_debug.o: $(PATH_SRC)/LibELFparse_debug.c
	$(CC) $(CFLAGS_DEBUG) -c $^ -o $@

LibCOFFparse_debug.o: $(PATH_SRC)/LibCOFFparse.c
	$(CC) $(CFLAGS_DEBUG) -c $^ -o $@

CreatePe_debug.o: $(PATH_SRC)/CreatePe.c
	$(CC) $(CFLAGS_DEBUG) -c $^ -o $@

CreateELF_debug.o: $(PATH_SRC)/CreateELF.c
	$(CC) $(CFLAGS_DEBUG) -c $^ -o $@

UtilsC_debug.o: $(PATH_SRC)/UtilsC.c
	$(CC) $(CFLAGS_DEBUG) -c $^ -o $@

cleanobj:
	$(RM) $(RMFLAGS) $(OBJECTS) $(OBJECTS_DEBUG)

cleanall: cleanobj
	$(RM) $(RMFLAGS) *.o $(TARGET).a \
	$(TARGET_DEBUG).a *.$(EXTENSION)

.SILENT: clean cleanobj cleanall
.IGNORE: cleanobj cleanall
.PHONY:  cleanobj cleanall