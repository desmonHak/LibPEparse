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
examples_debug: generate_lib
	$(CC) $(PATH_EXAMPLES)/main.c  $(CFLAGS_EXAMPLES_DEBUG) -o main.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/code1.c $(CFLAGS_EXAMPLES_DEBUG) -o code1.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/code2.c $(CFLAGS_EXAMPLES_DEBUG) -o code2.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/coff1.c $(CFLAGS_EXAMPLES_DEBUG) -o coff1.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/coff2.c $(CFLAGS_EXAMPLES_DEBUG) -o coff2.$(EXTENSION)
	$(CC) $(PATH_EXAMPLES)/coff3.c $(CFLAGS_EXAMPLES_DEBUG) -o coff3.$(EXTENSION)

$(TARGET).a: $(OBJECTS)
	echo "generando librerias estatica... $@"
	$(ARR) $(ARR_FLAGS) $@ $^
	ranlib $@

$(TARGET)_debug.a: $(OBJECTS_DEBUG)
	$(ARR) $(ARR_FLAGS) $(TARGET).a $^
	ranlib $(TARGET).a

LibPEparse.o: $(PATH_SRC)/LibPEparse.c
	$(CC) $(CFLAGS) -c $^ -o $@

LibCOFFparse.o: $(PATH_SRC)/LibCOFFparse.c
	$(CC) $(CFLAGS) -c $^ -o $@

CreatePe.o: $(PATH_SRC)/CreatePe.c
	$(CC) $(CFLAGS) -c $^ -o $@

LibPEparse_debug.o: $(PATH_SRC)/LibPEparse.c
	$(CC) $(CFLAGS_DEBUG) -c $^ -o $@

LibCOFFparse_debug.o: $(PATH_SRC)/LibCOFFparse.c
	$(CC) $(CFLAGS_DEBUG) -c $^ -o $@

CreatePe_debug.o: $(PATH_SRC)/CreatePe.c
	$(CC) $(CFLAGS_DEBUG) -c $^ -o $@

cleanobj:
	$(RM) $(RMFLAGS) $(OBJECTS) $(OBJECTS_DEBUG)

cleanall: cleanobj
	$(RM) $(RMFLAGS) *.o $(TARGET).a \
	$(TARGET_DEBUG).a

.SILENT: clean cleanobj cleanall
.IGNORE: cleanobj cleanall
.PHONY:  cleanobj cleanall