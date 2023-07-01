ALL_BINS=doctor1 doctor2 hcs patient1 patient2
BIN_DIR=bin
all: $(ALL_BINS)
	cp *.txt $(BIN_DIR)

# Path: doctor1.c
doctor1: doctor1.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@ 

# Path: doctor2.c
doctor2: doctor2.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

# Path: hcs.c
hcs: hcs.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

# Path: patient1.c
patient1: patient1.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

# Path: patient2.c
patient2: patient2.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

clean:
	rm -f $(ALL_BINS) $(BIN_DIR)/*

.PHONY: all clean

	
