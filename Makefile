# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -pthread
OUT_DIR = out
SRC_DIR = src_2

# Source and output files
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst $(SRC_DIR)/%.c, $(OUT_DIR)/%.o, $(SRC))
BIN = $(OUT_DIR)/auction

# Ensure output directory exists
$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# Compile object files
$(OUT_DIR)/%.o: $(SRC_DIR)/%.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ -lssl -lcrypto

# Link executable
$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@

# Clean build files
clean:
	rm -rf $(OUT_DIR)

# Run the program
run: $(BIN)
	./$(BIN)

.PHONY: clean run
