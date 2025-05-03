# Variables
CC = gcc
CFLAGS = -Iinclude -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
SRC_DIR = src
OUT_DIR = build
BIN = enchere
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst $(SRC_DIR)/%.c, $(OUT_DIR)/%.o, $(SRC))

# Ensure output directory exists
$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# Compile object files
$(OUT_DIR)/%.o: $(SRC_DIR)/%.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link executable
$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Clean build files
clean:
	rm -rf $(OUT_DIR) $(BIN)

# Run the program
run: $(BIN)
	DYLD_LIBRARY_PATH=/opt/homebrew/opt/openssl@3/lib ./$(BIN)

.PHONY: clean run