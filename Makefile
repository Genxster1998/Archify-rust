# Makefile for building the SMJobBless installer tool

SMJOBLESS_SRC = smjobbless_installer.m
SMJOBLESS_BIN = smjobbless_installer

all: $(SMJOBLESS_BIN)

$(SMJOBLESS_BIN): $(SMJOBLESS_SRC)
	clang -framework Foundation -framework ServiceManagement -framework Security -o $(SMJOBLESS_BIN) $(SMJOBLESS_SRC)

clean:
	rm -f $(SMJOBLESS_BIN) 