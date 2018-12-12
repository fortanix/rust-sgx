TOOLS_DIR ?= ../../target/debug

all: report.sgxs

clean:
	rm -f main.o main.text.bin report.sgxs

main.o: main.S
	gcc -c $< -o $@

main.text.bin: main.o
	objcopy -O binary $< $@

report.sgxs: main.text.bin
	$(TOOLS_DIR)/sgxs-build rx=$< tcs=nssa:1 > $@
