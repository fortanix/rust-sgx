all: fake-vdso.so

clean:
	rm -f main.so fake-vdso.so

main.so: main.S
	gcc -fPIC -shared -Wl,-soname=linux-vdso.so.1 -Wl,--build-id=none -Wl,--no-ld-generated-unwind-info -Wl,-z,norelro -nostdlib $< -o $@

fake-vdso.so: main.so
	cp $< $@
	strip $@
