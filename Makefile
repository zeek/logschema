.PHONY:	all test

all:	test

# Uncomment the following for plugins and analyzers
#
#.PHONY: build
#
#build:
#	mkdir -p build
#	cd build; cmake ..; cmake --build .

test:
	make -C testing
