.PHONY: all test clean

all: mysudo test-exe

mysudo: sudo.c
	gcc $< -lcrypt -o $@
	sudo cp mysudo /usr/local/bin/
	sudo chmod u+s /usr/local/bin/mysudo

test-exe: test.c
	mkdir -p ../test
	gcc $< -o $@
	cp $@ ../test

test: test-exe mysudo
	mysudo ../test/test-exe

clean:
	sudo $(RM) -r mysudo test-exe ../test /usr/local/bin/mysudo
