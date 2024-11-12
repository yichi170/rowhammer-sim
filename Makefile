.PHONY: all test test-attack clean

all: mysudo test-exe

mysudo: sudo.c
	gcc $< -lcrypt -o $@
	sudo cp mysudo /usr/local/bin/
	sudo chmod u+s /usr/local/bin/mysudo

test-exe: test.c
	mkdir -p ../test
	gcc $< -o $@
	cp $@ ../test

attack: attacker.c
	gcc $< -o $@

test: test-exe mysudo
	mysudo ../test/test-exe

test-attack: attack
	./$<

clean:
	sudo $(RM) -r mysudo test-exe attack ../test /usr/local/bin/mysudo
