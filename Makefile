SUBDIRS = ./src


all: $(SUBDIRS)
	HOSTCC=clang $(MAKE) -C $<

clean: $(SUBDIRS)
	$(MAKE) clean -C $<

init:
	git submodule update --init --recursive

deinit:
	git submodule deinit -f --all
	rm -rf .git/modules

.PHONY: init deinit all $(SUBDIR)
