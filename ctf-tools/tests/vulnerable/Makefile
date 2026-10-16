# Deliberately vulnerable test targets.
#
# These programs exist only so the tools can be tested against known-good
# ground truth.  Do not run them outside a sandbox.

CC      ?= gcc
COMMON  := -w -g
NOPROT  := -fno-stack-protector -z execstack
BINARIES := stack_basic ret2win canary_guard fmt_string bounded_read nx_rop pie_win menu_prefix seccomp_jail fork_server heap_play passcheck

all: $(BINARIES)

stack_basic: stack_basic.c
	$(CC) $(COMMON) -fno-stack-protector -no-pie -z noexecstack -o $@ $<

ret2win: ret2win.c
	$(CC) $(COMMON) -fno-stack-protector -no-pie -z noexecstack -o $@ $<

canary_guard: canary_guard.c
	$(CC) $(COMMON) -fstack-protector-all -no-pie -o $@ $<

fmt_string: fmt_string.c
	$(CC) $(COMMON) -fno-stack-protector -no-pie -o $@ $<

bounded_read: bounded_read.c
	$(CC) $(COMMON) -fno-stack-protector -no-pie -o $@ $<

nx_rop: nx_rop.c
	$(CC) $(COMMON) -fno-stack-protector -no-pie -z noexecstack -o $@ $<

pie_win: pie_win.c
	$(CC) $(COMMON) -fno-stack-protector -pie -fPIE -o $@ $<

menu_prefix: menu_prefix.c
	$(CC) $(COMMON) -fno-stack-protector -no-pie -o $@ $<

seccomp_jail: seccomp_jail.c
	$(CC) $(COMMON) -fno-stack-protector -no-pie -o $@ $<

fork_server: fork_server.c
	$(CC) $(COMMON) -fstack-protector-all -no-pie -o $@ $<

heap_play: heap_play.c
	$(CC) $(COMMON) -no-pie -o $@ $<

passcheck: passcheck.c
	$(CC) $(COMMON) -fno-stack-protector -no-pie -o $@ $<

clean:
	rm -f $(BINARIES)

.PHONY: all clean
