bin_PROGRAMS = dsa_perf_micros
dsa_perf_micros_SOURCES = main.c device.c user_device.c idxd_device.c prep.c init.c options.c cpu.c util.c log.c
dsa_perf_micros_LDADD = -laccel-config -lpthread -ldl
dsa_perf_micros_CFLAGS = -std=gnu99 -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
dsa_perf_micros_CFLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
dsa_perf_micros_CFLAGS += -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral
dsa_perf_micros_CFLAGS += -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Werror
dsa_perf_micros_CFLAGS += -Wno-missing-field-initializers -Wimplicit-fallthrough=2
dsa_perf_micros_CFLAGS += -Wno-format-truncation -Wno-address-of-packed-member -Wunused-parameter
dsa_perf_micros_CFLAGS += $(EXTRA_CFLAGS)
