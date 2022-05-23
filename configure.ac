AC_INIT([dsa_perf_micros], 1.0)
AM_INIT_AUTOMAKE([foreign])
AC_SEARCH_LIBS(numa_max_node, numa,,)
AC_PROG_CC
CFLAGS+=" -mavx512f"
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
