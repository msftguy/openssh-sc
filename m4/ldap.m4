# Options to build with LDAP
#
# Author: Roumen Petrov
# Revision: 7 Dec 2011
#
dnl The variables provided are :
dnl - build flags:
dnl     LDAP_LDFLAGS
dnl     LDAP_LIBS
dnl     LDAP_CPPFLAGS
dnl - conditional:
dnl     LDAP_ON   (e.g. '' or '#')
dnl     LDAP_OFF  (e.g. '#' or '' - oposite of LDAP_ON)
dnl - paths:
dnl     LDAP_BINDIR
dnl     LDAP_LIBEXECDIR
dnl     LDAP_SYSCONFDIR

AC_DEFUN([AC_WITH_LDAP],
[
dnl
dnl Get the ldap paths
dnl

ac_ldap=none
AC_ARG_ENABLE([ldap],
  [AS_HELP_STRING([--enable-ldap], [Enable LDAP queries])],
  [ac_ldap=$enableval]
)

if test "x$ac_ldap" = xyes; then
  ac_ldap_prefix=""
  AC_ARG_WITH([ldap-prefix],
    [AS_HELP_STRING([--with-ldap-prefix=PATH], [Prefix where LDAP is installed (optional)])],
    [ac_ldap_prefix=$withval]
  )

  AC_ARG_WITH([ldap-bindir],
    [AS_HELP_STRING([--with-ldap-bindir=PATH], [Prefix where LDAP user executables are installed (optional)])],
    [LDAP_BINDIR=$withval],
    [
      if test "x$ac_ldap_prefix" != "x"; then
        LDAP_BINDIR="$ac_ldap_prefix/bin"
      fi
    ]
  )
  AC_SUBST(LDAP_BINDIR)

  AC_ARG_WITH([ldap-libexecdir],
    [AS_HELP_STRING([--with-ldap-libexecdir=PATH], [Prefix where LDAP program executables are installed (optional)])],
    [LDAP_LIBEXECDIR=$withval],
    [
      if test "x$ac_ldap_prefix" = "x"; then
        LDAP_LIBEXECDIR="/usr/libexec"
      else
        LDAP_LIBEXECDIR="$ac_ldap_prefix/libexec"
      fi
    ]
  )
  AC_SUBST([LDAP_LIBEXECDIR])
dnl### Check for slapd
dnl  if test "x$cross_compiling" = "xyes" ; then
dnl    AC_MSG_NOTICE([cannot check for LDAP daemon when cross compiling])
dnl  else
dnl    AC_CHECK_FILES(
dnl      [
dnl        $LDAP_LIBEXECDIR/slapd
dnl      ]
dnl    )
dnl  fi

  AC_ARG_WITH([ldap-sysconfdir],
    [AS_HELP_STRING([--with-ldap-sysconfdir=PATH], [Prefix where LDAP single-machine data are installed (optional)])],
    [LDAP_SYSCONFDIR=$withval],
    [LDAP_SYSCONFDIR="$ac_ldap_prefix/etc/openldap"]
  )
  AC_SUBST([LDAP_SYSCONFDIR])
dnl### Check for schema files
dnl  if test "x$cross_compiling" = "xyes" ; then
dnl    AC_MSG_NOTICE([cannot check for schema files existence when cross compiling])
dnl  else
dnl    AC_CHECK_FILES(
dnl      [
dnl        $LDAP_SYSCONFDIR/schema/core.schema
dnl        $LDAP_SYSCONFDIR/schema/cosine.schema
dnl        $LDAP_SYSCONFDIR/schema/inetorgperson.schema
dnl      ]
dnl    )
dnl  fi


  AC_ARG_WITH([ldap-libdir],
    [AS_HELP_STRING([--with-ldap-libdir=PATH], [Prefix where LDAP libaries are installed (optional)])],
    [LDAP_LDFLAGS="-L$withval"],
    [
      if test "x$ac_ldap_prefix" != "x"; then
        LDAP_LDFLAGS="-L$ac_ldap_prefix/lib"
      else
        LDAP_LDFLAGS=""
      fi
    ]
  )
  AC_SUBST(LDAP_LDFLAGS)

  AC_ARG_WITH([ldap-includedir],
    [AS_HELP_STRING([--with-ldap-includedir=PATH], [Prefix where LDAP header files are installed (optional)])],
    [LDAP_CPPFLAGS="-I$withval"],
    [
      if test "x$ac_ldap_prefix" != "x"; then
        LDAP_CPPFLAGS="-I$ac_ldap_prefix/include"
      else
        LDAP_CPPFLAGS=""
      fi
    ]
  )
  AC_SUBST([LDAP_CPPFLAGS])


  ac_save_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $LDAP_CPPFLAGS"
  AC_CHECK_HEADERS(
    [lber.h ldap.h],
    [],
    [
      AC_MSG_ERROR([cannot found LDAP headers])
    ]
  )
  CPPFLAGS="$ac_save_CPPFLAGS"

  ac_ldap_libs=""
  AC_ARG_WITH([ldap-libs],
    [  --with-ldap-libs=LIBS   Specify LDAP libraries to link with.
                            (default is -lldap -llber -lssl -lcrypto)],
    [ac_ldap_libs="$withval"]
  )

### Try to link with LDAP libs
  ac_save_LDFLAGS="$LDFLAGS"
  ac_save_LIBS="$LIBS"

  LDFLAGS="$LDAP_LDFLAGS $LDFLAGS"
  ac_LDAP_LINK=""
  if test "x$ac_ldap_libs" != "x"; then
    AC_MSG_CHECKING([to link with specified LDAP libs])

    LDAP_LIBS="$ac_ldap_libs"
    LIBS="$LDAP_LIBS $ac_save_LIBS"
    AC_LINK_IFELSE(
      [AC_LANG_CALL([], [ldap_init])],
      [ac_LDAP_LINK="yes"]
    )
    if test "x$ac_LDAP_LINK" != "xyes"; then
      AC_MSG_ERROR([cannot link with specified LDAP libs])
    fi
  else
    AC_MSG_CHECKING([how to link LDAP libs])

    LDAP_LIBS="-lldap"
    for L in lber ssl crypto; do
      LDAP_LIBS="$LDAP_LIBS -l$L"
      LIBS="$LDAP_LIBS $ac_save_LIBS"
      AC_LINK_IFELSE(
        [AC_LANG_CALL([], [ldap_init])],
        [ac_LDAP_LINK="yes"]
      )
      if test "x$ac_LDAP_LINK" = "xyes"; then
        break
      fi
    done
    if test "x$ac_LDAP_LINK" != "xyes"; then
      AC_MSG_ERROR([cannot link with default LDAP libs])
    fi
  fi
  AC_MSG_RESULT([done])
  LIBS="$ac_save_LIBS"
  LDFLAGS="$ac_save_LDFLAGS"
  AC_SUBST([LDAP_LIBS])
else
  AC_MSG_NOTICE([LDAP is disabled])
fi

if test "x$ac_ldap" = "xyes"; then
	AC_DEFINE_UNQUOTED(
		[LDAP_ENABLED], [1],
		[Define if you want to enable LDAP queries])
	LDAP_ON=''
	LDAP_OFF='#'
else
	LDAP_ON='#'
	LDAP_OFF=''
fi
AC_SUBST([LDAP_ON])
AC_SUBST([LDAP_OFF])
])


# AC_LDAP_FUNCS(FUNCTION...)
# --------------------------------
AC_DEFUN([AC_LDAP_FUNCS],
[
dnl
dnl Check ldap functions
dnl
AC_REQUIRE([AC_WITH_LDAP])
if test "x$ac_ldap" = "xyes"; then
  ac_save_CPPFLAGS="$CPPFLAGS"
  ac_save_LDFLAGS="$LDFLAGS"
  ac_save_LIBS="$LIBS"
  CPPFLAGS="$CPPFLAGS $LDAP_CPPFLAGS"
  LDFLAGS="$LDFLAGS $LDAP_LDFLAGS"
  LIBS="$LDAP_LIBS $LIBS"
  AC_CHECK_FUNCS([$1],[],[])
  LIBS="$ac_save_LIBS"
  LDFLAGS="$ac_save_LDFLAGS"
  CPPFLAGS="$ac_save_CPPFLAGS"
fi
])
