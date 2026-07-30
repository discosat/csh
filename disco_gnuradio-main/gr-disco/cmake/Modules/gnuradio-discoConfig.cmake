find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_DISCO gnuradio-disco)

FIND_PATH(
    GR_DISCO_INCLUDE_DIRS
    NAMES gnuradio/disco/api.h
    HINTS $ENV{DISCO_DIR}/include
        ${PC_DISCO_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_DISCO_LIBRARIES
    NAMES gnuradio-disco
    HINTS $ENV{DISCO_DIR}/lib
        ${PC_DISCO_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-discoTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_DISCO DEFAULT_MSG GR_DISCO_LIBRARIES GR_DISCO_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_DISCO_LIBRARIES GR_DISCO_INCLUDE_DIRS)
