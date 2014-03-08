MESSAGE(STATUS "Using bundled Findlibiconv.cmake...")
FIND_PATH(
    LIBICONV_INCLUDE_DIR
    iconv.h
    /usr/include/
    /usr/local/include/
    .
)

FIND_LIBRARY(
    LIBICONV_LIBRARY
    NAMES iconv
    PATHS /usr/lib/ /usr/local/lib/
)
