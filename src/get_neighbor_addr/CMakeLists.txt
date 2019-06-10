
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

ADD_EXECUTABLE(get_neighbor_addr get_neighbor_addr.cpp)

FIND_LIBRARY(MNL_LIB mnl)
IF(NOT MNL_LIB)
    MESSAGE(FATAL_ERROR "libmnl not found")
ELSE()
    MESSAGE("LIBMNL found: " ${MNL_LIB})
ENDIF()

TARGET_LINK_LIBRARIES (get_neighbor_addr ${MNL_LIB})

install(TARGETS get_neighbor_addr
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static
        )
