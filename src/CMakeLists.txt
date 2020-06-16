
FIND_LIBRARY(MNL_LIB mnl)
IF(NOT MNL_LIB)
    MESSAGE(FATAL_ERROR "libmnl not found")
ELSE()
    MESSAGE("LIBMNL found: " ${MNL_LIB})
ENDIF()

ADD_SUBDIRECTORY(fetchip)
ADD_SUBDIRECTORY(get_neighbor_addr)
ADD_SUBDIRECTORY(ipupdatemon)
