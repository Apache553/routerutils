
ADD_EXECUTABLE(ipupdatemon ipupdatemon.cpp)

TARGET_LINK_LIBRARIES (ipupdatemon ${MNL_LIB})

install(TARGETS ipupdatemon
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static
        )
