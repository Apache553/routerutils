
ADD_EXECUTABLE(getnetinfo getnetinfo.cpp)

install(TARGETS getnetinfo
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static
        )
