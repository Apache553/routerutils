
ADD_EXECUTABLE(fetchip fetchip.cpp)

install(TARGETS fetchip
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static
        )
