foreach(bin tlsclienthello tlshelloworld tlssimple tlssimpleserver)
    add_executable(${bin} ${bin}.c)
    target_compile_definitions(${bin} PRIVATE ${TLSE_COMPILE_DEFINITIONS})
endforeach()
