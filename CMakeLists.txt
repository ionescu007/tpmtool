cmake_minimum_required (VERSION 3.9)

project ("tpmtool")

if(WIN32)
    list(APPEND PLATFORM_SOURCE "tpmoswin.cpp")
else()
    list(APPEND PLATFORM_SOURCE "tpmoslin.cpp")
endif()

add_executable (tpmtool tpmcmd.cpp tpmtool.cpp ${PLATFORM_SOURCE})
set_target_properties(tpmtool PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)

if(MSVC)
    set(CMAKE_CXX_STANDARD_LIBRARIES "tbs.lib")

    set_property(TARGET tpmtool PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

    string(REGEX REPLACE "/W[1-3]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/WX /Ox /Ob2 /Oi /Os /Oy /GF /Gy /MT /Zi /wd4214 /permissive- /sdl /MP")
    set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /OPT:ICF /OPT:REF /DEBUG /EMITPOGOPHASEINFO /NOVCFEATURE /NOCOFFGRPINFO /PDBALTPATH:tpmtool.pdb")

else()
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "-Ofast -Wall -Werror")
endif()
