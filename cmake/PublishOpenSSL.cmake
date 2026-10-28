# Publishes a built OpenSSL (FROM, its install folder) as the machine's shared copy (TO). The copy
# lands beside TO and is renamed into place, so a tree never sees half of it; when another tree
# published the same key first, its copy stays and this one is dropped.
if(EXISTS ${TO})
    return()
endif()
string(RANDOM LENGTH 8 _suffix)
set(_staging ${TO}.${_suffix}.partial)
file(COPY ${FROM}/include ${FROM}/lib DESTINATION ${_staging})
file(RENAME ${_staging} ${TO} RESULT _renamed)
if(NOT _renamed STREQUAL "0")
    file(REMOVE_RECURSE ${_staging})
endif()
