set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)

if("${CPACK_DDISASM_DEBIAN_PACKAGE}" STREQUAL "ddisasm")
  set(CPACK_DEBIAN_PACKAGE_NAME "ddisasm")
  set(CPACK_PACKAGE_FILE_NAME "ddisasm")
  set(CPACK_COMPONENTS_ALL ddisasm)
  if("${CPACK_DEBIAN_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgomp1, libgtirb (=${CPACK_GTIRB_VERSION}-${CPACK_DEBIAN_RELEASE}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}), libboost-filesystem1.71.0, libboost-program-options1.71.0, libcapstone-dev (=1:4.0.1-gt3)"
    )
  else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgomp1, libgtirb (=${CPACK_GTIRB_VERSION}-${CPACK_DEBIAN_RELEASE}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}), libboost (>=1.67) | libboost1.67, libcapstone-dev (=1:4.0.1-gt3)"
    )
  endif()
elseif("${CPACK_DDISASM_DEBIAN_PACKAGE}" STREQUAL "debug")
  set(CPACK_DEBIAN_PACKAGE_NAME "ddisasm-dbg")
  set(CPACK_PACKAGE_FILE_NAME "ddisasm-dbg")
  set(CPACK_COMPONENTS_ALL debug-file)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "ddisasm (=${CPACK_DDISASM_VERSION})")
endif()
