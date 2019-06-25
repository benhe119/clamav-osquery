cmake_minimum_required(VERSION 3.12)
project(clamav_ext)

function(main)
  set(source_files
    src/clamav.cpp
  )

  add_osquery_extension("${PROJECT_NAME}" ${source_files})

  #ImportLibraries("libclamav")
  #ImportLibraries("ssl")
  #ImportLibraries("crypto")
  list(APPEND libraries clamav)
  list(APPEND libraries ssl)
  list(APPEND libraries crypto)

  target_link_libraries("${PROJECT_NAME}" ${libraries})
  target_link_libraries("${PROJECT_NAME}" clamav)
  
    set(project_include_dirs
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
  )
endfunction()


main()
