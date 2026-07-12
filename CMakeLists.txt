cmake_minimum_required(VERSION 3.15)
project(GameAPIHook LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- MinHook (static lib) ----
add_library(minhook STATIC
    lib/minhook/src/buffer.c
    lib/minhook/src/hook.c
    lib/minhook/src/trampoline.c
    lib/minhook/src/hde/hde64.c
)
target_include_directories(minhook PUBLIC lib/minhook/include)

# ---- GameHook.dll (face share capture) ----
add_library(GameHook SHARED
    src/dllmain.cpp
    src/hook/config.cpp
    src/hook/capture_writer.cpp
    src/hook/redact.cpp
    src/hook/winhttp_capture.cpp
    src/hook/lua_runtime_hook.cpp
    src/hook/lua_signature_probe.cpp
)
target_include_directories(GameHook PRIVATE src lib/minhook/include)
target_link_libraries(GameHook PRIVATE minhook)
target_link_libraries(GameHook PRIVATE user32 winhttp psapi bcrypt version)

# ---- Injector.exe ----
add_executable(Injector src/injector.cpp)

# ---- Offline signature probe (diagnostic only) ----
add_executable(LuaSignatureProbe
    src/lua_signature_probe_main.cpp
    src/hook/config.cpp
    src/hook/lua_signature_probe.cpp
)
target_include_directories(LuaSignatureProbe PRIVATE src)
target_link_libraries(LuaSignatureProbe PRIVATE bcrypt version psapi)
set_target_properties(LuaSignatureProbe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ---- Font tools (legacy, optional) ----
if (EXISTS "${CMAKE_SOURCE_DIR}/src/font_injector.cpp")
  add_library(FontInjector SHARED src/font_injector.cpp)
  target_include_directories(FontInjector PRIVATE src)
  target_link_libraries(FontInjector PRIVATE minhook gdi32 user32)
  add_executable(FontLauncher src/font_launcher.cpp)
  set_target_properties(FontInjector FontLauncher PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )
endif()

set_target_properties(GameHook Injector PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ---- post-build copy scripts/config ----
add_custom_command(TARGET GameHook POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:GameHook>/Scripts"
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:GameHook>/captures"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/Scripts/face_share_logger.lua"
            "$<TARGET_FILE_DIR:GameHook>/Scripts/face_share_logger.lua"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/hook_config.example.json"
            "$<TARGET_FILE_DIR:GameHook>/hook_config.example.json"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/hook_config.example.json"
            "$<TARGET_FILE_DIR:GameHook>/hook_config.json"
    COMMENT "Copy face share logger + example config next to GameHook.dll"
)
