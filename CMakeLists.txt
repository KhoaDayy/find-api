cmake_minimum_required(VERSION 3.15)
project(GameAPIHook LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)

# ---- MinHook (static lib) ----
add_library(minhook STATIC
    lib/minhook/src/buffer.c
    lib/minhook/src/hook.c
    lib/minhook/src/trampoline.c
    lib/minhook/src/hde/hde64.c
)
target_include_directories(minhook PUBLIC lib/minhook/include)

# ---- GameHook.dll ----
add_library(GameHook SHARED src/dllmain.cpp)
target_include_directories(GameHook PRIVATE src)
target_link_libraries(GameHook PRIVATE minhook)

# ---- Injector.exe ----
add_executable(Injector src/injector.cpp)

# ---- output to build/bin ----
set_target_properties(GameHook Injector PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
