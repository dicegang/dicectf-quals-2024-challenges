cmake_minimum_required(VERSION 3.27)
project(rev_graphnode)

set(CMAKE_C_STANDARD 23)

add_executable(rev_graphnode src/main.c)
target_compile_options(rev_graphnode PRIVATE -masm=intel -O2)

add_custom_target(scrambled-up
        BYPRODUCTS scrambled-up
        COMMAND cp rev_graphnode scrambled-up && strip scrambled-up
        DEPENDS rev_graphnode)

add_compile_definitions(-DNDEBUG)
#target_link_options(rev_graphnode PRIVATE --sanitize=address)

add_custom_target(generate_module_texts)

file(GLOB modules "src/modules/*.c")
message(${modules})
foreach(module ${modules})
    cmake_path(GET module STEM module_name)
    add_executable(module_${module_name} ${module})
    target_compile_options(module_${module_name} PRIVATE -fno-builtin -ffreestanding -nostdlib -pie -static -fno-stack-protector -z execstack -fcf-protection=none -mssse3)
    target_link_options(module_${module_name} PRIVATE -fno-builtin -ffreestanding -nostdlib -pie -static -e ${module_name})

    add_custom_target(module_${module_name}.text
        BYPRODUCTS module_${module_name}.text
        COMMAND objcopy -O binary -j .text module_${module_name} module_${module_name}.text
        DEPENDS module_${module_name})
    add_dependencies(generate_module_texts module_${module_name}.text)
endforeach()

