cmake_minimum_required(VERSION 3.13)
project(netprobe)

# add the executable
add_executable(${PROJECT_NAME}
    main.c
    handle_packet.c
    flow.c
    globals.c
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE pcap pthread curl
)
