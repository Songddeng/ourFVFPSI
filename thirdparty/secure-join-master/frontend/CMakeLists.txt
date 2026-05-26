
set( SRCS 
	main.cpp
	benchmark.cpp
	)

add_executable(secJoinfrontend  ${SRCS})

target_link_libraries(secJoinfrontend secureJoin_Tests tests_cryptoTools)
