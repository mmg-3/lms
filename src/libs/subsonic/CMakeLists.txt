
add_library(lmssubsonic SHARED
	impl/ParameterParsing.cpp
	impl/Scan.cpp
	impl/Stream.cpp
	impl/SubsonicId.cpp
	impl/SubsonicResource.cpp
	impl/SubsonicResponse.cpp
	)

target_include_directories(lmssubsonic INTERFACE
	include
	)

target_include_directories(lmssubsonic PRIVATE
	include
	)

target_link_libraries(lmssubsonic PRIVATE
	lmsauth
	lmsav
	lmscover
	lmsdatabase
	lmsrecommendation
	lmsscanner
	lmsutils
	std::filesystem
	)

target_link_libraries(lmssubsonic PUBLIC
	Wt::Wt
	)

install(TARGETS lmssubsonic DESTINATION lib)

