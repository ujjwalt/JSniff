cmd_Release/npcap_binding.node := ./gyp-mac-tool flock ./Release/linker.lock g++ -shared -Wl,-search_paths_first -mmacosx-version-min=10.5 -arch x86_64 -L./Release -install_name @loader_path/npcap_binding.node  -o Release/npcap_binding.node Release/obj.target/npcap_binding/npcap_binding.o -undefined dynamic_lookup -lpcap
