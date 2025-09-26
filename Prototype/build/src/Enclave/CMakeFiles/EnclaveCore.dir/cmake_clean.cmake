file(REMOVE_RECURSE
  "../../../lib/libEnclaveCore.a"
  "../../../lib/libEnclaveCore.pdb"
  "storeEnclave_t.h"
  "storeEnclave_u.h"
  "../../../lib/storeEnclave.signed.so"
  "../../../lib/storeEnclave_hash.hex"
  "CMakeFiles/EnclaveCore.dir/ocallSrc/ocallUtil.cc.o"
  "CMakeFiles/EnclaveCore.dir/ocallSrc/storeOCall.cc.o"
  "CMakeFiles/EnclaveCore.dir/storeEnclave_u.c.o"
  "storeEnclave_u.c"
)

# Per-language clean rules from dependency scanning.
foreach(lang C CXX)
  include(CMakeFiles/EnclaveCore.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
