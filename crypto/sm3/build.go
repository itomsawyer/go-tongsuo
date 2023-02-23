package sm3

// #cgo linux CFLAGS: -Wno-deprecated-declarations -I/usr/local/opt/tongsuo/include
// #cgo linux LDFLAGS: -L/usr/local/opt/tongsuo/lib64  -lssl -lcrypto
// #cgo darwin CFLAGS: -I/opt/tongsuo/include -Wno-deprecated-declarations
// #cgo darwin LDFLAGS: -L/opt/tongsuo/lib -lssl -lcrypto
// #cgo windows CFLAGS: -DWIN32_LEAN_AND_MEAN
// #cgo windows pkg-config: libssl libcrypto
// #include "../../shim.h"
import "C"
