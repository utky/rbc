use libc::{syscall, c_int};
use std::io::{Result, Error, ErrorKind};

//    struct { /* anonymous struct used by BPF_MAP_CREATE command */
//        __u32   map_type;   /* one of enum bpf_map_type */
//        __u32   key_size;   /* size of key in bytes */
//        __u32   value_size; /* size of value in bytes */
//        __u32   max_entries;    /* max number of entries in a map */
//        __u32   map_flags;  /* BPF_MAP_CREATE related
//                     * flags defined above.
//                     */
//        __u32   inner_map_fd;   /* fd pointing to the inner map */
//        __u32   numa_node;  /* numa node (effective only if
//                     * BPF_F_NUMA_NODE is set).
//                     */
//        char    map_name[BPF_OBJ_NAME_LEN];
//    };
#[derive(Debug)]
#[repr(C)]
struct BpfAttrMapCreate {
  map_fd: c_int,
  key_size: usize,
  value_size: usize,
  max_entries: usize,
  map_flags: u32,
}

// https://elixir.bootlin.com/linux/v4.9/source/include/uapi/linux/types.h#L42
//    struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
//        __u32       map_fd;
//        __aligned_u64   key;
//        union {
//            __aligned_u64 value;
//            __aligned_u64 next_key;
//        };
//        __u64       flags;
//    };
#[derive(Debug)]
#[repr(C)]
struct BpfAttrMapElem {
  map_fd: c_int,
  key: u64,
  value: u64,
  flags: u64,
}

union MapKey {
  value: u64,
  next_key: u64,
}
