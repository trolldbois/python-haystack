from ctypes import *

STRING = c_char_p


class entry(Structure):
    pass
Entry = entry
entry._fields_ = [
    ('flink', POINTER(Entry)),
    ('blink', POINTER(Entry)),
]
class usual(Structure):
    pass
usual._fields_ = [
    ('val1', c_uint),
    ('val2', c_uint),
    ('root', Entry),
    ('txt', c_char * 128),
    ('val2b', c_uint),
    ('val1b', c_uint),
]
class Node(Structure):
    pass
Node._fields_ = [
    ('val1', c_uint),
    ('list', Entry),
    ('val2', c_uint),
]
class _G_fpos_t(Structure):
    pass
__off_t = c_long
class __mbstate_t(Structure):
    pass
class N11__mbstate_t3DOT_2E(Union):
    pass
N11__mbstate_t3DOT_2E._fields_ = [
    ('__wch', c_uint),
    ('__wchb', c_char * 4),
]
__mbstate_t._fields_ = [
    ('__count', c_int),
    ('__value', N11__mbstate_t3DOT_2E),
]
_G_fpos_t._fields_ = [
    ('__pos', __off_t),
    ('__state', __mbstate_t),
]
class _G_fpos64_t(Structure):
    pass
__quad_t = c_longlong
__off64_t = __quad_t
_G_fpos64_t._pack_ = 4
_G_fpos64_t._fields_ = [
    ('__pos', __off64_t),
    ('__state', __mbstate_t),
]
_G_int16_t = c_short
_G_int32_t = c_int
_G_uint16_t = c_ushort
_G_uint32_t = c_uint
pthread_t = c_ulong
class __pthread_internal_slist(Structure):
    pass
__pthread_internal_slist._fields_ = [
    ('__next', POINTER(__pthread_internal_slist)),
]
__pthread_slist_t = __pthread_internal_slist
class __pthread_mutex_s(Structure):
    pass
class N15pthread_mutex_t17__pthread_mutex_s4DOT_15E(Union):
    pass
N15pthread_mutex_t17__pthread_mutex_s4DOT_15E._fields_ = [
    ('__spins', c_int),
    ('__list', __pthread_slist_t),
]
__pthread_mutex_s._anonymous_ = ['_0']
__pthread_mutex_s._fields_ = [
    ('__lock', c_int),
    ('__count', c_uint),
    ('__owner', c_int),
    ('__kind', c_int),
    ('__nusers', c_uint),
    ('_0', N15pthread_mutex_t17__pthread_mutex_s4DOT_15E),
]
class N14pthread_cond_t4DOT_18E(Structure):
    pass
N14pthread_cond_t4DOT_18E._pack_ = 4
N14pthread_cond_t4DOT_18E._fields_ = [
    ('__lock', c_int),
    ('__futex', c_uint),
    ('__total_seq', c_ulonglong),
    ('__wakeup_seq', c_ulonglong),
    ('__woken_seq', c_ulonglong),
    ('__mutex', c_void_p),
    ('__nwaiters', c_uint),
    ('__broadcast_seq', c_uint),
]
pthread_key_t = c_uint
pthread_once_t = c_int
class N16pthread_rwlock_t4DOT_21E(Structure):
    pass
N16pthread_rwlock_t4DOT_21E._fields_ = [
    ('__lock', c_int),
    ('__nr_readers', c_uint),
    ('__readers_wakeup', c_uint),
    ('__writer_wakeup', c_uint),
    ('__nr_readers_queued', c_uint),
    ('__nr_writers_queued', c_uint),
    ('__flags', c_ubyte),
    ('__shared', c_ubyte),
    ('__pad1', c_ubyte),
    ('__pad2', c_ubyte),
    ('__writer', c_int),
]
pthread_spinlock_t = c_int
__sig_atomic_t = c_int
class __sigset_t(Structure):
    pass
__sigset_t._fields_ = [
    ('__val', c_ulong * 32),
]
class timeval(Structure):
    pass
__time_t = c_long
__suseconds_t = c_long
timeval._fields_ = [
    ('tv_sec', __time_t),
    ('tv_usec', __suseconds_t),
]
__u_char = c_ubyte
__u_short = c_ushort
__u_int = c_uint
__u_long = c_ulong
__int8_t = c_byte
__uint8_t = c_ubyte
__int16_t = c_short
__uint16_t = c_ushort
__int32_t = c_int
__uint32_t = c_uint
__int64_t = c_longlong
__uint64_t = c_ulonglong
__u_quad_t = c_ulonglong
__dev_t = __u_quad_t
__uid_t = c_uint
__gid_t = c_uint
__ino_t = c_ulong
__ino64_t = __u_quad_t
__mode_t = c_uint
__nlink_t = c_uint
__pid_t = c_int
class __fsid_t(Structure):
    pass
__fsid_t._fields_ = [
    ('__val', c_int * 2),
]
__clock_t = c_long
__rlim_t = c_ulong
__rlim64_t = __u_quad_t
__id_t = c_uint
__useconds_t = c_uint
__daddr_t = c_int
__swblk_t = c_long
__key_t = c_int
__clockid_t = c_int
__timer_t = c_void_p
__blksize_t = c_long
__blkcnt_t = c_long
__blkcnt64_t = __quad_t
__fsblkcnt_t = c_ulong
__fsblkcnt64_t = __u_quad_t
__fsfilcnt_t = c_ulong
__fsfilcnt64_t = __u_quad_t
__ssize_t = c_int
__loff_t = __off64_t
__qaddr_t = POINTER(__quad_t)
__caddr_t = STRING
__intptr_t = c_int
__socklen_t = c_uint
class N4wait3DOT_6E(Structure):
    pass
N4wait3DOT_6E._fields_ = [
    ('__w_termsig', c_uint, 7),
    ('__w_coredump', c_uint, 1),
    ('__w_retcode', c_uint, 8),
    ('', c_uint, 16),
]
class N4wait3DOT_7E(Structure):
    pass
N4wait3DOT_7E._fields_ = [
    ('__w_stopval', c_uint, 8),
    ('__w_stopsig', c_uint, 8),
    ('', c_uint, 16),
]
sigset_t = __sigset_t
__fd_mask = c_long
class fd_set(Structure):
    pass
fd_set._fields_ = [
    ('fds_bits', __fd_mask * 32),
]
fd_mask = __fd_mask
u_char = __u_char
u_short = __u_short
u_int = __u_int
u_long = __u_long
quad_t = __quad_t
u_quad_t = __u_quad_t
fsid_t = __fsid_t
loff_t = __loff_t
ino_t = __ino_t
ino64_t = __ino64_t
dev_t = __dev_t
gid_t = __gid_t
mode_t = __mode_t
nlink_t = __nlink_t
uid_t = __uid_t
pid_t = __pid_t
id_t = __id_t
daddr_t = __daddr_t
caddr_t = __caddr_t
key_t = __key_t
useconds_t = __useconds_t
suseconds_t = __suseconds_t
ulong = c_ulong
ushort = c_ushort
uint = c_uint
int8_t = c_int8
int16_t = c_int16
int32_t = c_int32
int64_t = c_int64
u_int8_t = c_ubyte
u_int16_t = c_ushort
u_int32_t = c_uint
u_int64_t = c_ulonglong
register_t = c_int
blksize_t = __blksize_t
blkcnt_t = __blkcnt_t
fsblkcnt_t = __fsblkcnt_t
fsfilcnt_t = __fsfilcnt_t
blkcnt64_t = __blkcnt64_t
fsblkcnt64_t = __fsblkcnt64_t
fsfilcnt64_t = __fsfilcnt64_t
class _IO_jump_t(Structure):
    pass
_IO_lock_t = None
class _IO_marker(Structure):
    pass
class _IO_FILE(Structure):
    pass
_IO_marker._fields_ = [
    ('_next', POINTER(_IO_marker)),
    ('_sbuf', POINTER(_IO_FILE)),
    ('_pos', c_int),
]
size_t = c_uint
_IO_FILE._pack_ = 4
_IO_FILE._fields_ = [
    ('_flags', c_int),
    ('_IO_read_ptr', STRING),
    ('_IO_read_end', STRING),
    ('_IO_read_base', STRING),
    ('_IO_write_base', STRING),
    ('_IO_write_ptr', STRING),
    ('_IO_write_end', STRING),
    ('_IO_buf_base', STRING),
    ('_IO_buf_end', STRING),
    ('_IO_save_base', STRING),
    ('_IO_backup_base', STRING),
    ('_IO_save_end', STRING),
    ('_markers', POINTER(_IO_marker)),
    ('_chain', POINTER(_IO_FILE)),
    ('_fileno', c_int),
    ('_flags2', c_int),
    ('_old_offset', __off_t),
    ('_cur_column', c_ushort),
    ('_vtable_offset', c_byte),
    ('_shortbuf', c_char * 1),
    ('_lock', POINTER(_IO_lock_t)),
    ('_offset', __off64_t),
    ('__pad1', c_void_p),
    ('__pad2', c_void_p),
    ('__pad3', c_void_p),
    ('__pad4', c_void_p),
    ('__pad5', size_t),
    ('_mode', c_int),
    ('_unused2', c_char * 40),
]
class _IO_FILE_plus(Structure):
    pass
__io_read_fn = CFUNCTYPE(__ssize_t, c_void_p, STRING, size_t)
__io_write_fn = CFUNCTYPE(__ssize_t, c_void_p, STRING, size_t)
__io_seek_fn = CFUNCTYPE(c_int, c_void_p, POINTER(__off64_t), c_int)
__io_close_fn = CFUNCTYPE(c_int, c_void_p)
cookie_read_function_t = __io_read_fn
cookie_write_function_t = __io_write_fn
cookie_seek_function_t = __io_seek_fn
cookie_close_function_t = __io_close_fn
class _IO_cookie_io_functions_t(Structure):
    pass
_IO_cookie_io_functions_t._fields_ = [
    ('read', POINTER(__io_read_fn)),
    ('write', POINTER(__io_write_fn)),
    ('seek', POINTER(__io_seek_fn)),
    ('close', POINTER(__io_close_fn)),
]
cookie_io_functions_t = _IO_cookie_io_functions_t
class _IO_cookie_file(Structure):
    pass
FILE = _IO_FILE
__FILE = _IO_FILE
__gnuc_va_list = STRING
va_list = __gnuc_va_list
off_t = __off_t
off64_t = __off64_t
ssize_t = __ssize_t
fpos_t = _G_fpos_t
fpos64_t = _G_fpos64_t
class obstack(Structure):
    pass
class div_t(Structure):
    pass
div_t._fields_ = [
    ('quot', c_int),
    ('rem', c_int),
]
class ldiv_t(Structure):
    pass
ldiv_t._fields_ = [
    ('quot', c_long),
    ('rem', c_long),
]
class lldiv_t(Structure):
    pass
lldiv_t._pack_ = 4
lldiv_t._fields_ = [
    ('quot', c_longlong),
    ('rem', c_longlong),
]
class random_data(Structure):
    pass
random_data._fields_ = [
    ('fptr', POINTER(int32_t)),
    ('rptr', POINTER(int32_t)),
    ('state', POINTER(int32_t)),
    ('rand_type', c_int),
    ('rand_deg', c_int),
    ('rand_sep', c_int),
    ('end_ptr', POINTER(int32_t)),
]
class drand48_data(Structure):
    pass
drand48_data._pack_ = 4
drand48_data._fields_ = [
    ('__x', c_ushort * 3),
    ('__old_x', c_ushort * 3),
    ('__c', c_ushort),
    ('__init', c_ushort),
    ('__a', c_ulonglong),
]
__compar_fn_t = CFUNCTYPE(c_int, c_void_p, c_void_p)
comparison_fn_t = __compar_fn_t
__compar_d_fn_t = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p)
clock_t = __clock_t
time_t = __time_t
clockid_t = __clockid_t
timer_t = __timer_t
class timespec(Structure):
    pass
timespec._fields_ = [
    ('tv_sec', __time_t),
    ('tv_nsec', c_long),
]
intptr_t = __intptr_t
socklen_t = __socklen_t
class __locale_struct(Structure):
    pass
class __locale_data(Structure):
    pass
__locale_struct._fields_ = [
    ('__locales', POINTER(__locale_data) * 13),
    ('__ctype_b', POINTER(c_ushort)),
    ('__ctype_tolower', POINTER(c_int)),
    ('__ctype_toupper', POINTER(c_int)),
    ('__names', STRING * 13),
]
__locale_t = POINTER(__locale_struct)
locale_t = __locale_t
__all__ = ['__uint16_t', '__pthread_mutex_s', '__int16_t',
           'socklen_t', 'pthread_once_t', 'fsfilcnt_t', '__timer_t',
           'mode_t', '__off64_t', 'size_t', 'random_data',
           '__uint32_t', 'fpos_t', 'fd_set', 'blkcnt_t', '__ino64_t',
           'fsblkcnt64_t', '_G_int16_t', '__FILE', 'int32_t',
           '__loff_t', 'intptr_t', 'off64_t',
           'N14pthread_cond_t4DOT_18E', 'daddr_t', '_G_uint32_t',
           'cookie_seek_function_t', 'u_char', 'fpos64_t', 'uid_t',
           'cookie_write_function_t', 'u_int64_t', 'u_int16_t',
           '__time_t', 'sigset_t', '_G_fpos64_t', 'blksize_t',
           'va_list', '_IO_jump_t', '__int32_t', 'fd_mask',
           '__nlink_t', '__compar_fn_t', '__fsid_t',
           'cookie_close_function_t', '__uint64_t', 'FILE',
           '__ssize_t', '__io_close_fn', 'comparison_fn_t',
           '__fd_mask', 'int16_t', 'clock_t', '__id_t',
           'cookie_io_functions_t', '__sigset_t', '__clockid_t',
           '__useconds_t', 'div_t', 'id_t', 'ldiv_t', '_G_fpos_t',
           '__gid_t', 'u_int32_t', '_G_uint16_t',
           '_IO_cookie_io_functions_t', '__gnuc_va_list',
           '__intptr_t', '__u_long', '_IO_FILE_plus', 'key_t',
           'ushort', '__blkcnt_t', 'pthread_t', 'clockid_t',
           'caddr_t', 'uint', '__rlim64_t', 'ino_t',
           'N15pthread_mutex_t17__pthread_mutex_s4DOT_15E',
           '__io_read_fn', 'fsfilcnt64_t', '__mode_t', 'useconds_t',
           '__blksize_t', 'pthread_spinlock_t', '__off_t',
           '__pthread_slist_t', 'N4wait3DOT_7E', 'fsblkcnt_t', 'Node',
           'u_quad_t', 'timespec', 'register_t', '__compar_d_fn_t',
           'obstack', 'N11__mbstate_t3DOT_2E', '__locale_struct',
           '__daddr_t', 'ino64_t', '_IO_cookie_file', '__caddr_t',
           '__mbstate_t', 'N4wait3DOT_6E', '__io_seek_fn', '__u_char',
           '__fsblkcnt64_t', '__locale_data', 'u_int',
           '__sig_atomic_t', '__blkcnt64_t', '__dev_t', 'gid_t',
           '__qaddr_t', '__suseconds_t', 'pid_t', 'timer_t', 'quad_t',
           'u_long', '__fsfilcnt64_t', '_IO_FILE',
           'cookie_read_function_t', 'pthread_key_t', 'blkcnt64_t',
           'u_int8_t', 'loff_t', 'off_t', 'int64_t', '__fsblkcnt_t',
           '__rlim_t', 'time_t', 'u_short', '__locale_t', 'nlink_t',
           '__uint8_t', 'lldiv_t', 'timeval', '_IO_marker',
           '__u_quad_t', '__u_short', '__int8_t', 'fsid_t', '__pid_t',
           'ssize_t', 'ulong', '__io_write_fn', '_G_int32_t',
           '__ino_t', 'int8_t', 'dev_t', '_IO_lock_t', 'Entry',
           '__swblk_t', 'locale_t', '__socklen_t', 'drand48_data',
           '__pthread_internal_slist', '__u_int', '__quad_t',
           '__int64_t', '__key_t', 'N16pthread_rwlock_t4DOT_21E',
           '__clock_t', 'entry', '__uid_t', '__fsfilcnt_t',
           'suseconds_t', 'usual']
