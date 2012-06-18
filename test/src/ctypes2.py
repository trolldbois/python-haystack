from ctypes import *

STRING = c_char_p
WSTRING = c_wchar_p


class sA(Structure):
    pass
sA._fields_ = [
    ('a', c_int),
]
class sB(sA):
    pass
sB._fields_ = [
    ('b', c_uint),
]
class sC(sB):
    pass
sC._fields_ = [
    ('c', c_uint),
]
class sD(sB):
    pass
sD._fields_ = [
    ('d', c_uint),
]
class cA(Structure):
    pass
cA._fields_ = [
    ('a', c_int),
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
class allocator_void_(Structure):
    pass
size_t = c_uint
size_type = size_t
ptrdiff_t = c_int
difference_type = ptrdiff_t
pointer = c_void_p
const_pointer = c_void_p
value_type = None
size_type = size_t
size_type = size_t
difference_type = ptrdiff_t
difference_type = ptrdiff_t
pointer = STRING
pointer = WSTRING
const_pointer = STRING
const_pointer = WSTRING
reference = STRING
reference = WSTRING
const_reference = STRING
const_reference = WSTRING
value_type = c_char
value_type = c_wchar
class new_allocator_char_(Structure):
    pass
class allocator_char_(new_allocator_char_):
    pass
other = allocator_char_
other = allocator_char_
class new_allocator_wchar_t_(Structure):
    pass
class allocator_wchar_t_(new_allocator_wchar_t_):
    pass
other = allocator_wchar_t_
class rebind_wchar_t_(Structure):
    pass
class rebind_char_(Structure):
    pass
class rebind_char_(Structure):
    pass
char_type = c_wchar
char_type = c_char
int_type = c_int
wint_t = c_uint
int_type = wint_t
class fpos___mbstate_t_(Structure):
    pass
streampos = fpos___mbstate_t_
pos_type = streampos
wstreampos = fpos___mbstate_t_
pos_type = wstreampos
streamoff = c_long
off_type = streamoff
off_type = streamoff
class char_traits_char_(Structure):
    pass
traits_type = char_traits_char_
class char_traits_wchar_t_(Structure):
    pass
traits_type = char_traits_wchar_t_
class facet(Structure):
    pass
class ctype_base(Structure):
    pass
class ctype_char_(facet, ctype_base):
    pass
__ctype_type = ctype_char_
class __ctype_abstract_base_wchar_t_(facet, ctype_base):
    pass
class ctype_wchar_t_(__ctype_abstract_base_wchar_t_):
    pass
__ctype_type = ctype_wchar_t_
class num_put_charstd__ostreambuf_iterator_charstd__char_traits_char___(facet):
    pass
__num_put_type = num_put_charstd__ostreambuf_iterator_charstd__char_traits_char___
class num_put_wchar_tstd__ostreambuf_iterator_wchar_tstd__char_traits_wchar_t___(facet):
    pass
__num_put_type = num_put_wchar_tstd__ostreambuf_iterator_wchar_tstd__char_traits_wchar_t___
class num_get_wchar_tstd__istreambuf_iterator_wchar_tstd__char_traits_wchar_t___(facet):
    pass
__num_get_type = num_get_wchar_tstd__istreambuf_iterator_wchar_tstd__char_traits_wchar_t___
class num_get_charstd__istreambuf_iterator_charstd__char_traits_char___(facet):
    pass
__num_get_type = num_get_charstd__istreambuf_iterator_charstd__char_traits_char___
_CharT_alloc_type = allocator_char_
_CharT_alloc_type = allocator_wchar_t_
traits_type = char_traits_char_
traits_type = char_traits_wchar_t_
value_type = c_wchar
value_type = c_char
allocator_type = allocator_wchar_t_
allocator_type = allocator_char_
size_type = size_t
size_type = size_t
difference_type = ptrdiff_t
difference_type = ptrdiff_t
reference = STRING
reference = WSTRING
const_reference = STRING
const_reference = WSTRING
pointer = STRING
pointer = WSTRING
const_pointer = STRING
const_pointer = WSTRING
class __normal_iterator_char*std__basic_string_charstd__char_traits_char_std__allocator_char___(Structure):
    pass
iterator = __normal_iterator_char*std__basic_string_charstd__char_traits_char_std__allocator_char___
class __normal_iterator_wchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t___(Structure):
    pass
iterator = __normal_iterator_wchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t___
class __normal_iterator_constchar*std__basic_string_charstd__char_traits_char_std__allocator_char___(Structure):
    pass
const_iterator = __normal_iterator_constchar*std__basic_string_charstd__char_traits_char_std__allocator_char___
class __normal_iterator_constwchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t___(Structure):
    pass
const_iterator = __normal_iterator_constwchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t___
class reverse_iterator___gnu_cxx____normal_iterator_constchar*std__basic_string_charstd__char_traits_char_std__allocator_char____(Structure):
    pass
const_reverse_iterator = reverse_iterator___gnu_cxx____normal_iterator_constchar*std__basic_string_charstd__char_traits_char_std__allocator_char____
class reverse_iterator___gnu_cxx____normal_iterator_constwchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t____(Structure):
    pass
const_reverse_iterator = reverse_iterator___gnu_cxx____normal_iterator_constwchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t____
class reverse_iterator___gnu_cxx____normal_iterator_char*std__basic_string_charstd__char_traits_char_std__allocator_char____(Structure):
    pass
reverse_iterator = reverse_iterator___gnu_cxx____normal_iterator_char*std__basic_string_charstd__char_traits_char_std__allocator_char____
class reverse_iterator___gnu_cxx____normal_iterator_wchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t____(Structure):
    pass
reverse_iterator = reverse_iterator___gnu_cxx____normal_iterator_wchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t____
class _Rep_base(Structure):
    pass
_Atomic_word = c_int
_Rep_base._fields_ = [
    ('_M_length', size_t),
    ('_M_capacity', size_t),
    ('_M_refcount', _Atomic_word),
]
class _Rep_base(Structure):
    pass
_Rep_base._fields_ = [
    ('_M_length', size_t),
    ('_M_capacity', size_t),
    ('_M_refcount', _Atomic_word),
]
class _Rep(_Rep_base):
    pass
class _Rep(_Rep_base):
    pass
_Raw_bytes_alloc = allocator_char_
_Raw_bytes_alloc = allocator_char_
class _Alloc_hider(allocator_char_):
    pass
_Alloc_hider._fields_ = [
    ('_M_p', STRING),
]
class _Alloc_hider(allocator_wchar_t_):
    pass
_Alloc_hider._fields_ = [
    ('_M_p', WSTRING),
]
char_type = c_char
int_type = c_int
pos_type = streampos
off_type = streamoff
mbstate_t = __mbstate_t
state_type = mbstate_t
char_type = c_wchar
int_type = wint_t
off_type = streamoff
pos_type = wstreampos
state_type = mbstate_t
class __true_type(Structure):
    pass
class __false_type(Structure):
    pass
__type = __true_type
class __truth_type_true_(Structure):
    pass
class __is_void_void_(Structure):
    pass
__type = __true_type
class __is_integer_double_(Structure):
    pass
class __is_integer_longdouble_(Structure):
    pass
class __is_integer_float_(Structure):
    pass
__type = __false_type
__type = __false_type
__type = __false_type
class __is_integer_bool_(Structure):
    pass
__type = __true_type
class __is_integer_char_(Structure):
    pass
__type = __true_type
class __is_integer_signedchar_(Structure):
    pass
__type = __true_type
class __is_integer_unsignedchar_(Structure):
    pass
__type = __true_type
class __is_integer_wchar_t_(Structure):
    pass
__type = __true_type
class __is_integer_shortint_(Structure):
    pass
__type = __true_type
class __is_integer_shortunsignedint_(Structure):
    pass
__type = __true_type
class __is_integer_int_(Structure):
    pass
__type = __true_type
class __is_integer_unsignedint_(Structure):
    pass
__type = __true_type
class __is_integer_longint_(Structure):
    pass
__type = __true_type
class __is_integer_longunsignedint_(Structure):
    pass
__type = __true_type
class __is_integer_longlongint_(Structure):
    pass
__type = __true_type
class __is_integer_longlongunsignedint_(Structure):
    pass
__type = __true_type
class __is_floating_float_(Structure):
    pass
__type = __true_type
class __is_floating_double_(Structure):
    pass
__type = __true_type
class __is_floating_longdouble_(Structure):
    pass
__type = __true_type
class __is_char_char_(Structure):
    pass
__type = __true_type
class __is_char_wchar_t_(Structure):
    pass
__type = __true_type
class __is_byte_char_(Structure):
    pass
__type = __true_type
class __is_byte_signedchar_(Structure):
    pass
__type = __true_type
class __is_byte_unsignedchar_(Structure):
    pass
__type = __true_type
class __forced_unwind(Structure):
    pass
class ios_base(Structure):
    pass
streamsize = ptrdiff_t

# values for enumeration '_Ios_Fmtflags'
_S_boolalpha = 1
_S_dec = 2
_S_fixed = 4
_S_hex = 8
_S_internal = 16
_S_left = 32
_S_oct = 64
_S_right = 128
_S_scientific = 256
_S_showbase = 512
_S_showpoint = 1024
_S_showpos = 2048
_S_skipws = 4096
_S_unitbuf = 8192
_S_uppercase = 16384
_S_adjustfield = 176
_S_basefield = 74
_S_floatfield = 260
_S_ios_fmtflags_end = 65536
_Ios_Fmtflags = c_int # enum

# values for enumeration '_Ios_Iostate'
_S_goodbit = 0
_S_badbit = 1
_S_eofbit = 2
_S_failbit = 4
_S_ios_iostate_end = 65536
_Ios_Iostate = c_int # enum
class _Callback_list(Structure):
    pass
class _Words(Structure):
    pass
_Words._fields_ = [
    ('_M_pword', c_void_p),
    ('_M_iword', c_long),
]
class locale(Structure):
    pass
class _Impl(Structure):
    pass
class basic_string_charstd__char_traits_char_std__allocator_char__(Structure):
    pass
string = basic_string_charstd__char_traits_char_std__allocator_char__
locale._fields_ = [
    ('_M_impl', POINTER(_Impl)),
]

# values for enumeration 'event'
erase_event = 0
imbue_event = 1
copyfmt_event = 2
event = c_int # enum
ios_base._fields_ = [
    ('_M_precision', streamsize),
    ('_M_width', streamsize),
    ('_M_flags', _Ios_Fmtflags),
    ('_M_exception', _Ios_Iostate),
    ('_M_streambuf_state', _Ios_Iostate),
    ('_M_callbacks', POINTER(_Callback_list)),
    ('_M_word_zero', _Words),
    ('_M_local_word', _Words * 8),
    ('_M_word_size', c_int),
    ('_M_word', POINTER(_Words)),
    ('_M_ios_locale', locale),
]
class exception(Structure):
    pass
class failure(exception):
    pass
basic_string_charstd__char_traits_char_std__allocator_char__._fields_ = [
    ('_M_dataplus', _Alloc_hider),
]
failure._fields_ = [
    ('_M_msg', string),
]
fmtflags = _Ios_Fmtflags
iostate = _Ios_Iostate

# values for enumeration '_Ios_Openmode'
_S_app = 1
_S_ate = 2
_S_bin = 4
_S_in = 8
_S_out = 16
_S_trunc = 32
_S_ios_openmode_end = 65536
_Ios_Openmode = c_int # enum
openmode = _Ios_Openmode

# values for enumeration '_Ios_Seekdir'
_S_beg = 0
_S_cur = 1
_S_end = 2
_S_ios_seekdir_end = 65536
_Ios_Seekdir = c_int # enum
seekdir = _Ios_Seekdir
io_state = c_int
open_mode = c_int
seek_dir = c_int
event_callback = CFUNCTYPE(None, event, POINTER(ios_base), c_int)
_Callback_list._fields_ = [
    ('_M_next', POINTER(_Callback_list)),
    ('_M_fn', CFUNCTYPE(None, event, POINTER(ios_base), c_int)),
    ('_M_index', c_int),
    ('_M_refcount', _Atomic_word),
]
class Init(Structure):
    pass
category = c_int
none = 0 # Variable c_int '0'
ctype = 1 # Variable c_int '1'
numeric = 2 # Variable c_int '2'
collate = 4 # Variable c_int '4'
time = 8 # Variable c_int '8'
monetary = 16 # Variable c_int '16'
messages = 32 # Variable c_int '32'
all = 63 # Variable c_int '63'
class __locale_struct(Structure):
    pass
__locale_t = POINTER(__locale_struct)
__c_locale = __locale_t
facet._fields_ = [
    ('_M_refcount', _Atomic_word),
]
class id(Structure):
    pass
id._fields_ = [
    ('_M_index', size_t),
]
_Impl._fields_ = [
    ('_M_refcount', _Atomic_word),
    ('_M_facets', POINTER(POINTER(facet))),
    ('_M_facets_size', size_t),
    ('_M_caches', POINTER(POINTER(facet))),
    ('_M_names', POINTER(STRING)),
]
class collate_char_(facet):
    pass
collate_char_._fields_ = [
    ('_M_c_locale_collate', __c_locale),
]
class collate_wchar_t_(facet):
    pass
class basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__(Structure):
    pass
basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__._fields_ = [
    ('_M_dataplus', _Alloc_hider),
]
collate_wchar_t_._fields_ = [
    ('_M_c_locale_collate', __c_locale),
]
char_type = c_char
char_type = c_wchar
string_type = basic_string_charstd__char_traits_char_std__allocator_char__
string_type = basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
class collate_byname_wchar_t_(collate_wchar_t_):
    pass
class collate_byname_char_(collate_char_):
    pass
char_type = c_wchar
char_type = c_char
string_type = basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
string_type = basic_string_charstd__char_traits_char_std__allocator_char__
char_type = c_wchar
ctype_char_._fields_ = [
    ('_M_c_locale_ctype', __c_locale),
    ('_M_del', c_bool),
    ('_M_toupper', POINTER(c_int)),
    ('_M_tolower', POINTER(c_int)),
    ('_M_table', POINTER(c_ushort)),
    ('_M_widen_ok', c_char),
    ('_M_widen', c_char * 256),
    ('_M_narrow', c_char * 256),
    ('_M_narrow_ok', c_char),
]
class __vmi_class_type_info_pseudo2(Structure):
    pass
class __type_info_pseudo(Structure):
    pass
class __base_class_type_info_pseudo(Structure):
    pass
__vmi_class_type_info_pseudo2._anonymous_ = ['_0']
__vmi_class_type_info_pseudo2._fields_ = [
    ('_0', __type_info_pseudo),
    ('', c_int),
    ('', c_int),
    ('', __base_class_type_info_pseudo * 2),
]
char_type = c_char
wctype_t = c_ulong
ctype_wchar_t_._fields_ = [
    ('_M_c_locale_ctype', __c_locale),
    ('_M_narrow_ok', c_bool),
    ('_M_narrow', c_char * 128),
    ('_M_widen', wint_t * 256),
    ('_M_bit', c_ushort * 16),
    ('_M_wmask', wctype_t * 16),
]
char_type = c_wchar
__wmask_type = wctype_t
class ctype_byname_char_(ctype_char_):
    pass
class ctype_byname_wchar_t_(ctype_wchar_t_):
    pass
class __num_base(Structure):
    pass
class __numpunct_cache_char_(Structure):
    pass
class __numpunct_cache_wchar_t_(Structure):
    pass
class numpunct_wchar_t_(facet):
    pass
numpunct_wchar_t_._fields_ = [
    ('_M_data', POINTER(__numpunct_cache_wchar_t_)),
]
class numpunct_char_(facet):
    pass
numpunct_char_._fields_ = [
    ('_M_data', POINTER(__numpunct_cache_char_)),
]
char_type = c_char
char_type = c_wchar
string_type = basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
string_type = basic_string_charstd__char_traits_char_std__allocator_char__
__cache_type = __numpunct_cache_wchar_t_
__cache_type = __numpunct_cache_char_
class numpunct_byname_wchar_t_(numpunct_wchar_t_):
    pass
class numpunct_byname_char_(numpunct_char_):
    pass
char_type = c_wchar
char_type = c_char
string_type = basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
string_type = basic_string_charstd__char_traits_char_std__allocator_char__
class istreambuf_iterator_wchar_tstd__char_traits_wchar_t__(Structure):
    pass
class istreambuf_iterator_charstd__char_traits_char__(Structure):
    pass
char_type = c_char
char_type = c_wchar
iter_type = istreambuf_iterator_charstd__char_traits_char__
iter_type = istreambuf_iterator_wchar_tstd__char_traits_wchar_t__
class ostreambuf_iterator_wchar_tstd__char_traits_wchar_t__(Structure):
    pass
class ostreambuf_iterator_charstd__char_traits_char__(Structure):
    pass
char_type = c_wchar
char_type = c_char
iter_type = ostreambuf_iterator_charstd__char_traits_char__
iter_type = ostreambuf_iterator_wchar_tstd__char_traits_wchar_t__
class codecvt_base(Structure):
    pass
class codecvt_wchar_tchar__mbstate_t_(Structure):
    pass
class codecvt_charchar__mbstate_t_(Structure):
    pass
class time_base(Structure):
    pass
class money_base(Structure):
    pass
class messages_base(Structure):
    pass
class input_iterator_tag(Structure):
    pass
class output_iterator_tag(Structure):
    pass
class forward_iterator_tag(input_iterator_tag):
    pass
class bidirectional_iterator_tag(forward_iterator_tag):
    pass
class random_access_iterator_tag(bidirectional_iterator_tag):
    pass
class iterator_std__output_iterator_tagvoidvoidvoidvoid_(Structure):
    pass
iterator_category = output_iterator_tag
value_type = None
difference_type = None
pointer = None
reference = None
wstring = basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
class bad_exception(exception):
    pass
terminate_handler = CFUNCTYPE(None)
unexpected_handler = CFUNCTYPE(None)
size_type = size_t
size_type = size_t
difference_type = ptrdiff_t
difference_type = ptrdiff_t
pointer = WSTRING
pointer = STRING
const_pointer = WSTRING
const_pointer = STRING
reference = WSTRING
reference = STRING
const_reference = WSTRING
const_reference = STRING
value_type = c_wchar
value_type = c_char
class __numeric_traits_integer_longunsignedint_(Structure):
    pass
class __numeric_traits_integer_shortint_(Structure):
    pass
class __numeric_traits_integer_char_(Structure):
    pass
class __numeric_traits_integer_int_(Structure):
    pass
__min = -32768 # Variable c_short '-0x000008000'
__min = -2147483648 # Variable c_int '-0x080000000'
__max = 32767 # Variable c_short '32767'
__max = 2147483647 # Variable c_int '2147483647'
__max = '\x7f' # Variable c_char "'\\177'"
__digits = 32 # Variable c_int '32'
class __numeric_traits_floating_char_(Structure):
    pass
class __numeric_traits_floating_shortint_(Structure):
    pass
class __numeric_traits_floating_longunsignedint_(Structure):
    pass
class __numeric_traits_floating_int_(Structure):
    pass
class __numeric_traits_int_(__numeric_traits_integer_int_):
    pass
class __numeric_traits_char_(__numeric_traits_integer_char_):
    pass
class __numeric_traits_longunsignedint_(__numeric_traits_integer_longunsignedint_):
    pass
class __numeric_traits_shortint_(__numeric_traits_integer_shortint_):
    pass
class __conditional_type_truelongunsignedintlonglongunsignedint_(Structure):
    pass
__type = __numeric_traits_integer_longunsignedint_
__type = c_ulong
class __conditional_type_true__gnu_cxx____numeric_traits_integer_shortint___gnu_cxx____numeric_traits_floating_shortint__(Structure):
    pass
class __conditional_type_true__gnu_cxx____numeric_traits_integer_char___gnu_cxx____numeric_traits_floating_char__(Structure):
    pass
__type = __numeric_traits_integer_char_
class __conditional_type_true__gnu_cxx____numeric_traits_integer_longunsignedint___gnu_cxx____numeric_traits_floating_longunsignedint__(Structure):
    pass
__type = __numeric_traits_integer_int_
__type = __numeric_traits_integer_shortint_
class __conditional_type_true__gnu_cxx____numeric_traits_integer_int___gnu_cxx____numeric_traits_floating_int__(Structure):
    pass
class __add_unsigned_bool_(Structure):
    pass
class __add_unsigned_wchar_t_(Structure):
    pass
class __add_unsigned_char_(Structure):
    pass
__type = c_ubyte
__type = c_ubyte
class __add_unsigned_signedchar_(Structure):
    pass
__type = c_ushort
class __add_unsigned_shortint_(Structure):
    pass
__type = c_uint
class __add_unsigned_int_(Structure):
    pass
__type = c_ulong
class __add_unsigned_longint_(Structure):
    pass
__type = c_ulonglong
class __add_unsigned_longlongint_(Structure):
    pass
class __remove_unsigned_wchar_t_(Structure):
    pass
class __remove_unsigned_bool_(Structure):
    pass
class __remove_unsigned_char_(Structure):
    pass
__type = c_byte
class __remove_unsigned_unsignedchar_(Structure):
    pass
__type = c_byte
class __remove_unsigned_shortunsignedint_(Structure):
    pass
__type = c_short
class __remove_unsigned_unsignedint_(Structure):
    pass
__type = c_int
class __remove_unsigned_longunsignedint_(Structure):
    pass
__type = c_long
class __remove_unsigned_longlongunsignedint_(Structure):
    pass
__type = c_longlong
__type = c_longdouble
class __promote_longdoublefalse_(Structure):
    pass
class __promote_doublefalse_(Structure):
    pass
__type = c_double
class __promote_floatfalse_(Structure):
    pass
__type = c_float
__to_type = POINTER(c_int)
mask = c_ushort
upper = 256 # Variable c_ushort '256u'
lower = 512 # Variable c_ushort '512u'
alpha = 1024 # Variable c_ushort '1024u'
digit = 2048 # Variable c_ushort '2048u'
xdigit = 4096 # Variable c_ushort '4096u'
space = 8192 # Variable c_ushort '8192u'
print = 16384 # Variable c_ushort '16384u'
graph = 3076 # Variable c_ushort '3076u'
cntrl = 2 # Variable c_ushort '2u'
punct = 4 # Variable c_ushort '4u'
alnum = 3072 # Variable c_ushort '3072u'
pthread_t = c_ulong
__gthread_t = pthread_t
pthread_key_t = c_uint
__gthread_key_t = pthread_key_t
pthread_once_t = c_int
__gthread_once_t = pthread_once_t
class pthread_mutex_t(Union):
    pass
__gthread_mutex_t = pthread_mutex_t
__gthread_recursive_mutex_t = pthread_mutex_t
class pthread_cond_t(Union):
    pass
__gthread_cond_t = pthread_cond_t
class timespec(Structure):
    pass
__gthread_time_t = timespec
class basic_ios_charstd__char_traits_char__(ios_base):
    pass
class basic_ostream_charstd__char_traits_char__(basic_ios_charstd__char_traits_char__):
    pass
class basic_streambuf_charstd__char_traits_char__(Structure):
    pass
basic_ios_charstd__char_traits_char__._fields_ = [
    ('_M_tie', POINTER(basic_ostream_charstd__char_traits_char__)),
    ('_M_fill', c_char),
    ('_M_fill_init', c_bool),
    ('_M_streambuf', POINTER(basic_streambuf_charstd__char_traits_char__)),
    ('_M_ctype', POINTER(ctype_char_)),
    ('_M_num_put', POINTER(num_put_charstd__ostreambuf_iterator_charstd__char_traits_char___)),
    ('_M_num_get', POINTER(num_get_charstd__istreambuf_iterator_charstd__char_traits_char___)),
]
class basic_ios_wchar_tstd__char_traits_wchar_t__(ios_base):
    pass
class basic_ostream_wchar_tstd__char_traits_wchar_t__(basic_ios_wchar_tstd__char_traits_wchar_t__):
    pass
class basic_streambuf_wchar_tstd__char_traits_wchar_t__(Structure):
    pass
basic_ios_wchar_tstd__char_traits_wchar_t__._fields_ = [
    ('_M_tie', POINTER(basic_ostream_wchar_tstd__char_traits_wchar_t__)),
    ('_M_fill', c_wchar),
    ('_M_fill_init', c_bool),
    ('_M_streambuf', POINTER(basic_streambuf_wchar_tstd__char_traits_wchar_t__)),
    ('_M_ctype', POINTER(ctype_wchar_t_)),
    ('_M_num_put', POINTER(num_put_wchar_tstd__ostreambuf_iterator_wchar_tstd__char_traits_wchar_t___)),
    ('_M_num_get', POINTER(num_get_wchar_tstd__istreambuf_iterator_wchar_tstd__char_traits_wchar_t___)),
]
basic_streambuf_charstd__char_traits_char__._fields_ = [
    ('_M_in_beg', STRING),
    ('_M_in_cur', STRING),
    ('_M_in_end', STRING),
    ('_M_out_beg', STRING),
    ('_M_out_cur', STRING),
    ('_M_out_end', STRING),
    ('_M_buf_locale', locale),
]
basic_streambuf_wchar_tstd__char_traits_wchar_t__._fields_ = [
    ('_M_in_beg', WSTRING),
    ('_M_in_cur', WSTRING),
    ('_M_in_end', WSTRING),
    ('_M_out_beg', WSTRING),
    ('_M_out_cur', WSTRING),
    ('_M_out_end', WSTRING),
    ('_M_buf_locale', locale),
]
class basic_istream_wchar_tstd__char_traits_wchar_t__(basic_ios_wchar_tstd__char_traits_wchar_t__):
    pass
basic_istream_wchar_tstd__char_traits_wchar_t__._fields_ = [
    ('_M_gcount', streamsize),
]
class basic_istream_charstd__char_traits_char__(basic_ios_charstd__char_traits_char__):
    pass
basic_istream_charstd__char_traits_char__._fields_ = [
    ('_M_gcount', streamsize),
]
class __vmi_class_type_info_pseudo1(Structure):
    pass
__vmi_class_type_info_pseudo1._anonymous_ = ['_0']
__vmi_class_type_info_pseudo1._fields_ = [
    ('_0', __type_info_pseudo),
    ('', c_int),
    ('', c_int),
    ('', __base_class_type_info_pseudo * 1),
]
class basic_iostream_wchar_tstd__char_traits_wchar_t__(basic_istream_wchar_tstd__char_traits_wchar_t__, basic_ostream_wchar_tstd__char_traits_wchar_t__):
    pass
class basic_iostream_charstd__char_traits_char__(basic_istream_charstd__char_traits_char__, basic_ostream_charstd__char_traits_char__):
    pass
class basic_stringbuf_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__(Structure):
    pass
class basic_stringbuf_charstd__char_traits_char_std__allocator_char__(Structure):
    pass
class basic_istringstream_charstd__char_traits_char_std__allocator_char__(Structure):
    pass
class basic_istringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__(Structure):
    pass
class basic_ostringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__(Structure):
    pass
class basic_ostringstream_charstd__char_traits_char_std__allocator_char__(Structure):
    pass
class basic_stringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__(Structure):
    pass
class basic_stringstream_charstd__char_traits_char_std__allocator_char__(Structure):
    pass
class basic_filebuf_wchar_tstd__char_traits_wchar_t__(Structure):
    pass
class basic_filebuf_charstd__char_traits_char__(Structure):
    pass
class basic_ifstream_charstd__char_traits_char__(Structure):
    pass
class basic_ifstream_wchar_tstd__char_traits_wchar_t__(Structure):
    pass
class basic_ofstream_charstd__char_traits_char__(Structure):
    pass
class basic_ofstream_wchar_tstd__char_traits_wchar_t__(Structure):
    pass
class basic_fstream_charstd__char_traits_char__(Structure):
    pass
class basic_fstream_wchar_tstd__char_traits_wchar_t__(Structure):
    pass
ios = basic_ios_charstd__char_traits_char__
streambuf = basic_streambuf_charstd__char_traits_char__
istream = basic_istream_charstd__char_traits_char__
ostream = basic_ostream_charstd__char_traits_char__
iostream = basic_iostream_charstd__char_traits_char__
stringbuf = basic_stringbuf_charstd__char_traits_char_std__allocator_char__
istringstream = basic_istringstream_charstd__char_traits_char_std__allocator_char__
ostringstream = basic_ostringstream_charstd__char_traits_char_std__allocator_char__
stringstream = basic_stringstream_charstd__char_traits_char_std__allocator_char__
filebuf = basic_filebuf_charstd__char_traits_char__
ifstream = basic_ifstream_charstd__char_traits_char__
ofstream = basic_ofstream_charstd__char_traits_char__
fstream = basic_fstream_charstd__char_traits_char__
wios = basic_ios_wchar_tstd__char_traits_wchar_t__
wstreambuf = basic_streambuf_wchar_tstd__char_traits_wchar_t__
wistream = basic_istream_wchar_tstd__char_traits_wchar_t__
wostream = basic_ostream_wchar_tstd__char_traits_wchar_t__
wiostream = basic_iostream_wchar_tstd__char_traits_wchar_t__
wstringbuf = basic_stringbuf_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
wistringstream = basic_istringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
wostringstream = basic_ostringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
wstringstream = basic_stringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
wfilebuf = basic_filebuf_wchar_tstd__char_traits_wchar_t__
wifstream = basic_ifstream_wchar_tstd__char_traits_wchar_t__
wofstream = basic_ofstream_wchar_tstd__char_traits_wchar_t__
wfstream = basic_fstream_wchar_tstd__char_traits_wchar_t__
char_type = c_wchar
char_type = c_char
int_type = c_int
int_type = wint_t
pos_type = streampos
pos_type = wstreampos
off_type = streamoff
off_type = streamoff
traits_type = char_traits_wchar_t_
traits_type = char_traits_char_
__streambuf_type = basic_streambuf_wchar_tstd__char_traits_wchar_t__
__streambuf_type = basic_streambuf_charstd__char_traits_char__
__ios_type = basic_ios_wchar_tstd__char_traits_wchar_t__
__ios_type = basic_ios_charstd__char_traits_char__
__num_get_type = num_get_wchar_tstd__istreambuf_iterator_wchar_tstd__char_traits_wchar_t___
__num_get_type = num_get_charstd__istreambuf_iterator_charstd__char_traits_char___
__ctype_type = ctype_char_
__ctype_type = ctype_wchar_t_
class sentry(Structure):
    pass
sentry._fields_ = [
    ('_M_ok', c_bool),
]
class sentry(Structure):
    pass
sentry._fields_ = [
    ('_M_ok', c_bool),
]
traits_type = char_traits_wchar_t_
traits_type = char_traits_char_
__streambuf_type = basic_streambuf_wchar_tstd__char_traits_wchar_t__
__streambuf_type = basic_streambuf_charstd__char_traits_char__
__istream_type = basic_istream_wchar_tstd__char_traits_wchar_t__
__istream_type = basic_istream_charstd__char_traits_char__
__ctype_type = ctype_wchar_t_
__ctype_type = ctype_char_
__int_type = wint_t
__int_type = c_int
char_type = c_char
char_type = c_wchar
int_type = c_int
int_type = wint_t
pos_type = streampos
pos_type = wstreampos
off_type = streamoff
off_type = streamoff
traits_type = char_traits_char_
traits_type = char_traits_wchar_t_
__istream_type = basic_istream_charstd__char_traits_char__
__istream_type = basic_istream_wchar_tstd__char_traits_wchar_t__
__ostream_type = basic_ostream_charstd__char_traits_char__
__ostream_type = basic_ostream_wchar_tstd__char_traits_wchar_t__
class bad_alloc(exception):
    pass
class nothrow_t(Structure):
    pass
new_handler = CFUNCTYPE(None)
char_type = c_char
char_type = c_wchar
int_type = c_int
int_type = wint_t
pos_type = streampos
pos_type = wstreampos
off_type = streamoff
off_type = streamoff
traits_type = char_traits_char_
traits_type = char_traits_wchar_t_
__streambuf_type = basic_streambuf_charstd__char_traits_char__
__streambuf_type = basic_streambuf_wchar_tstd__char_traits_wchar_t__
__ios_type = basic_ios_charstd__char_traits_char__
__ios_type = basic_ios_wchar_tstd__char_traits_wchar_t__
__num_put_type = num_put_charstd__ostreambuf_iterator_charstd__char_traits_char___
__num_put_type = num_put_wchar_tstd__ostreambuf_iterator_wchar_tstd__char_traits_wchar_t___
__ctype_type = ctype_wchar_t_
__ctype_type = ctype_char_
class sentry(Structure):
    pass
sentry._fields_ = [
    ('_M_ok', c_bool),
    ('_M_os', POINTER(basic_ostream_charstd__char_traits_char__)),
]
class sentry(Structure):
    pass
sentry._fields_ = [
    ('_M_ok', c_bool),
    ('_M_os', POINTER(basic_ostream_wchar_tstd__char_traits_wchar_t__)),
]
char_type = c_wchar
char_type = c_char
traits_type = char_traits_wchar_t_
traits_type = char_traits_char_
int_type = wint_t
int_type = c_int
pos_type = wstreampos
pos_type = streampos
off_type = streamoff
off_type = streamoff
Lmid_t = c_long
class Dl_info(Structure):
    pass
Dl_info._fields_ = [
    ('dli_fname', STRING),
    ('dli_fbase', c_void_p),
    ('dli_sname', STRING),
    ('dli_saddr', c_void_p),
]
class Dl_serpath(Structure):
    pass
Dl_serpath._fields_ = [
    ('dls_name', STRING),
    ('dls_flags', c_uint),
]
class Dl_serinfo(Structure):
    pass
size_t = c_uint
Dl_serinfo._fields_ = [
    ('dls_size', size_t),
    ('dls_cnt', c_uint),
    ('dls_serpath', Dl_serpath * 1),
]
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
class sched_param(Structure):
    pass
sched_param._fields_ = [
    ('__sched_priority', c_int),
]
class __sched_param(Structure):
    pass
__sched_param._fields_ = [
    ('__sched_priority', c_int),
]
__cpu_mask = c_ulong
class cpu_set_t(Structure):
    pass
cpu_set_t._fields_ = [
    ('__bits', __cpu_mask * 32),
]
__jmp_buf = c_int * 6
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
class timex(Structure):
    pass
timex._fields_ = [
    ('modes', c_uint),
    ('offset', c_long),
    ('freq', c_long),
    ('maxerror', c_long),
    ('esterror', c_long),
    ('status', c_int),
    ('constant', c_long),
    ('precision', c_long),
    ('tolerance', c_long),
    ('time', timeval),
    ('tick', c_long),
    ('ppsfreq', c_long),
    ('jitter', c_long),
    ('shift', c_int),
    ('stabil', c_long),
    ('jitcnt', c_long),
    ('calcnt', c_long),
    ('errcnt', c_long),
    ('stbcnt', c_long),
    ('tai', c_int),
    ('', c_int, 32),
    ('', c_int, 32),
    ('', c_int, 32),
    ('', c_int, 32),
    ('', c_int, 32),
    ('', c_int, 32),
    ('', c_int, 32),
    ('', c_int, 32),
    ('', c_int, 32),
    ('', c_int, 32),
    ('', c_int, 32),
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
class lconv(Structure):
    pass
lconv._fields_ = [
    ('decimal_point', STRING),
    ('thousands_sep', STRING),
    ('grouping', STRING),
    ('int_curr_symbol', STRING),
    ('currency_symbol', STRING),
    ('mon_decimal_point', STRING),
    ('mon_thousands_sep', STRING),
    ('mon_grouping', STRING),
    ('positive_sign', STRING),
    ('negative_sign', STRING),
    ('int_frac_digits', c_char),
    ('frac_digits', c_char),
    ('p_cs_precedes', c_char),
    ('p_sep_by_space', c_char),
    ('n_cs_precedes', c_char),
    ('n_sep_by_space', c_char),
    ('p_sign_posn', c_char),
    ('n_sign_posn', c_char),
    ('int_p_cs_precedes', c_char),
    ('int_p_sep_by_space', c_char),
    ('int_n_cs_precedes', c_char),
    ('int_n_sep_by_space', c_char),
    ('int_p_sign_posn', c_char),
    ('int_n_sign_posn', c_char),
]
class _pthread_cleanup_buffer(Structure):
    pass
_pthread_cleanup_buffer._fields_ = [
    ('__routine', CFUNCTYPE(None, c_void_p)),
    ('__arg', c_void_p),
    ('__canceltype', c_int),
    ('__prev', POINTER(_pthread_cleanup_buffer)),
]
class _4DOT_73(Structure):
    pass
class N4DOT_734DOT_74E(Structure):
    pass
N4DOT_734DOT_74E._fields_ = [
    ('__cancel_jmp_buf', __jmp_buf),
    ('__mask_was_saved', c_int),
]
_4DOT_73._fields_ = [
    ('__cancel_jmp_buf', N4DOT_734DOT_74E * 1),
    ('__pad', c_void_p * 4),
]
__pthread_unwind_buf_t = _4DOT_73
class __pthread_cleanup_frame(Structure):
    pass
__pthread_cleanup_frame._fields_ = [
    ('__cancel_routine', CFUNCTYPE(None, c_void_p)),
    ('__cancel_arg', c_void_p),
    ('__do_it', c_int),
    ('__cancel_type', c_int),
]
class __pthread_cleanup_class(Structure):
    pass
__pthread_cleanup_class._fields_ = [
    ('__cancel_routine', CFUNCTYPE(None, c_void_p)),
    ('__cancel_arg', c_void_p),
    ('__do_it', c_int),
    ('__cancel_type', c_int),
]
class __jmp_buf_tag(Structure):
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
timespec._fields_ = [
    ('tv_sec', __time_t),
    ('tv_nsec', c_long),
]
class tm(Structure):
    pass
tm._fields_ = [
    ('tm_sec', c_int),
    ('tm_min', c_int),
    ('tm_hour', c_int),
    ('tm_mday', c_int),
    ('tm_mon', c_int),
    ('tm_year', c_int),
    ('tm_wday', c_int),
    ('tm_yday', c_int),
    ('tm_isdst', c_int),
    ('tm_gmtoff', c_long),
    ('tm_zone', STRING),
]
class itimerspec(Structure):
    pass
itimerspec._fields_ = [
    ('it_interval', timespec),
    ('it_value', timespec),
]
class sigevent(Structure):
    pass
intptr_t = __intptr_t
socklen_t = __socklen_t
wctrans_t = POINTER(__int32_t)
class __locale_data(Structure):
    pass
__locale_struct._fields_ = [
    ('__locales', POINTER(__locale_data) * 13),
    ('__ctype_b', POINTER(c_ushort)),
    ('__ctype_tolower', POINTER(c_int)),
    ('__ctype_toupper', POINTER(c_int)),
    ('__names', STRING * 13),
]
locale_t = __locale_t
class __iter_swap_true_(Structure):
    pass
class __copy_move_falsefalsestd__random_access_iterator_tag_(Structure):
    pass
class __copy_move_backward_falsefalsestd__random_access_iterator_tag_(Structure):
    pass
class __equal_true_(Structure):
    pass
class __lc_rai_std__random_access_iterator_tagstd__random_access_iterator_tag_(Structure):
    pass
class __lexicographical_compare_true_(Structure):
    pass
pthread_mutex_t._fields_ = [
    ('__data', __pthread_mutex_s),
    ('__size', c_char * 24),
    ('__align', c_long),
]
pthread_cond_t._pack_ = 4
pthread_cond_t._fields_ = [
    ('__data', N14pthread_cond_t4DOT_18E),
    ('__size', c_char * 48),
    ('__align', c_longlong),
]
__all__ = ['__off_t', 'all', 'cpu_set_t', '__int16_t', 'iterator',
           'istringstream', '__is_byte_char_', '_4DOT_73',
           '__off64_t', '__numeric_traits_integer_int_', 'wifstream',
           'copyfmt_event',
           '__copy_move_falsefalsestd__random_access_iterator_tag_',
           'fpos_t', 'graph',
           'basic_ifstream_wchar_tstd__char_traits_wchar_t__', 'tm',
           'istream', '__cpu_mask', '_G_int16_t',
           'basic_istringstream_charstd__char_traits_char_std__allocator_char__',
           '_S_basefield', 'digit', 'string', '__true_type',
           '__normal_iterator_constchar*std__basic_string_charstd__char_traits_char_std__allocator_char___',
           '_S_internal', 'N4DOT_734DOT_74E', '__time_t',
           '_Atomic_word', '__gthread_mutex_t', '_IO_jump_t',
           '_Ios_Openmode', 'codecvt_base', 'event_callback', 'upper',
           '__uint64_t', 'mode_t', 'timespec', '__type',
           'basic_stringbuf_charstd__char_traits_char_std__allocator_char__',
           '__remove_unsigned_bool_', 'char_traits_wchar_t_',
           '__clockid_t', 'numpunct_byname_wchar_t_',
           'basic_filebuf_wchar_tstd__char_traits_wchar_t__',
           '__ctype_abstract_base_wchar_t_', 'id_t', '_G_fpos_t',
           '_S_hex', '__is_integer_unsignedchar_', 'punct',
           '__promote_longdoublefalse_',
           '__lc_rai_std__random_access_iterator_tagstd__random_access_iterator_tag_',
           'Dl_info', '__locale_data', '__u_long', 'ctype_char_',
           '_Rep', 'pthread_t',
           'N15pthread_mutex_t17__pthread_mutex_s4DOT_15E',
           '__io_read_fn', '__mode_t',
           'ostreambuf_iterator_wchar_tstd__char_traits_wchar_t__',
           'const_reference', '__is_integer_int_', 'u_quad_t',
           'pos_type', 'rebind_wchar_t_', 'fstream', 'fsfilcnt64_t',
           '_S_fixed', 'daddr_t', 'wstreampos', 'fmtflags',
           '__is_integer_longunsignedint_', '__int8_t',
           '__fsblkcnt64_t', 'ctype', 'state_type', '_Ios_Fmtflags',
           'timex', 'cntrl', 'none', 'seek_dir', 'pid_t', 'timer_t',
           'sentry', 'imbue_event', '_IO_FILE', 'pthread_key_t',
           'wistream',
           'basic_ostream_wchar_tstd__char_traits_wchar_t__',
           '__locale_struct', 'u_int8_t', '__digits', 'messages',
           'char_type', 'off_t', '_S_beg', '__fsblkcnt_t',
           'const_reverse_iterator', 'reverse_iterator', '__locale_t',
           'N14pthread_cond_t4DOT_18E',
           'basic_ostream_charstd__char_traits_char__', 'ssize_t',
           'istreambuf_iterator_wchar_tstd__char_traits_wchar_t__',
           '__c_locale', '__add_unsigned_shortint_', 'xdigit',
           'wistringstream', '__is_integer_char_',
           'fpos___mbstate_t_', 'key_t', 'lconv', 'uint', 'sC', 'sB',
           'sA', 'money_base', 'sD',
           '__normal_iterator_wchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t___',
           'wctype_t', '__pthread_internal_slist', '__u_int',
           'random_access_iterator_tag', '__iter_swap_true_',
           '_S_badbit', '__clock_t', '__int_type', '__fsfilcnt_t',
           '__is_char_char_', 'FILE', 'size_t',
           'reverse_iterator___gnu_cxx____normal_iterator_wchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t____',
           'ofstream', 'pointer', '__numeric_traits_floating_int_',
           '__copy_move_backward_falsefalsestd__random_access_iterator_tag_',
           'basic_ostringstream_charstd__char_traits_char_std__allocator_char__',
           '_IO_marker', 'blkcnt_t',
           '__conditional_type_true__gnu_cxx____numeric_traits_integer_int___gnu_cxx____numeric_traits_floating_int__',
           '__gthread_once_t', '__FILE', 'wofstream',
           '__numeric_traits_shortint_',
           'basic_istream_charstd__char_traits_char__',
           'ostreambuf_iterator_charstd__char_traits_char__',
           'u_char', '_S_skipws', 'uid_t', 'cookie_write_function_t',
           'u_int64_t', '__numeric_traits_floating_longunsignedint_',
           '__add_unsigned_int_', '__truth_type_true_',
           '__type_info_pseudo',
           'num_put_wchar_tstd__ostreambuf_iterator_wchar_tstd__char_traits_wchar_t___',
           '__is_byte_signedchar_', 'traits_type', '__int32_t',
           'rebind_char_',
           '__conditional_type_true__gnu_cxx____numeric_traits_integer_shortint___gnu_cxx____numeric_traits_floating_shortint__',
           'new_allocator_wchar_t_', 'sigevent', 'numeric',
           '__ios_type', 'N4wait3DOT_7E', 'clock_t', 'event',
           '__gthread_recursive_mutex_t', '_S_scientific', 'category',
           'collate_char_', '__useconds_t', 'collate_wchar_t_',
           'space', 'ctype_wchar_t_', '__num_base', '_Rep_base',
           'basic_stringstream_charstd__char_traits_char_std__allocator_char__',
           'collate', 'print', '__jmp_buf_tag',
           '__remove_unsigned_wchar_t_', '__to_type', '__gid_t',
           'iostream', '__base_class_type_info_pseudo',
           '__io_write_fn', '_pthread_cleanup_buffer',
           '_IO_cookie_io_functions_t', 'forward_iterator_tag',
           '__gnuc_va_list', 'nothrow_t', '__pthread_cleanup_class',
           'iterator_std__output_iterator_tagvoidvoidvoidvoid_',
           'wfilebuf', '__cache_type', '__is_integer_unsignedint_',
           '_S_failbit', '__add_unsigned_longint_', '__rlim64_t',
           'ino_t', '_S_oct', 'difference_type',
           '__remove_unsigned_char_', '__caddr_t', 'streamsize',
           '__blksize_t', 'pthread_spinlock_t', '__is_integer_float_',
           '__pthread_slist_t',
           '__numeric_traits_integer_longunsignedint_', '__ssize_t',
           '__is_floating_longdouble_', 'comparison_fn_t',
           '__remove_unsigned_unsignedchar_', 'ino64_t', '_S_cur',
           '__numeric_traits_floating_char_', '__mbstate_t',
           'codecvt_charchar__mbstate_t_', '__uint8_t',
           'basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__',
           '_S_floatfield',
           '__normal_iterator_char*std__basic_string_charstd__char_traits_char_std__allocator_char___',
           '__blkcnt64_t', 'alnum',
           'num_put_charstd__ostreambuf_iterator_charstd__char_traits_char___',
           '_S_showpoint', 'div_t', 'quad_t', '__fsfilcnt64_t',
           'basic_fstream_charstd__char_traits_char__', 'wctrans_t',
           'numpunct_wchar_t_', 'sched_param', 'register_t',
           'pthread_cond_t', 'string_type', 'itimerspec', 'wios',
           '_S_dec', 'terminate_handler', '__rlim_t',
           '__istream_type', '_S_ios_openmode_end', 'Dl_serpath',
           'nlink_t', 'size_type', 'seekdir', 'timeval',
           '__add_unsigned_signedchar_', 'filebuf',
           'basic_filebuf_charstd__char_traits_char__',
           'basic_ofstream_wchar_tstd__char_traits_wchar_t__',
           '__sigset_t', '__vmi_class_type_info_pseudo2',
           '__vmi_class_type_info_pseudo1', '_Callback_list',
           'wstreambuf', 'input_iterator_tag', 'int8_t',
           'num_get_charstd__istreambuf_iterator_charstd__char_traits_char___',
           'ostream', 'alpha', '_S_adjustfield', 'obstack', '_S_out',
           '__remove_unsigned_longlongunsignedint_', '_S_end',
           '__is_byte_unsignedchar_', 'fsblkcnt_t', 'streamoff',
           '__remove_unsigned_longunsignedint_', '__quad_t',
           '__key_t', 'N16pthread_rwlock_t4DOT_21E', 'dev_t',
           '__uid_t', '__uint16_t', '__pthread_mutex_s',
           'reverse_iterator___gnu_cxx____normal_iterator_constwchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t____',
           'bad_alloc', '_S_ios_seekdir_end',
           '__remove_unsigned_shortunsignedint_', 'const_iterator',
           '__swblk_t', 'output_iterator_tag',
           'istreambuf_iterator_charstd__char_traits_char__',
           '__ostream_type', 'char_traits_char_', 'time_t',
           'ctype_base',
           '__normal_iterator_constwchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t___',
           '__loff_t', 'intptr_t', '__is_integer_longint_',
           'new_handler', 'cookie_seek_function_t',
           '__is_integer_longdouble_', '_S_showbase',
           '__gthread_cond_t', 'ctype_byname_wchar_t_', 'va_list',
           'basic_streambuf_charstd__char_traits_char__',
           '_S_uppercase', 'fd_mask', 'collate_byname_char_',
           'iostate', '__timer_t', 'cookie_close_function_t',
           'reference', 'locale', '__wmask_type', '__gthread_time_t',
           'int16_t', '__is_integer_double_',
           '__remove_unsigned_unsignedint_', 'mbstate_t',
           'wostringstream', '_Alloc_hider', '__pthread_unwind_buf_t',
           'ldiv_t',
           'basic_istringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__',
           '__streambuf_type',
           'basic_fstream_wchar_tstd__char_traits_wchar_t__',
           'time_base', 'value_type', 'streambuf', '__intptr_t',
           'erase_event', '_IO_FILE_plus', 'ushort', '__blkcnt_t',
           'facet', 'clockid_t', '__gthread_t', 'Dl_serinfo',
           'fd_set', 'caddr_t', '__add_unsigned_wchar_t_', 'wostream',
           '_S_boolalpha',
           'basic_stringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__',
           'int32_t', 'off64_t', 'codecvt_wchar_tchar__mbstate_t_',
           'const_pointer', '__compar_d_fn_t', 'cA',
           'N11__mbstate_t3DOT_2E',
           'basic_ios_charstd__char_traits_char__',
           '__conditional_type_truelongunsignedintlonglongunsignedint_',
           'N4wait3DOT_6E', '__numpunct_cache_wchar_t_',
           'basic_string_charstd__char_traits_char_std__allocator_char__',
           'fpos64_t', '__dev_t', 'collate_byname_wchar_t_',
           '__forced_unwind', '__qaddr_t', 'exception',
           '__suseconds_t', '__lexicographical_compare_true_',
           '_S_app',
           'num_get_wchar_tstd__istreambuf_iterator_wchar_tstd__char_traits_wchar_t___',
           'u_long', '_S_bin', 'allocator_type',
           '__add_unsigned_char_', 'numpunct_byname_char_',
           'streampos', '_S_in',
           'basic_ifstream_charstd__char_traits_char__', '__u_char',
           '__jmp_buf', 'Init', '_S_trunc', 'id', '_Words', 'u_short',
           'drand48_data', '_S_ios_iostate_end', 'fsblkcnt64_t',
           'fsfilcnt_t', '__is_integer_longlongint_',
           '__is_void_void_', 'ios', '__ino_t', '_IO_lock_t',
           'wstring', '__ctype_type', '__max', 'iter_type', 'lower',
           '_Ios_Seekdir', '__is_floating_float_', 'bad_exception',
           '__numeric_traits_char_', 'pthread_mutex_t', '__int64_t',
           'basic_ostringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__',
           'suseconds_t', 'ctype_byname_char_', '__num_get_type',
           '__is_integer_bool_', 'pthread_once_t', '_S_unitbuf',
           '__fsid_t', '__is_integer_longlongunsignedint_',
           '_S_eofbit', 'random_data', 'u_int16_t', 'ios_base',
           '__uint32_t', '_S_goodbit', '__equal_true_', 'stringbuf',
           '__ino64_t', 'basic_ios_wchar_tstd__char_traits_wchar_t__',
           '__u_short', 'loff_t', '__is_integer_shortint_',
           'blksize_t', '_S_ate', 'open_mode', 'u_int32_t',
           'basic_streambuf_wchar_tstd__char_traits_wchar_t__',
           '_G_uint32_t', 'ifstream', '_G_fpos64_t',
           '__pthread_cleanup_frame',
           '__numeric_traits_integer_shortint_',
           '__is_floating_double_',
           'basic_iostream_wchar_tstd__char_traits_wchar_t__',
           '__nlink_t', '__compar_fn_t', 'bidirectional_iterator_tag',
           'iterator_category', 'fsid_t',
           'reverse_iterator___gnu_cxx____normal_iterator_constchar*std__basic_string_charstd__char_traits_char_std__allocator_char____',
           'basic_stringbuf_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__',
           '__id_t', 'cookie_io_functions_t', '__promote_floatfalse_',
           'ulong',
           '__conditional_type_true__gnu_cxx____numeric_traits_integer_char___gnu_cxx____numeric_traits_floating_char__',
           'socklen_t', 'int_type', '__gthread_key_t',
           '__numeric_traits_int_', '_S_ios_fmtflags_end',
           '_G_uint16_t', '__io_close_fn', 'monetary',
           'numpunct_char_', '__add_unsigned_bool_',
           'basic_istream_wchar_tstd__char_traits_wchar_t__',
           'ptrdiff_t', 'other', '_Ios_Iostate', 'openmode',
           '_Raw_bytes_alloc', 'allocator_wchar_t_', 'wint_t',
           'stringstream', '__num_put_type', 'new_allocator_char_',
           '__numeric_traits_floating_shortint_',
           '__promote_doublefalse_',
           'reverse_iterator___gnu_cxx____normal_iterator_char*std__basic_string_charstd__char_traits_char_std__allocator_char____',
           'io_state', 'Lmid_t',
           '__conditional_type_true__gnu_cxx____numeric_traits_integer_longunsignedint___gnu_cxx____numeric_traits_floating_longunsignedint__',
           '__add_unsigned_longlongint_', '__is_integer_wchar_t_',
           '__daddr_t', '__false_type', '_IO_cookie_file',
           '__sig_atomic_t', 'wiostream', 'wstringbuf',
           '__io_seek_fn', '_CharT_alloc_type', 'u_int', 'failure',
           '__fd_mask', 'gid_t', 'unexpected_handler',
           '__is_integer_shortunsignedint_', 'cookie_read_function_t',
           'blkcnt64_t', 'sigset_t', 'ostringstream', 'wfstream',
           'int64_t', 'messages_base', 'off_type',
           'basic_ofstream_charstd__char_traits_char__', 'lldiv_t',
           'allocator_char_', '_S_right', '_S_showpos',
           '__is_integer_signedchar_', '__u_quad_t', 'wstringstream',
           '__numeric_traits_longunsignedint_', 'allocator_void_',
           '__pid_t', '_S_left',
           'basic_iostream_charstd__char_traits_char__', '__min',
           '__numeric_traits_integer_char_', 'useconds_t',
           '__sched_param', '__numpunct_cache_char_', '_Impl',
           'locale_t', '__socklen_t', 'mask', '__is_char_wchar_t_',
           'time', '_G_int32_t']
