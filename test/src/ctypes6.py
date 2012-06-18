from ctypes import *

WSTRING = c_wchar_p
STRING = c_char_p


class rtld_global(Structure):
    pass
class rtld_global_ro(Structure):
    pass
class Node(Structure):
    pass
Node._fields_ = [
    ('val1', c_uint),
    ('ptr2', c_void_p),
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
class allocator_QPair_doubleQColor__(Structure):
    pass
class allocator_QPainterPath__Element_(Structure):
    pass
class allocator_QPointF_(Structure):
    pass
class allocator_QPoint_(Structure):
    pass
class allocator_QString_(Structure):
    pass
class allocator_QObject*_(Structure):
    pass
size_type = size_t
size_type = size_t
difference_type = ptrdiff_t
difference_type = ptrdiff_t
pointer = WSTRING
pointer = STRING
const_pointer = WSTRING
const_pointer = STRING
reference = STRING
reference = WSTRING
const_reference = WSTRING
const_reference = STRING
value_type = c_char
value_type = c_wchar
class new_allocator_char_(Structure):
    pass
class allocator_char_(new_allocator_char_):
    pass
other = allocator_char_
class rebind_char_(Structure):
    pass
class rebind_char_(Structure):
    pass
other = allocator_char_
class new_allocator_wchar_t_(Structure):
    pass
class allocator_wchar_t_(new_allocator_wchar_t_):
    pass
other = allocator_wchar_t_
class rebind_wchar_t_(Structure):
    pass
char_type = c_char
char_type = c_wchar
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
class num_get_charstd__istreambuf_iterator_charstd__char_traits_char___(facet):
    pass
__num_get_type = num_get_charstd__istreambuf_iterator_charstd__char_traits_char___
class num_get_wchar_tstd__istreambuf_iterator_wchar_tstd__char_traits_wchar_t___(facet):
    pass
__num_get_type = num_get_wchar_tstd__istreambuf_iterator_wchar_tstd__char_traits_wchar_t___
_CharT_alloc_type = allocator_wchar_t_
_CharT_alloc_type = allocator_char_
traits_type = char_traits_wchar_t_
traits_type = char_traits_char_
value_type = c_wchar
value_type = c_char
allocator_type = allocator_wchar_t_
allocator_type = allocator_char_
size_type = size_t
size_type = size_t
difference_type = ptrdiff_t
difference_type = ptrdiff_t
reference = WSTRING
reference = STRING
const_reference = STRING
const_reference = WSTRING
pointer = WSTRING
pointer = STRING
const_pointer = WSTRING
const_pointer = STRING
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
__normal_iterator_wchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t___._fields_ = [
    ('_M_current', WSTRING),
]
basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__._fields_ = [
    ('_M_dataplus', _Alloc_hider),
]
collate_wchar_t_._fields_ = [
    ('_M_c_locale_collate', __c_locale),
]
char_type = c_wchar
char_type = c_char
string_type = basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
string_type = basic_string_charstd__char_traits_char_std__allocator_char__
class collate_byname_char_(collate_char_):
    pass
class collate_byname_wchar_t_(collate_wchar_t_):
    pass
char_type = c_char
char_type = c_wchar
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
class __numpunct_cache_wchar_t_(Structure):
    pass
class __numpunct_cache_char_(Structure):
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
string_type = basic_string_charstd__char_traits_char_std__allocator_char__
string_type = basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
__cache_type = __numpunct_cache_char_
__cache_type = __numpunct_cache_wchar_t_
class numpunct_byname_wchar_t_(numpunct_wchar_t_):
    pass
class numpunct_byname_char_(numpunct_char_):
    pass
char_type = c_char
char_type = c_wchar
string_type = basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
string_type = basic_string_charstd__char_traits_char_std__allocator_char__
class istreambuf_iterator_charstd__char_traits_char__(Structure):
    pass
class istreambuf_iterator_wchar_tstd__char_traits_wchar_t__(Structure):
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
iter_type = ostreambuf_iterator_wchar_tstd__char_traits_wchar_t__
iter_type = ostreambuf_iterator_charstd__char_traits_char__
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
_Bit_type = c_ulong
class _Bit_reference(Structure):
    pass
_Bit_reference._fields_ = [
    ('_M_p', POINTER(_Bit_type)),
    ('_M_mask', _Bit_type),
]
class iterator_std__random_access_iterator_tagboolintbool*bool&_(Structure):
    pass
class _Bit_iterator_base(iterator_std__random_access_iterator_tagboolintbool*bool&_):
    pass
_Bit_iterator_base._fields_ = [
    ('_M_p', POINTER(_Bit_type)),
    ('_M_offset', c_uint),
]
class _Bit_iterator(_Bit_iterator_base):
    pass
reference = _Bit_reference
pointer = POINTER(_Bit_reference)
class _Bit_const_iterator(_Bit_iterator_base):
    pass
reference = c_bool
const_reference = c_bool
pointer = POINTER(c_bool)
class _Destroy_aux_false_(Structure):
    pass
class _Destroy_aux_true_(Structure):
    pass
class iterator_std__random_access_iterator_tagboolintconstbool*bool_(Structure):
    pass
class reverse_iterator_std___Bit_const_iterator_(iterator_std__random_access_iterator_tagboolintconstbool*bool_):
    pass
reverse_iterator_std___Bit_const_iterator_._fields_ = [
    ('current', _Bit_const_iterator),
]
class iterator_std__random_access_iterator_tagboolintstd___Bit_reference*std___Bit_reference_(Structure):
    pass
class reverse_iterator_std___Bit_iterator_(iterator_std__random_access_iterator_tagboolintstd___Bit_reference*std___Bit_reference_):
    pass
reverse_iterator_std___Bit_iterator_._fields_ = [
    ('current', _Bit_iterator),
]
class iterator_traits_std___Bit_iterator_(Structure):
    pass
__traits_type = iterator_traits_std___Bit_iterator_
class iterator_traits_std___Bit_const_iterator_(Structure):
    pass
__traits_type = iterator_traits_std___Bit_const_iterator_
iterator_type = _Bit_iterator
iterator_type = _Bit_const_iterator
difference_type = c_int
difference_type = c_int
pointer = POINTER(c_bool)
pointer = POINTER(_Bit_reference)
reference = _Bit_reference
reference = c_bool
class iterator_traits_wchar_t*_(Structure):
    pass
__traits_type = iterator_traits_wchar_t*_
iterator_type = WSTRING
class input_iterator_tag(Structure):
    pass
class forward_iterator_tag(input_iterator_tag):
    pass
class bidirectional_iterator_tag(forward_iterator_tag):
    pass
class random_access_iterator_tag(bidirectional_iterator_tag):
    pass
iterator_category = random_access_iterator_tag
value_type = c_wchar
difference_type = ptrdiff_t
reference = WSTRING
pointer = WSTRING
class output_iterator_tag(Structure):
    pass
class iterator_std__output_iterator_tagvoidvoidvoidvoid_(Structure):
    pass
iterator_category = output_iterator_tag
iterator_category = random_access_iterator_tag
iterator_category = random_access_iterator_tag
iterator_category = random_access_iterator_tag
value_type = None
value_type = c_bool
value_type = c_bool
value_type = c_bool
difference_type = c_int
difference_type = c_int
difference_type = None
difference_type = c_int
pointer = POINTER(_Bit_reference)
pointer = POINTER(c_bool)
pointer = POINTER(c_bool)
pointer = None
reference = _Bit_reference
reference = c_bool
reference = POINTER(c_bool)
reference = None
iterator_category = random_access_iterator_tag
iterator_category = random_access_iterator_tag
value_type = c_bool
value_type = c_bool
difference_type = c_int
difference_type = c_int
pointer = POINTER(_Bit_reference)
pointer = POINTER(c_bool)
reference = c_bool
reference = _Bit_reference
iterator_category = random_access_iterator_tag
value_type = c_wchar
difference_type = ptrdiff_t
pointer = WSTRING
reference = WSTRING
class _List_node_base(Structure):
    pass
_List_node_base._fields_ = [
    ('_M_next', POINTER(_List_node_base)),
    ('_M_prev', POINTER(_List_node_base)),
]
class list_QStringstd__allocator_QString__(Structure):
    pass
class list_QObject*std__allocator_QObject*__(Structure):
    pass
class __uninitialized_copy_false_(Structure):
    pass
class __uninitialized_copy_true_(Structure):
    pass
class __uninitialized_fill_false_(Structure):
    pass
class __uninitialized_fill_true_(Structure):
    pass
class __uninitialized_fill_n_false_(Structure):
    pass
class __uninitialized_fill_n_true_(Structure):
    pass
class vector_QPainterPath__Elementstd__allocator_QPainterPath__Element__(Structure):
    pass
class vector_QPair_doubleQColor_std__allocator_QPair_doubleQColor___(Structure):
    pass
class vector_QPointFstd__allocator_QPointF__(Structure):
    pass
class vector_QPointstd__allocator_QPoint__(Structure):
    pass
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
class __numeric_traits_integer_int_(Structure):
    pass
class __numeric_traits_integer_shortint_(Structure):
    pass
class __numeric_traits_integer_longunsignedint_(Structure):
    pass
class __numeric_traits_integer_char_(Structure):
    pass
__min = -32768 # Variable c_short '-0x000008000'
__min = -2147483648 # Variable c_int '-0x080000000'
__max = 2147483647 # Variable c_int '2147483647'
__max = 32767 # Variable c_short '32767'
__max = '\x7f' # Variable c_char "'\\177'"
__digits = 32 # Variable c_int '32'
class __numeric_traits_floating_shortint_(Structure):
    pass
class __numeric_traits_floating_char_(Structure):
    pass
class __numeric_traits_floating_longunsignedint_(Structure):
    pass
class __numeric_traits_floating_int_(Structure):
    pass
class __numeric_traits_shortint_(__numeric_traits_integer_shortint_):
    pass
class __numeric_traits_int_(__numeric_traits_integer_int_):
    pass
class __numeric_traits_char_(__numeric_traits_integer_char_):
    pass
class __numeric_traits_longunsignedint_(__numeric_traits_integer_longunsignedint_):
    pass
class __conditional_type_true__gnu_cxx____numeric_traits_integer_char___gnu_cxx____numeric_traits_floating_char__(Structure):
    pass
class __conditional_type_true__gnu_cxx____numeric_traits_integer_longunsignedint___gnu_cxx____numeric_traits_floating_longunsignedint__(Structure):
    pass
class __conditional_type_true__gnu_cxx____numeric_traits_integer_shortint___gnu_cxx____numeric_traits_floating_shortint__(Structure):
    pass
class __conditional_type_truelongunsignedintlonglongunsignedint_(Structure):
    pass
class __conditional_type_true__gnu_cxx____numeric_traits_integer_int___gnu_cxx____numeric_traits_floating_int__(Structure):
    pass
__type = __numeric_traits_integer_char_
__type = __numeric_traits_integer_int_
__type = __numeric_traits_integer_shortint_
__type = c_ulong
__type = __numeric_traits_integer_longunsignedint_
class __add_unsigned_wchar_t_(Structure):
    pass
class __add_unsigned_bool_(Structure):
    pass
__type = c_ubyte
class __add_unsigned_char_(Structure):
    pass
class __add_unsigned_signedchar_(Structure):
    pass
__type = c_ubyte
class __add_unsigned_shortint_(Structure):
    pass
__type = c_ushort
class __add_unsigned_int_(Structure):
    pass
__type = c_uint
class __add_unsigned_longint_(Structure):
    pass
__type = c_ulong
__type = c_ulonglong
class __add_unsigned_longlongint_(Structure):
    pass
class __remove_unsigned_bool_(Structure):
    pass
class __remove_unsigned_wchar_t_(Structure):
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
basic_streambuf_wchar_tstd__char_traits_wchar_t__._fields_ = [
    ('_M_in_beg', WSTRING),
    ('_M_in_cur', WSTRING),
    ('_M_in_end', WSTRING),
    ('_M_out_beg', WSTRING),
    ('_M_out_cur', WSTRING),
    ('_M_out_end', WSTRING),
    ('_M_buf_locale', locale),
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
class basic_iostream_charstd__char_traits_char__(basic_istream_charstd__char_traits_char__, basic_ostream_charstd__char_traits_char__):
    pass
class basic_iostream_wchar_tstd__char_traits_wchar_t__(basic_istream_wchar_tstd__char_traits_wchar_t__, basic_ostream_wchar_tstd__char_traits_wchar_t__):
    pass
class basic_stringbuf_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__(Structure):
    pass
class basic_stringbuf_charstd__char_traits_char_std__allocator_char__(Structure):
    pass
class basic_istringstream_charstd__char_traits_char_std__allocator_char__(Structure):
    pass
class basic_istringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__(Structure):
    pass
class basic_ostringstream_charstd__char_traits_char_std__allocator_char__(Structure):
    pass
class basic_ostringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__(Structure):
    pass
class basic_stringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__(Structure):
    pass
class basic_stringstream_charstd__char_traits_char_std__allocator_char__(Structure):
    pass
class basic_filebuf_wchar_tstd__char_traits_wchar_t__(Structure):
    pass
class basic_filebuf_charstd__char_traits_char__(Structure):
    pass
class basic_ifstream_wchar_tstd__char_traits_wchar_t__(Structure):
    pass
class basic_ifstream_charstd__char_traits_char__(Structure):
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
int_type = wint_t
int_type = c_int
pos_type = wstreampos
pos_type = streampos
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
__ctype_type = ctype_wchar_t_
__ctype_type = ctype_char_
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
traits_type = char_traits_char_
traits_type = char_traits_wchar_t_
__streambuf_type = basic_streambuf_wchar_tstd__char_traits_wchar_t__
__streambuf_type = basic_streambuf_charstd__char_traits_char__
__istream_type = basic_istream_charstd__char_traits_char__
__istream_type = basic_istream_wchar_tstd__char_traits_wchar_t__
__ctype_type = ctype_char_
__ctype_type = ctype_wchar_t_
__int_type = c_int
__int_type = wint_t
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
char_type = c_wchar
char_type = c_char
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
__ios_type = basic_ios_wchar_tstd__char_traits_wchar_t__
__ios_type = basic_ios_charstd__char_traits_char__
__num_put_type = num_put_charstd__ostreambuf_iterator_charstd__char_traits_char___
__num_put_type = num_put_wchar_tstd__ostreambuf_iterator_wchar_tstd__char_traits_wchar_t___
__ctype_type = ctype_char_
__ctype_type = ctype_wchar_t_
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
char_type = c_char
char_type = c_wchar
traits_type = char_traits_char_
traits_type = char_traits_wchar_t_
int_type = wint_t
int_type = c_int
pos_type = streampos
pos_type = wstreampos
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
class _5DOT_102(Structure):
    pass
class N5DOT_1025DOT_103E(Structure):
    pass
N5DOT_1025DOT_103E._fields_ = [
    ('__cancel_jmp_buf', __jmp_buf),
    ('__mask_was_saved', c_int),
]
_5DOT_102._fields_ = [
    ('__cancel_jmp_buf', N5DOT_1025DOT_103E * 1),
    ('__pad', c_void_p * 4),
]
__pthread_unwind_buf_t = _5DOT_102
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
class QBasicAtomicInt(Structure):
    pass
class QAtomicInt(QBasicAtomicInt):
    pass
QBasicAtomicInt._fields_ = [
    ('_q_value', c_int),
]
class QList_QByteArray_(Structure):
    pass
class QByteArray(Structure):
    pass
class Data(Structure):
    pass
class QBool(Structure):
    pass
QBool._fields_ = [
    ('b', c_bool),
]
class QString(Structure):
    pass
class Data(Structure):
    pass
class QChar(Structure):
    pass
ushort = c_ushort

# values for enumeration 'Category'
NoCategory = 0
Mark_NonSpacing = 1
Mark_SpacingCombining = 2
Mark_Enclosing = 3
Number_DecimalDigit = 4
Number_Letter = 5
Number_Other = 6
Separator_Space = 7
Separator_Line = 8
Separator_Paragraph = 9
Other_Control = 10
Other_Format = 11
Other_Surrogate = 12
Other_PrivateUse = 13
Other_NotAssigned = 14
Letter_Uppercase = 15
Letter_Lowercase = 16
Letter_Titlecase = 17
Letter_Modifier = 18
Letter_Other = 19
Punctuation_Connector = 20
Punctuation_Dash = 21
Punctuation_Open = 22
Punctuation_Close = 23
Punctuation_InitialQuote = 24
Punctuation_FinalQuote = 25
Punctuation_Other = 26
Symbol_Math = 27
Symbol_Currency = 28
Symbol_Modifier = 29
Symbol_Other = 30
Punctuation_Dask = 21
Category = c_int # enum

# values for enumeration 'Direction'
DirL = 0
DirR = 1
DirEN = 2
DirES = 3
DirET = 4
DirAN = 5
DirCS = 6
DirB = 7
DirS = 8
DirWS = 9
DirON = 10
DirLRE = 11
DirLRO = 12
DirAL = 13
DirRLE = 14
DirRLO = 15
DirPDF = 16
DirNSM = 17
DirBN = 18
Direction = c_int # enum

# values for enumeration 'Joining'
OtherJoining = 0
Dual = 1
Right = 2
Center = 3
Joining = c_int # enum

# values for enumeration 'Decomposition'
NoDecomposition = 0
Canonical = 1
Font = 2
NoBreak = 3
Initial = 4
Medial = 5
Final = 6
Isolated = 7
Circle = 8
Super = 9
Sub = 10
Vertical = 11
Wide = 12
Narrow = 13
Small = 14
Square = 15
Compat = 16
Fraction = 17
Decomposition = c_int # enum

# values for enumeration 'UnicodeVersion'
Unicode_Unassigned = 0
Unicode_1_1 = 1
Unicode_2_0 = 2
Unicode_2_1_2 = 3
Unicode_3_0 = 4
Unicode_3_1 = 5
Unicode_3_2 = 6
Unicode_4_0 = 7
Unicode_4_1 = 8
Unicode_5_0 = 9
UnicodeVersion = c_int # enum
uchar = c_ubyte
uint = c_uint
QChar._fields_ = [
    ('ucs', ushort),
]
qint64 = c_longlong
qlonglong = qint64
quint64 = c_ulonglong
qulonglong = quint64
ulong = c_ulong
__gnuc_va_list = STRING
va_list = __gnuc_va_list

# values for enumeration 'CaseSensitivity'
CaseInsensitive = 0
CaseSensitive = 1
CaseSensitivity = c_int # enum
class QLatin1String(Structure):
    pass
QLatin1String._fields_ = [
    ('chars', STRING),
]
class QRegExp(Structure):
    pass
class QRegExpPrivate(Structure):
    pass

# values for enumeration 'PatternSyntax'
RegExp = 0
Wildcard = 1
FixedString = 2
RegExp2 = 3
WildcardUnix = 4
W3CXmlSchema11 = 5
PatternSyntax = c_int # enum

# values for enumeration 'CaretMode'
CaretAtZero = 0
CaretAtOffset = 1
CaretWontMatch = 2
CaretMode = c_int # enum
class QList_QString_(Structure):
    pass
class QStringList(QList_QString_):
    pass
class N5QListI7QStringE5DOT_111E(Union):
    pass
class QListData(Structure):
    pass
class Data(Structure):
    pass
QListData._fields_ = [
    ('d', POINTER(Data)),
]
N5QListI7QStringE5DOT_111E._fields_ = [
    ('p', QListData),
    ('d', POINTER(Data)),
]
class iterator(Structure):
    pass
class const_iterator(Structure):
    pass
class QVector_QString_(Structure):
    pass
class QSet_QString_(Structure):
    pass
class Node(Structure):
    pass
QList_QString_._anonymous_ = ['_0']
QList_QString_._fields_ = [
    ('_0', N5QListI7QStringE5DOT_111E),
]
QRegExp._fields_ = [
    ('priv', POINTER(QRegExpPrivate)),
]
class QFlags_QString__SectionFlag_(Structure):
    pass

# values for enumeration 'SectionFlag'
SectionDefault = 0
SectionSkipEmpty = 1
SectionIncludeLeadingSep = 2
SectionIncludeTrailingSep = 4
SectionCaseInsensitiveSeps = 8
SectionFlag = c_int # enum
QFlags_QString__SectionFlag_._fields_ = [
    ('i', c_int),
]
class QStringRef(Structure):
    pass
QStringRef._fields_ = [
    ('m_string', POINTER(QString)),
    ('m_position', c_int),
    ('m_size', c_int),
]

# values for enumeration 'SplitBehavior'
KeepEmptyParts = 0
SkipEmptyParts = 1
SplitBehavior = c_int # enum

# values for enumeration 'NormalizationForm'
NormalizationForm_D = 0
NormalizationForm_C = 1
NormalizationForm_KD = 2
NormalizationForm_KC = 3
NormalizationForm = c_int # enum
class QVector_unsignedint_(Structure):
    pass
QStdWString = basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__
QString._fields_ = [
    ('d', POINTER(Data)),
]
QByteArray._fields_ = [
    ('d', POINTER(Data)),
]
Data._fields_ = [
    ('ref', QBasicAtomicInt),
    ('alloc', c_int),
    ('size', c_int),
    ('data', STRING),
    ('array', c_char * 1),
]
iterator = STRING
const_iterator = STRING
Iterator = STRING
ConstIterator = STRING
const_reference = STRING
reference = STRING
value_type = c_char
DataPtr = POINTER(Data)
class QByteRef(Structure):
    pass
QByteRef._fields_ = [
    ('a', POINTER(QByteArray)),
    ('i', c_int),
]
class QTypeInfo_QByteArray_(Structure):
    pass
class QLatin1Char(Structure):
    pass
QLatin1Char._fields_ = [
    ('ch', c_char),
]
class QTypeInfo_QChar_(Structure):
    pass
class QTranslator(Structure):
    pass
class QPostEventList(Structure):
    pass
class QObject(Structure):
    pass
class QCoreApplication(QObject):
    pass
class QMetaObject(Structure):
    pass
class N11QMetaObject4DOT_51E(Structure):
    pass
N11QMetaObject4DOT_51E._fields_ = [
    ('superdata', POINTER(QMetaObject)),
    ('stringdata', STRING),
    ('data', POINTER(uint)),
    ('extradata', c_void_p),
]
class QMetaMethod(Structure):
    pass
class QMetaEnum(Structure):
    pass
class QMetaProperty(Structure):
    pass
class QMetaClassInfo(Structure):
    pass
class QScopedPointer_QObjectDataQScopedPointerDeleter_QObjectData__(Structure):
    pass
class QObjectData(Structure):
    pass
QScopedPointer_QObjectDataQScopedPointerDeleter_QObjectData__._fields_ = [
    ('d', POINTER(QObjectData)),
]

# values for enumeration 'Call'
InvokeMetaMethod = 0
ReadProperty = 1
WriteProperty = 2
ResetProperty = 3
QueryPropertyDesignable = 4
QueryPropertyScriptable = 5
QueryPropertyStored = 6
QueryPropertyEditable = 7
QueryPropertyUser = 8
CreateInstance = 9
Call = c_int # enum
class QObjectPrivate(Structure):
    pass
class QEvent(Structure):
    pass
class QThread(Structure):
    pass
class QList_QObject*_(Structure):
    pass
QObjectList = QList_QObject*_

# values for enumeration 'ConnectionType'
AutoConnection = 0
DirectConnection = 1
QueuedConnection = 2
AutoCompatConnection = 3
BlockingQueuedConnection = 4
UniqueConnection = 128
ConnectionType = c_int # enum
class QVariant(Structure):
    pass
class QObjectUserData(Structure):
    pass
class QTimerEvent(QEvent):
    pass
class QChildEvent(QEvent):
    pass
QObject._fields_ = [
    ('d_ptr', QScopedPointer_QObjectDataQScopedPointerDeleter_QObjectData__),
]
class QGenericArgument(Structure):
    pass
class QGenericReturnArgument(QGenericArgument):
    pass
QGenericArgument._fields_ = [
    ('_data', c_void_p),
    ('_name', STRING),
]
QMetaObject._fields_ = [
    ('d', N11QMetaObject4DOT_51E),
]
class QCoreApplicationPrivate(Structure):
    pass

# values for enumeration 'ApplicationAttribute'
AA_ImmediateWidgetCreation = 0
AA_MSWindowsUseDirect3DByDefault = 1
AA_DontShowIconsInMenus = 2
AA_NativeWindows = 3
AA_DontCreateNativeWidgetSiblings = 4
AA_MacPluginApplication = 5
AA_DontUseNativeMenuBar = 6
AA_MacDontSwapCtrlAndMeta = 7
AA_S60DontConstructApplicationPanes = 8
AA_S60DisablePartialScreenInputMode = 9
AA_X11InitThreads = 10
AA_AttributeCount = 11
ApplicationAttribute = c_int # enum
class QFlags_QEventLoop__ProcessEventsFlag_(Structure):
    pass

# values for enumeration 'ProcessEventsFlag'
AllEvents = 0
ExcludeUserInputEvents = 1
ExcludeSocketNotifiers = 2
WaitForMoreEvents = 4
X11ExcludeTimers = 8
DeferredDeletion = 16
EventLoopExec = 32
DialogExec = 64
ProcessEventsFlag = c_int # enum
QFlags_QEventLoop__ProcessEventsFlag_._fields_ = [
    ('i', c_int),
]

# values for enumeration 'Encoding'
CodecForTr = 0
UnicodeUTF8 = 1
DefaultCodec = 0
Encoding = c_int # enum
EventFilter = CFUNCTYPE(c_bool, c_void_p, POINTER(c_long))
class QEventDispatcherUNIXPrivate(Structure):
    pass
class QWidgetPrivate(Structure):
    pass
class QClassFactory(Structure):
    pass
QtCleanUpFunction = CFUNCTYPE(None)
class QEventPrivate(Structure):
    pass

# values for enumeration 'Type'
None = 0
Timer = 1
MouseButtonPress = 2
MouseButtonRelease = 3
MouseButtonDblClick = 4
MouseMove = 5
KeyPress = 6
KeyRelease = 7
FocusIn = 8
FocusOut = 9
Enter = 10
Leave = 11
Paint = 12
Move = 13
Resize = 14
Create = 15
Destroy = 16
Show = 17
Hide = 18
Close = 19
Quit = 20
ParentChange = 21
ParentAboutToChange = 131
ThreadChange = 22
WindowActivate = 24
WindowDeactivate = 25
ShowToParent = 26
HideToParent = 27
Wheel = 31
WindowTitleChange = 33
WindowIconChange = 34
ApplicationWindowIconChange = 35
ApplicationFontChange = 36
ApplicationLayoutDirectionChange = 37
ApplicationPaletteChange = 38
PaletteChange = 39
Clipboard = 40
Speech = 42
MetaCall = 43
SockAct = 50
WinEventAct = 132
DeferredDelete = 52
DragEnter = 60
DragMove = 61
DragLeave = 62
Drop = 63
DragResponse = 64
ChildAdded = 68
ChildPolished = 69
ChildRemoved = 71
ShowWindowRequest = 73
PolishRequest = 74
Polish = 75
LayoutRequest = 76
UpdateRequest = 77
UpdateLater = 78
EmbeddingControl = 79
ActivateControl = 80
DeactivateControl = 81
ContextMenu = 82
InputMethod = 83
AccessibilityPrepare = 86
TabletMove = 87
LocaleChange = 88
LanguageChange = 89
LayoutDirectionChange = 90
Style = 91
TabletPress = 92
TabletRelease = 93
OkRequest = 94
HelpRequest = 95
IconDrag = 96
FontChange = 97
EnabledChange = 98
ActivationChange = 99
StyleChange = 100
IconTextChange = 101
ModifiedChange = 102
MouseTrackingChange = 109
WindowBlocked = 103
WindowUnblocked = 104
WindowStateChange = 105
ToolTip = 110
WhatsThis = 111
StatusTip = 112
ActionChanged = 113
ActionAdded = 114
ActionRemoved = 115
FileOpen = 116
Shortcut = 117
ShortcutOverride = 51
WhatsThisClicked = 118
ToolBarChange = 120
ApplicationActivate = 121
ApplicationActivated = 121
ApplicationDeactivate = 122
ApplicationDeactivated = 122
QueryWhatsThis = 123
EnterWhatsThisMode = 124
LeaveWhatsThisMode = 125
ZOrderChange = 126
HoverEnter = 127
HoverLeave = 128
HoverMove = 129
AccessibilityHelp = 119
AccessibilityDescription = 130
AcceptDropsChange = 152
MenubarUpdated = 153
ZeroTimerEvent = 154
GraphicsSceneMouseMove = 155
GraphicsSceneMousePress = 156
GraphicsSceneMouseRelease = 157
GraphicsSceneMouseDoubleClick = 158
GraphicsSceneContextMenu = 159
GraphicsSceneHoverEnter = 160
GraphicsSceneHoverMove = 161
GraphicsSceneHoverLeave = 162
GraphicsSceneHelp = 163
GraphicsSceneDragEnter = 164
GraphicsSceneDragMove = 165
GraphicsSceneDragLeave = 166
GraphicsSceneDrop = 167
GraphicsSceneWheel = 168
KeyboardLayoutChange = 169
DynamicPropertyChange = 170
TabletEnterProximity = 171
TabletLeaveProximity = 172
NonClientAreaMouseMove = 173
NonClientAreaMouseButtonPress = 174
NonClientAreaMouseButtonRelease = 175
NonClientAreaMouseButtonDblClick = 176
MacSizeChange = 177
ContentsRectChange = 178
MacGLWindowChange = 179
FutureCallOut = 180
GraphicsSceneResize = 181
GraphicsSceneMove = 182
CursorChange = 183
ToolTipChange = 184
NetworkReplyUpdated = 185
GrabMouse = 186
UngrabMouse = 187
GrabKeyboard = 188
UngrabKeyboard = 189
MacGLClearDrawable = 191
StateMachineSignal = 192
StateMachineWrapped = 193
TouchBegin = 194
TouchUpdate = 195
TouchEnd = 196
NativeGesture = 197
RequestSoftwareInputPanel = 199
CloseSoftwareInputPanel = 200
UpdateSoftKeys = 201
WinIdChange = 203
Gesture = 198
GestureOverride = 202
User = 1000
MaxUser = 65535
Type = c_int # enum
QEvent._fields_ = [
    ('d', POINTER(QEventPrivate)),
    ('t', ushort),
    ('posted', ushort, 1),
    ('spont', ushort, 1),
    ('m_accept', ushort, 1),
    ('reserved', ushort, 13),
]
class Q3AccelManager(Structure):
    pass
class QShortcutMap(Structure):
    pass
class QETWidget(Structure):
    pass
class QGraphicsView(Structure):
    pass
class QGraphicsViewPrivate(Structure):
    pass
class QGraphicsScenePrivate(Structure):
    pass
class QGestureManager(Structure):
    pass
QTimerEvent._fields_ = [
    ('id', c_int),
]
QChildEvent._fields_ = [
    ('c', POINTER(QObject)),
]
class QDynamicPropertyChangeEvent(QEvent):
    pass
QDynamicPropertyChangeEvent._fields_ = [
    ('n', QByteArray),
]
class QDataStreamPrivate(Structure):
    pass
class QDataStream(Structure):
    pass
class QScopedPointer_QDataStreamPrivateQScopedPointerDeleter_QDataStreamPrivate__(Structure):
    pass
QScopedPointer_QDataStreamPrivateQScopedPointerDeleter_QDataStreamPrivate__._fields_ = [
    ('d', POINTER(QDataStreamPrivate)),
]
class QIODevice(QObject):
    pass

# values for enumeration 'ByteOrder'
BigEndian = 0
LittleEndian = 1
ByteOrder = c_int # enum

# values for enumeration 'Status'
Ok = 0
ReadPastEnd = 1
ReadCorruptData = 2
Status = c_int # enum

# values for enumeration 'FloatingPointPrecision'
SinglePrecision = 0
DoublePrecision = 1
FloatingPointPrecision = c_int # enum
QDataStream._fields_ = [
    ('d', QScopedPointer_QDataStreamPrivateQScopedPointerDeleter_QDataStreamPrivate__),
    ('dev', POINTER(QIODevice)),
    ('owndev', c_bool),
    ('noswap', c_bool),
    ('byteorder', ByteOrder),
    ('ver', c_int),
    ('q_status', Status),
]
class QEventLoopPrivate(Structure):
    pass
class QEventLoop(QObject):
    pass
ProcessEventsFlags = QFlags_QEventLoop__ProcessEventsFlag_
qint8 = c_byte
quint8 = c_ubyte
qint16 = c_short
quint16 = c_ushort
qint32 = c_int
quint32 = c_uint
Signed = qint8
class QIntegerForSize_1_(Structure):
    pass
Unsigned = quint8
Unsigned = quint16
class QIntegerForSize_2_(Structure):
    pass
Signed = qint16
class QIntegerForSize_4_(Structure):
    pass
Signed = qint32
Unsigned = quint32
Unsigned = quint64
class QIntegerForSize_8_(Structure):
    pass
Signed = qint64
class QIntegerForSizeof_void*_(QIntegerForSize_4_):
    pass
quintptr = quint32
qptrdiff = qint32
QNoImplicitBoolCast = c_int
qreal = c_double
class QSysInfo(Structure):
    pass
class QDebug(Structure):
    pass
class QNoDebug(Structure):
    pass

# values for enumeration 'QtMsgType'
QtDebugMsg = 0
QtWarningMsg = 1
QtCriticalMsg = 2
QtFatalMsg = 3
QtSystemMsg = 2
QtMsgType = c_int # enum
QtMsgHandler = CFUNCTYPE(None, QtMsgType, STRING)
class QTypeInfo_bool_(Structure):
    pass
class QTypeInfo_char_(Structure):
    pass
class QTypeInfo_signedchar_(Structure):
    pass
class QTypeInfo_unsignedchar_(Structure):
    pass
class QTypeInfo_shortint_(Structure):
    pass
class QTypeInfo_shortunsignedint_(Structure):
    pass
class QTypeInfo_int_(Structure):
    pass
class QTypeInfo_unsignedint_(Structure):
    pass
class QTypeInfo_longint_(Structure):
    pass
class QTypeInfo_longunsignedint_(Structure):
    pass
class QTypeInfo_longlongint_(Structure):
    pass
class QTypeInfo_longlongunsignedint_(Structure):
    pass
class QTypeInfo_float_(Structure):
    pass
class QTypeInfo_double_(Structure):
    pass
class QTypeInfo_longdouble_(Structure):
    pass
class QFlag(Structure):
    pass
QFlag._fields_ = [
    ('i', c_int),
]
class QIncompatibleFlag(Structure):
    pass
QIncompatibleFlag._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__TextInteractionFlag_(Structure):
    pass

# values for enumeration 'TextInteractionFlag'
NoTextInteraction = 0
TextSelectableByMouse = 1
TextSelectableByKeyboard = 2
LinksAccessibleByMouse = 4
LinksAccessibleByKeyboard = 8
TextEditable = 16
TextEditorInteraction = 19
TextBrowserInteraction = 13
TextInteractionFlag = c_int # enum
QFlags_Qt__TextInteractionFlag_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__MatchFlag_(Structure):
    pass

# values for enumeration 'MatchFlag'
MatchExactly = 0
MatchContains = 1
MatchStartsWith = 2
MatchEndsWith = 3
MatchRegExp = 4
MatchWildcard = 5
MatchFixedString = 8
MatchCaseSensitive = 16
MatchWrap = 32
MatchRecursive = 64
MatchFlag = c_int # enum
QFlags_Qt__MatchFlag_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__ItemFlag_(Structure):
    pass

# values for enumeration 'ItemFlag'
NoItemFlags = 0
ItemIsSelectable = 1
ItemIsEditable = 2
ItemIsDragEnabled = 4
ItemIsDropEnabled = 8
ItemIsUserCheckable = 16
ItemIsEnabled = 32
ItemIsTristate = 64
ItemFlag = c_int # enum
QFlags_Qt__ItemFlag_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__DropAction_(Structure):
    pass

# values for enumeration 'DropAction'
CopyAction = 1
MoveAction = 2
LinkAction = 4
ActionMask = 255
TargetMoveAction = 32770
IgnoreAction = 0
DropAction = c_int # enum
QFlags_Qt__DropAction_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__WindowState_(Structure):
    pass

# values for enumeration 'WindowState'
WindowNoState = 0
WindowMinimized = 1
WindowMaximized = 2
WindowFullScreen = 4
WindowActive = 8
WindowState = c_int # enum
QFlags_Qt__WindowState_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__ToolBarArea_(Structure):
    pass

# values for enumeration 'ToolBarArea'
LeftToolBarArea = 1
RightToolBarArea = 2
TopToolBarArea = 4
BottomToolBarArea = 8
ToolBarArea_Mask = 15
AllToolBarAreas = 15
NoToolBarArea = 0
ToolBarArea = c_int # enum
QFlags_Qt__ToolBarArea_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__DockWidgetArea_(Structure):
    pass

# values for enumeration 'DockWidgetArea'
LeftDockWidgetArea = 1
RightDockWidgetArea = 2
TopDockWidgetArea = 4
BottomDockWidgetArea = 8
DockWidgetArea_Mask = 15
AllDockWidgetAreas = 15
NoDockWidgetArea = 0
DockWidgetArea = c_int # enum
QFlags_Qt__DockWidgetArea_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__ImageConversionFlag_(Structure):
    pass

# values for enumeration 'ImageConversionFlag'
ColorMode_Mask = 3
AutoColor = 0
ColorOnly = 3
MonoOnly = 2
AlphaDither_Mask = 12
ThresholdAlphaDither = 0
OrderedAlphaDither = 4
DiffuseAlphaDither = 8
NoAlpha = 12
Dither_Mask = 48
DiffuseDither = 0
OrderedDither = 16
ThresholdDither = 32
DitherMode_Mask = 192
AutoDither = 0
PreferDither = 64
AvoidDither = 128
NoOpaqueDetection = 256
NoFormatConversion = 512
ImageConversionFlag = c_int # enum
QFlags_Qt__ImageConversionFlag_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__AlignmentFlag_(Structure):
    pass

# values for enumeration 'AlignmentFlag'
AlignLeft = 1
AlignLeading = 1
AlignRight = 2
AlignTrailing = 2
AlignHCenter = 4
AlignJustify = 8
AlignAbsolute = 16
AlignHorizontal_Mask = 31
AlignTop = 32
AlignBottom = 64
AlignVCenter = 128
AlignVertical_Mask = 224
AlignCenter = 132
AlignmentFlag = c_int # enum
QFlags_Qt__AlignmentFlag_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__MouseButton_(Structure):
    pass

# values for enumeration 'MouseButton'
NoButton = 0
LeftButton = 1
RightButton = 2
MidButton = 4
MiddleButton = 4
XButton1 = 8
XButton2 = 16
MouseButtonMask = 255
MouseButton = c_int # enum
QFlags_Qt__MouseButton_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__WindowType_(Structure):
    pass

# values for enumeration 'WindowType'
Widget = 0
Window = 1
Dialog = 3
Sheet = 5
Drawer = 7
Popup = 9
Tool = 11
ToolTip = 13
SplashScreen = 15
Desktop = 17
SubWindow = 18
WindowType_Mask = 255
MSWindowsFixedSizeDialogHint = 256
MSWindowsOwnDC = 512
X11BypassWindowManagerHint = 1024
FramelessWindowHint = 2048
WindowTitleHint = 4096
WindowSystemMenuHint = 8192
WindowMinimizeButtonHint = 16384
WindowMaximizeButtonHint = 32768
WindowMinMaxButtonsHint = 49152
WindowContextHelpButtonHint = 65536
WindowShadeButtonHint = 131072
WindowStaysOnTopHint = 262144
CustomizeWindowHint = 33554432
WindowStaysOnBottomHint = 67108864
WindowCloseButtonHint = 134217728
MacWindowToolBarButtonHint = 268435456
BypassGraphicsProxyWidget = 536870912
WindowOkButtonHint = 524288
WindowCancelButtonHint = 1048576
WindowSoftkeysVisibleHint = 1073741824
WindowSoftkeysRespondHint = -2147483648
WindowType = c_int # enum
QFlags_Qt__WindowType_._fields_ = [
    ('i', c_int),
]
class QFlags_QWidget__RenderFlag_(Structure):
    pass

# values for enumeration 'RenderFlag'
DrawWindowBackground = 1
DrawChildren = 2
IgnoreMask = 4
RenderFlag = c_int # enum
QFlags_QWidget__RenderFlag_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__GestureFlag_(Structure):
    pass

# values for enumeration 'GestureFlag'
DontStartGestureOnChildren = 1
ReceivePartialGestures = 2
IgnoredGesturesPropagateToParent = 4
GestureFlag = c_int # enum
QFlags_Qt__GestureFlag_._fields_ = [
    ('i', c_int),
]
class QFlags_QSizePolicy__ControlType_(Structure):
    pass

# values for enumeration 'ControlType'
DefaultType = 1
ButtonBox = 2
CheckBox = 4
ComboBox = 8
Frame = 16
GroupBox = 32
Label = 64
Line = 128
LineEdit = 256
PushButton = 512
RadioButton = 1024
Slider = 2048
SpinBox = 4096
TabWidget = 8192
ToolButton = 16384
ControlType = c_int # enum
QFlags_QSizePolicy__ControlType_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__KeyboardModifier_(Structure):
    pass

# values for enumeration 'KeyboardModifier'
NoModifier = 0
ShiftModifier = 33554432
ControlModifier = 67108864
AltModifier = 134217728
MetaModifier = 268435456
KeypadModifier = 536870912
GroupSwitchModifier = 1073741824
KeyboardModifierMask = -33554432
KeyboardModifier = c_int # enum
QFlags_Qt__KeyboardModifier_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__Orientation_(Structure):
    pass

# values for enumeration 'Orientation'
Horizontal = 1
Vertical = 2
Orientation = c_int # enum
QFlags_Qt__Orientation_._fields_ = [
    ('i', c_int),
]
class QFlags_QIODevice__OpenModeFlag_(Structure):
    pass

# values for enumeration 'OpenModeFlag'
NotOpen = 0
ReadOnly = 1
WriteOnly = 2
ReadWrite = 3
Append = 4
Truncate = 8
Text = 16
Unbuffered = 32
OpenModeFlag = c_int # enum
QFlags_QIODevice__OpenModeFlag_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__InputMethodHint_(Structure):
    pass

# values for enumeration 'InputMethodHint'
ImhNone = 0
ImhHiddenText = 1
ImhNoAutoUppercase = 2
ImhPreferNumbers = 4
ImhPreferUppercase = 8
ImhPreferLowercase = 16
ImhNoPredictiveText = 32
ImhDigitsOnly = 65536
ImhFormattedNumbersOnly = 131072
ImhUppercaseOnly = 262144
ImhLowercaseOnly = 524288
ImhDialableCharactersOnly = 1048576
ImhEmailCharactersOnly = 2097152
ImhUrlCharactersOnly = 4194304
ImhExclusiveInputMask = -65536
InputMethodHint = c_int # enum
QFlags_Qt__InputMethodHint_._fields_ = [
    ('i', c_int),
]
class QFlags_Qt__TouchPointState_(Structure):
    pass

# values for enumeration 'TouchPointState'
TouchPointPressed = 1
TouchPointMoved = 2
TouchPointStationary = 4
TouchPointReleased = 8
TouchPointStateMask = 15
TouchPointPrimary = 16
TouchPointState = c_int # enum
QFlags_Qt__TouchPointState_._fields_ = [
    ('i', c_int),
]
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
Zero = POINTER(c_void_p)
enum_type = AlignmentFlag
enum_type = DockWidgetArea
enum_type = MouseButton
enum_type = InputMethodHint
enum_type = WindowType
enum_type = MatchFlag
enum_type = ItemFlag
enum_type = TouchPointState
enum_type = GestureFlag
enum_type = Orientation
enum_type = ControlType
enum_type = DropAction
enum_type = WindowState
enum_type = KeyboardModifier
enum_type = ToolBarArea
enum_type = ProcessEventsFlag
enum_type = ImageConversionFlag
enum_type = TextInteractionFlag
enum_type = SectionFlag
enum_type = OpenModeFlag
enum_type = RenderFlag
class QIODevicePrivate(Structure):
    pass
OpenMode = QFlags_QIODevice__OpenModeFlag_
class QLine(Structure):
    pass
class QPoint(Structure):
    pass
QPoint._fields_ = [
    ('xp', c_int),
    ('yp', c_int),
]
QLine._fields_ = [
    ('pt1', QPoint),
    ('pt2', QPoint),
]
class QTypeInfo_QLine_(Structure):
    pass
class QLineF(Structure):
    pass
class QPointF(Structure):
    pass
QPointF._fields_ = [
    ('xp', qreal),
    ('yp', qreal),
]

# values for enumeration 'IntersectType'
NoIntersection = 0
BoundedIntersection = 1
UnboundedIntersection = 2
IntersectType = c_int # enum
QLineF._fields_ = [
    ('pt1', QPointF),
    ('pt2', QPointF),
]
class QTypeInfo_QLineF_(Structure):
    pass
class QSet_QWidget*_(Structure):
    pass
class QSet_QObject*_(Structure):
    pass
Data._fields_ = [
    ('ref', QBasicAtomicInt),
    ('alloc', c_int),
    ('begin', c_int),
    ('end', c_int),
    ('sharable', uint, 1),
    ('array', c_void_p * 1),
]
class N5QListIP7QObjectE5DOT_111E(Union):
    pass
N5QListIP7QObjectE5DOT_111E._fields_ = [
    ('p', QListData),
    ('d', POINTER(Data)),
]
class iterator(Structure):
    pass
class const_iterator(Structure):
    pass
class QVector_QObject*_(Structure):
    pass
class Node(Structure):
    pass
QList_QObject*_._anonymous_ = ['_0']
QList_QObject*_._fields_ = [
    ('_0', N5QListIP7QObjectE5DOT_111E),
]
class QList_QAction*_(Structure):
    pass
class QList_QPair_doubleQColor__(Structure):
    pass
class QList_QKeySequence_(Structure):
    pass
class QList_QSize_(Structure):
    pass
class QList_QImageTextKeyLang_(Structure):
    pass
class QList_QPainterPath__Element_(Structure):
    pass
class QList_QPolygonF_(Structure):
    pass
class QList_QPointF_(Structure):
    pass
class QList_QPoint_(Structure):
    pass
class QList_QWidget*_(Structure):
    pass
class QList_void*_(Structure):
    pass
Iterator = iterator
Iterator = iterator
ConstIterator = const_iterator
ConstIterator = const_iterator
size_type = c_int
size_type = c_int
value_type = QString
value_type = POINTER(QObject)
pointer = POINTER(QString)
pointer = POINTER(POINTER(QObject))
const_pointer = POINTER(QString)
const_pointer = POINTER(POINTER(QObject))
reference = POINTER(QString)
reference = POINTER(POINTER(QObject))
const_reference = POINTER(QString)
const_reference = POINTER(POINTER(QObject))
difference_type = qptrdiff
difference_type = qptrdiff
class QListIterator_QString_(Structure):
    pass
class QMutableListIterator_QString_(Structure):
    pass
class QMargins(Structure):
    pass
QMargins._fields_ = [
    ('m_left', c_int),
    ('m_top', c_int),
    ('m_right', c_int),
    ('m_bottom', c_int),
]
class QTypeInfo_QMargins_(Structure):
    pass
KeyboardModifiers = QFlags_Qt__KeyboardModifier_
MouseButtons = QFlags_Qt__MouseButton_
Orientations = QFlags_Qt__Orientation_
Alignment = QFlags_Qt__AlignmentFlag_
WindowFlags = QFlags_Qt__WindowType_
WindowStates = QFlags_Qt__WindowState_
ImageConversionFlags = QFlags_Qt__ImageConversionFlag_
DockWidgetAreas = QFlags_Qt__DockWidgetArea_
ToolBarAreas = QFlags_Qt__ToolBarArea_
InputMethodHints = QFlags_Qt__InputMethodHint_
DropActions = QFlags_Qt__DropAction_
ItemFlags = QFlags_Qt__ItemFlag_
MatchFlags = QFlags_Qt__MatchFlag_
HANDLE = c_ulong
WFlags = WindowFlags
TextInteractionFlags = QFlags_Qt__TextInteractionFlag_
TouchPointStates = QFlags_Qt__TouchPointState_
GestureFlags = QFlags_Qt__GestureFlag_
qInternalCallback = CFUNCTYPE(c_bool, POINTER(c_void_p))
class QInternal(Structure):
    pass

# values for enumeration 'Callback'
ConnectCallback = 0
DisconnectCallback = 1
AdoptCurrentThread = 2
EventNotifyCallback = 3
LastCallback = 4
Callback = c_int # enum

# values for enumeration 'InternalFunction'
CreateThreadForAdoption = 0
RefAdoptedThread = 1
DerefAdoptedThread = 2
SetCurrentThreadToMainThread = 3
SetQObjectSender = 4
GetQObjectSender = 5
ResetQObjectSender = 6
LastInternalFunction = 7
InternalFunction = c_int # enum
QObjectData._fields_ = [
    ('q_ptr', POINTER(QObject)),
    ('parent', POINTER(QObject)),
    ('children', QObjectList),
    ('isWidget', uint, 1),
    ('pendTimer', uint, 1),
    ('blockSig', uint, 1),
    ('wasDeleted', uint, 1),
    ('ownObjectName', uint, 1),
    ('sendChildEvents', uint, 1),
    ('receiveChildEvents', uint, 1),
    ('inEventHandler', uint, 1),
    ('inThreadChangeEvent', uint, 1),
    ('hasGuards', uint, 1),
    ('unused', uint, 22),
    ('postedEvents', c_int),
    ('metaObject', POINTER(QMetaObject)),
]
class QApplicationPrivate(Structure):
    pass
class QThreadData(Structure):
    pass
QMetaObjectAccessor = CFUNCTYPE(POINTER(QMetaObject))
class QMetaObjectExtraData(Structure):
    pass
QMetaObjectExtraData._fields_ = [
    ('objects', POINTER(POINTER(QMetaObject))),
    ('static_metacall', CFUNCTYPE(c_int, Call, c_int, POINTER(c_void_p))),
]

# values for enumeration 'QtValidLicenseForCoreModule'
LicensedCore = 1
QtValidLicenseForCoreModule = c_int # enum
QtCoreModule = QtValidLicenseForCoreModule
class QPair_doubleQColor_(Structure):
    pass
class QTypeInfo_QPoint_(Structure):
    pass
class QTypeInfo_QPointF_(Structure):
    pass
class QRect(Structure):
    pass
class QSize(Structure):
    pass

# values for enumeration 'AspectRatioMode'
IgnoreAspectRatio = 0
KeepAspectRatio = 1
KeepAspectRatioByExpanding = 2
AspectRatioMode = c_int # enum
QSize._fields_ = [
    ('wd', c_int),
    ('ht', c_int),
]
QRect._fields_ = [
    ('x1', c_int),
    ('y1', c_int),
    ('x2', c_int),
    ('y2', c_int),
]
class QTypeInfo_QRect_(Structure):
    pass
class QRectF(Structure):
    pass
class QSizeF(Structure):
    pass
QSizeF._fields_ = [
    ('wd', qreal),
    ('ht', qreal),
]
QRectF._fields_ = [
    ('xp', qreal),
    ('yp', qreal),
    ('w', qreal),
    ('h', qreal),
]
class QTypeInfo_QRectF_(Structure):
    pass
class QTypeInfo_QRegExp_(Structure):
    pass
class QScopedPointerDeleter_QPainterPathStrokerPrivate_(Structure):
    pass
class QScopedPointerDeleter_QDataStreamPrivate_(Structure):
    pass
class QScopedPointerDeleter_QObjectData_(Structure):
    pass
class QScopedPointerPodDeleter(Structure):
    pass
class QScopedPointer_QPainterPathStrokerPrivateQScopedPointerDeleter_QPainterPathStrokerPrivate__(Structure):
    pass
class QPainterPathStrokerPrivate(Structure):
    pass
QScopedPointer_QPainterPathStrokerPrivateQScopedPointerDeleter_QPainterPathStrokerPrivate__._fields_ = [
    ('d', POINTER(QPainterPathStrokerPrivate)),
]
class QScopedPointer_QPainterPathPrivateQPainterPathPrivateDeleter_(Structure):
    pass
class QPainterPathPrivate(Structure):
    pass
QScopedPointer_QPainterPathPrivateQPainterPathPrivateDeleter_._fields_ = [
    ('d', POINTER(QPainterPathPrivate)),
]
class QScopedPointer_QBrushDataQBrushDataPointerDeleter_(Structure):
    pass
class QBrushData(Structure):
    pass
QScopedPointer_QBrushDataQBrushDataPointerDeleter_._fields_ = [
    ('d', POINTER(QBrushData)),
]
RestrictedBool = POINTER(POINTER(QDataStreamPrivate))
RestrictedBool = POINTER(POINTER(QBrushData))
RestrictedBool = POINTER(POINTER(QPainterPathPrivate))
RestrictedBool = POINTER(POINTER(QObjectData))
RestrictedBool = POINTER(POINTER(QPainterPathStrokerPrivate))
pointer = POINTER(QDataStreamPrivate)
pointer = POINTER(QBrushData)
pointer = POINTER(QObjectData)
pointer = POINTER(QPainterPathPrivate)
pointer = POINTER(QPainterPathStrokerPrivate)
class QSharedData(Structure):
    pass
QSharedData._fields_ = [
    ('ref', QAtomicInt),
]
class QSharedDataPointer_QIcon_(Structure):
    pass
class QSharedDataPointer_QBrush_(Structure):
    pass
class QSharedDataPointer_QKeySequence_(Structure):
    pass
class QSharedDataPointer_QPixmap_(Structure):
    pass
class QSharedDataPointer_QImage_(Structure):
    pass
class QExplicitlySharedDataPointer_QIcon_(Structure):
    pass
class QExplicitlySharedDataPointer_QKeySequence_(Structure):
    pass
class QExplicitlySharedDataPointer_QBrush_(Structure):
    pass
class QExplicitlySharedDataPointer_QPixmapData_(Structure):
    pass
class QPixmapData(Structure):
    pass
QExplicitlySharedDataPointer_QPixmapData_._fields_ = [
    ('d', POINTER(QPixmapData)),
]
class QExplicitlySharedDataPointer_QImage_(Structure):
    pass
class QExplicitlySharedDataPointer_QFontPrivate_(Structure):
    pass
class QFontPrivate(Structure):
    pass
QExplicitlySharedDataPointer_QFontPrivate_._fields_ = [
    ('d', POINTER(QFontPrivate)),
]
class QExplicitlySharedDataPointer_QPixmap_(Structure):
    pass
Type = QPixmapData
Type = QFontPrivate
pointer = POINTER(QPixmapData)
pointer = POINTER(QFontPrivate)
class RemovePointer_QWidget*_(Structure):
    pass
class RemovePointer_constQWidget*_(Structure):
    pass
class QPaintDevice(Structure):
    pass
class QWidget(QObject, QPaintDevice):
    pass
class QWidgetData(Structure):
    pass
WId = c_ulong
class QStyle(Structure):
    pass

# values for enumeration 'WindowModality'
NonModal = 0
WindowModal = 1
ApplicationModal = 2
WindowModality = c_int # enum
class QRegion(Structure):
    pass
class QRegionData(Structure):
    pass
class QVector_QRect_(Structure):
    pass
class _XRegion(Structure):
    pass
Region = POINTER(_XRegion)
QRegion._fields_ = [
    ('d', POINTER(QRegionData)),
]
class QPalette(Structure):
    pass
class QPalettePrivate(Structure):
    pass

# values for enumeration 'ColorGroup'
Active = 0
Disabled = 1
Inactive = 2
NColorGroups = 3
Current = 4
All = 5
Normal = 0
ColorGroup = c_int # enum
class QColor(Structure):
    pass

# values for enumeration 'Spec'
Invalid = 0
Rgb = 1
Hsv = 2
Cmyk = 3
Hsl = 4
Spec = c_int # enum
class N6QColor5DOT_122E(Union):
    pass
class N6QColor5DOT_1225DOT_123E(Structure):
    pass
N6QColor5DOT_1225DOT_123E._fields_ = [
    ('alpha', ushort),
    ('red', ushort),
    ('green', ushort),
    ('blue', ushort),
    ('pad', ushort),
]
class N6QColor5DOT_1225DOT_124E(Structure):
    pass
N6QColor5DOT_1225DOT_124E._fields_ = [
    ('alpha', ushort),
    ('hue', ushort),
    ('saturation', ushort),
    ('value', ushort),
    ('pad', ushort),
]
class N6QColor5DOT_1225DOT_125E(Structure):
    pass
N6QColor5DOT_1225DOT_125E._fields_ = [
    ('alpha', ushort),
    ('cyan', ushort),
    ('magenta', ushort),
    ('yellow', ushort),
    ('black', ushort),
]
class N6QColor5DOT_1225DOT_126E(Structure):
    pass
N6QColor5DOT_1225DOT_126E._fields_ = [
    ('alpha', ushort),
    ('hue', ushort),
    ('saturation', ushort),
    ('lightness', ushort),
    ('pad', ushort),
]
N6QColor5DOT_122E._fields_ = [
    ('argb', N6QColor5DOT_1225DOT_123E),
    ('ahsv', N6QColor5DOT_1225DOT_124E),
    ('acmyk', N6QColor5DOT_1225DOT_125E),
    ('ahsl', N6QColor5DOT_1225DOT_126E),
    ('array', ushort * 5),
]
QRgb = c_uint
QColor._fields_ = [
    ('cspec', Spec),
    ('ct', N6QColor5DOT_122E),
]

# values for enumeration 'ColorRole'
WindowText = 0
Button = 1
Light = 2
Midlight = 3
Dark = 4
Mid = 5
Text = 6
BrightText = 7
ButtonText = 8
Base = 9
Window = 10
Shadow = 11
Highlight = 12
HighlightedText = 13
Link = 14
LinkVisited = 15
AlternateBase = 16
NoRole = 17
ToolTipBase = 18
ToolTipText = 19
NColorRoles = 20
Foreground = 0
Background = 10
ColorRole = c_int # enum
class QBrush(Structure):
    pass

# values for enumeration 'BrushStyle'
NoBrush = 0
SolidPattern = 1
Dense1Pattern = 2
Dense2Pattern = 3
Dense3Pattern = 4
Dense4Pattern = 5
Dense5Pattern = 6
Dense6Pattern = 7
Dense7Pattern = 8
HorPattern = 9
VerPattern = 10
CrossPattern = 11
BDiagPattern = 12
FDiagPattern = 13
DiagCrossPattern = 14
LinearGradientPattern = 15
RadialGradientPattern = 16
ConicalGradientPattern = 17
TexturePattern = 24
BrushStyle = c_int # enum
class QMatrix(Structure):
    pass
class QVector_QPointF_(Structure):
    pass
class QPolygonF(QVector_QPointF_):
    pass
class QVector_QPoint_(Structure):
    pass
class QPolygon(QVector_QPoint_):
    pass

# values for enumeration 'FillRule'
OddEvenFill = 0
WindingFill = 1
FillRule = c_int # enum
class N7QVectorI6QPointE5DOT_128E(Union):
    pass
class QVectorData(Structure):
    pass
class QVectorTypedData_QPoint_(Structure):
    pass
N7QVectorI6QPointE5DOT_128E._fields_ = [
    ('d', POINTER(QVectorData)),
    ('p', POINTER(QVectorTypedData_QPoint_)),
]
QVector_QPoint_._anonymous_ = ['_0']
QVector_QPoint_._fields_ = [
    ('_0', N7QVectorI6QPointE5DOT_128E),
]
class N7QVectorI7QPointFE5DOT_128E(Union):
    pass
class QVectorTypedData_QPointF_(Structure):
    pass
N7QVectorI7QPointFE5DOT_128E._fields_ = [
    ('d', POINTER(QVectorData)),
    ('p', POINTER(QVectorTypedData_QPointF_)),
]
QVector_QPointF_._anonymous_ = ['_0']
QVector_QPointF_._fields_ = [
    ('_0', N7QVectorI7QPointFE5DOT_128E),
]
class QPainterPath(Structure):
    pass
class QFont(Structure):
    pass

# values for enumeration 'Style'
StyleNormal = 0
StyleItalic = 1
StyleOblique = 2
Style = c_int # enum

# values for enumeration 'StyleHint'
Helvetica = 0
SansSerif = 0
Times = 1
Serif = 1
Courier = 2
TypeWriter = 2
OldEnglish = 3
Decorative = 3
System = 4
AnyStyle = 5
Cursive = 6
Monospace = 7
Fantasy = 8
StyleHint = c_int # enum

# values for enumeration 'StyleStrategy'
PreferDefault = 1
PreferBitmap = 2
PreferDevice = 4
PreferOutline = 8
ForceOutline = 16
PreferMatch = 32
PreferQuality = 64
PreferAntialias = 128
NoAntialias = 256
OpenGLCompatible = 512
ForceIntegerMetrics = 1024
NoFontMerging = 32768
StyleStrategy = c_int # enum

# values for enumeration 'SpacingType'
PercentageSpacing = 0
AbsoluteSpacing = 1
SpacingType = c_int # enum

# values for enumeration 'Capitalization'
MixedCase = 0
AllUppercase = 1
AllLowercase = 2
SmallCaps = 3
Capitalize = 4
Capitalization = c_int # enum
class FT_FaceRec_(Structure):
    pass
FT_Face = POINTER(FT_FaceRec_)
QFont._fields_ = [
    ('d', QExplicitlySharedDataPointer_QFontPrivate_),
    ('resolve_mask', uint),
]

# values for enumeration 'SizeMode'
AbsoluteSize = 0
RelativeSize = 1
SizeMode = c_int # enum
class QTransform(Structure):
    pass
class Private(Structure):
    pass

# values for enumeration 'TransformationType'
TxNone = 0
TxTranslate = 1
TxScale = 2
TxRotate = 4
TxShear = 8
TxProject = 16
TransformationType = c_int # enum

# values for enumeration 'Axis'
XAxis = 0
YAxis = 1
ZAxis = 2
Axis = c_int # enum
QTransform._fields_ = [
    ('affine', QMatrix),
    ('m_13', qreal),
    ('m_23', qreal),
    ('m_33', qreal),
    ('m_type', uint, 5),
    ('m_dirty', uint, 5),
    ('d', POINTER(Private)),
]
class Element(Structure):
    pass

# values for enumeration 'ElementType'
MoveToElement = 0
LineToElement = 1
CurveToElement = 2
CurveToDataElement = 3
ElementType = c_int # enum
Element._fields_ = [
    ('x', qreal),
    ('y', qreal),
    ('type', ElementType),
]
class QPainterPathData(Structure):
    pass
QPainterPath._fields_ = [
    ('d_ptr', QScopedPointer_QPainterPathPrivateQPainterPathPrivateDeleter_),
]
QMatrix._fields_ = [
    ('_m11', qreal),
    ('_m12', qreal),
    ('_m21', qreal),
    ('_m22', qreal),
    ('_dx', qreal),
    ('_dy', qreal),
]
class QPixmap(QPaintDevice):
    pass
class QBitmap(Structure):
    pass

# values for enumeration 'MaskMode'
MaskInColor = 0
MaskOutColor = 1
MaskMode = c_int # enum

# values for enumeration 'TransformationMode'
FastTransformation = 0
SmoothTransformation = 1
TransformationMode = c_int # enum
class QImage(QPaintDevice):
    pass
class QImageData(Structure):
    pass

# values for enumeration 'Format'
Format_Invalid = 0
Format_Mono = 1
Format_MonoLSB = 2
Format_Indexed8 = 3
Format_RGB32 = 4
Format_ARGB32 = 5
Format_ARGB32_Premultiplied = 6
Format_RGB16 = 7
Format_ARGB8565_Premultiplied = 8
Format_RGB666 = 9
Format_ARGB6666_Premultiplied = 10
Format_RGB555 = 11
Format_ARGB8555_Premultiplied = 12
Format_RGB888 = 13
Format_RGB444 = 14
Format_ARGB4444_Premultiplied = 15
NImageFormats = 16
Format = c_int # enum

# values for enumeration 'InvertMode'
InvertRgb = 0
InvertRgba = 1
InvertMode = c_int # enum
class QPaintEngine(Structure):
    pass
class QImageTextKeyLang(Structure):
    pass
QImageTextKeyLang._fields_ = [
    ('key', QByteArray),
    ('lang', QByteArray),
]

# values for enumeration 'PaintDeviceMetric'
PdmWidth = 1
PdmHeight = 2
PdmWidthMM = 3
PdmHeightMM = 4
PdmNumColors = 5
PdmDepth = 6
PdmDpiX = 7
PdmDpiY = 8
PdmPhysicalDpiX = 9
PdmPhysicalDpiY = 10
PaintDeviceMetric = c_int # enum
QPaintDevice._fields_ = [
    ('painters', ushort),
]
QImage._fields_ = [
    ('d', POINTER(QImageData)),
]
class QImageReader(Structure):
    pass

# values for enumeration 'ShareMode'
ImplicitlyShared = 0
ExplicitlyShared = 1
ShareMode = c_int # enum
class QX11Info(Structure):
    pass
class QImageWriter(Structure):
    pass

# values for enumeration 'Type'
PixmapType = 0
BitmapType = 1
Type = c_int # enum
QPixmap._fields_ = [
    ('data', QExplicitlySharedDataPointer_QPixmapData_),
]

# values for enumeration 'GlobalColor'
color0 = 0
color1 = 1
black = 2
white = 3
darkGray = 4
gray = 5
lightGray = 6
red = 7
green = 8
blue = 9
cyan = 10
magenta = 11
yellow = 12
darkRed = 13
darkGreen = 14
darkBlue = 15
darkCyan = 16
darkMagenta = 17
darkYellow = 18
transparent = 19
GlobalColor = c_int # enum
class QGradient(Structure):
    pass

# values for enumeration 'Type'
LinearGradient = 0
RadialGradient = 1
ConicalGradient = 2
NoGradient = 3
Type = c_int # enum

# values for enumeration 'Spread'
PadSpread = 0
ReflectSpread = 1
RepeatSpread = 2
Spread = c_int # enum
class QVector_QPair_doubleQColor__(Structure):
    pass
class N7QVectorI5QPairId6QColorEE5DOT_128E(Union):
    pass
class QVectorTypedData_QPair_doubleQColor__(Structure):
    pass
N7QVectorI5QPairId6QColorEE5DOT_128E._fields_ = [
    ('d', POINTER(QVectorData)),
    ('p', POINTER(QVectorTypedData_QPair_doubleQColor__)),
]
QVector_QPair_doubleQColor__._anonymous_ = ['_0']
QVector_QPair_doubleQColor__._fields_ = [
    ('_0', N7QVectorI5QPairId6QColorEE5DOT_128E),
]
QGradientStops = QVector_QPair_doubleQColor__
class N9QGradient5DOT_141E(Union):
    pass
class N9QGradient5DOT_1415DOT_142E(Structure):
    pass
N9QGradient5DOT_1415DOT_142E._pack_ = 4
N9QGradient5DOT_1415DOT_142E._fields_ = [
    ('x1', qreal),
    ('y1', qreal),
    ('x2', qreal),
    ('y2', qreal),
]
class N9QGradient5DOT_1415DOT_143E(Structure):
    pass
N9QGradient5DOT_1415DOT_143E._pack_ = 4
N9QGradient5DOT_1415DOT_143E._fields_ = [
    ('cx', qreal),
    ('cy', qreal),
    ('fx', qreal),
    ('fy', qreal),
    ('radius', qreal),
]
class N9QGradient5DOT_1415DOT_144E(Structure):
    pass
N9QGradient5DOT_1415DOT_144E._pack_ = 4
N9QGradient5DOT_1415DOT_144E._fields_ = [
    ('cx', qreal),
    ('cy', qreal),
    ('angle', qreal),
]
N9QGradient5DOT_141E._fields_ = [
    ('linear', N9QGradient5DOT_1415DOT_142E),
    ('radial', N9QGradient5DOT_1415DOT_143E),
    ('conical', N9QGradient5DOT_1415DOT_144E),
]

# values for enumeration 'CoordinateMode'
LogicalMode = 0
StretchToDeviceMode = 1
ObjectBoundingMode = 2
CoordinateMode = c_int # enum

# values for enumeration 'InterpolationMode'
ColorInterpolation = 0
ComponentInterpolation = 1
InterpolationMode = c_int # enum
QGradient._fields_ = [
    ('m_type', Type),
    ('m_spread', Spread),
    ('m_stops', QGradientStops),
    ('m_data', N9QGradient5DOT_141E),
    ('dummy', c_void_p),
]
QBrush._fields_ = [
    ('d', QScopedPointer_QBrushDataQBrushDataPointerDeleter_),
]
QPalette._fields_ = [
    ('d', POINTER(QPalettePrivate)),
    ('current_group', uint, 4),
    ('resolve_mask', uint, 28),
]
class QFontMetrics(Structure):
    pass

# values for enumeration 'TextElideMode'
ElideLeft = 0
ElideRight = 1
ElideMiddle = 2
ElideNone = 3
TextElideMode = c_int # enum
QFontMetrics._fields_ = [
    ('d', QExplicitlySharedDataPointer_QFontPrivate_),
]
class QFontInfo(Structure):
    pass
QFontInfo._fields_ = [
    ('d', QExplicitlySharedDataPointer_QFontPrivate_),
]
class QCursor(Structure):
    pass
class QCursorData(Structure):
    pass

# values for enumeration 'CursorShape'
ArrowCursor = 0
UpArrowCursor = 1
CrossCursor = 2
WaitCursor = 3
IBeamCursor = 4
SizeVerCursor = 5
SizeHorCursor = 6
SizeBDiagCursor = 7
SizeFDiagCursor = 8
SizeAllCursor = 9
BlankCursor = 10
SplitVCursor = 11
SplitHCursor = 12
PointingHandCursor = 13
ForbiddenCursor = 14
WhatsThisCursor = 15
BusyCursor = 16
OpenHandCursor = 17
ClosedHandCursor = 18
DragCopyCursor = 19
DragMoveCursor = 20
DragLinkCursor = 21
LastCursor = 21
BitmapCursor = 24
CustomCursor = 25
CursorShape = c_int # enum
QCursor._fields_ = [
    ('d', POINTER(QCursorData)),
]
class QPainter(Structure):
    pass
class QGraphicsEffect(Structure):
    pass

# values for enumeration 'GestureType'
TapGesture = 1
TapAndHoldGesture = 2
PanGesture = 3
PinchGesture = 4
SwipeGesture = 5
CustomGesture = 256
LastGestureType = -1
GestureType = c_int # enum
class QIcon(Structure):
    pass
class QIconPrivate(Structure):
    pass

# values for enumeration 'Mode'
Normal = 0
Disabled = 1
Active = 2
Selected = 3
Mode = c_int # enum

# values for enumeration 'State'
On = 0
Off = 1
State = c_int # enum
QIcon._fields_ = [
    ('d', POINTER(QIconPrivate)),
]

# values for enumeration 'LayoutDirection'
LeftToRight = 0
RightToLeft = 1
LayoutDirectionAuto = 2
LayoutDirection = c_int # enum
class QLocale(Structure):
    pass

# values for enumeration 'FocusReason'
MouseFocusReason = 0
TabFocusReason = 1
BacktabFocusReason = 2
ActiveWindowFocusReason = 3
PopupFocusReason = 4
ShortcutFocusReason = 5
MenuBarFocusReason = 6
OtherFocusReason = 7
NoFocusReason = 8
FocusReason = c_int # enum

# values for enumeration 'FocusPolicy'
NoFocus = 0
TabFocus = 1
ClickFocus = 2
StrongFocus = 11
WheelFocus = 15
FocusPolicy = c_int # enum

# values for enumeration 'ContextMenuPolicy'
NoContextMenu = 0
DefaultContextMenu = 1
ActionsContextMenu = 2
CustomContextMenu = 3
PreventContextMenu = 4
ContextMenuPolicy = c_int # enum
class QKeySequence(Structure):
    pass
class QKeySequencePrivate(Structure):
    pass

# values for enumeration 'SequenceFormat'
NativeText = 0
PortableText = 1
SequenceFormat = c_int # enum

# values for enumeration 'SequenceMatch'
NoMatch = 0
PartialMatch = 1
ExactMatch = 2
SequenceMatch = c_int # enum

# values for enumeration 'StandardKey'
UnknownKey = 0
HelpContents = 1
WhatsThis = 2
Open = 3
Close = 4
Save = 5
New = 6
Delete = 7
Cut = 8
Copy = 9
Paste = 10
Undo = 11
Redo = 12
Back = 13
Forward = 14
Refresh = 15
ZoomIn = 16
ZoomOut = 17
Print = 18
AddTab = 19
NextChild = 20
PreviousChild = 21
Find = 22
FindNext = 23
FindPrevious = 24
Replace = 25
SelectAll = 26
Bold = 27
Italic = 28
Underline = 29
MoveToNextChar = 30
MoveToPreviousChar = 31
MoveToNextWord = 32
MoveToPreviousWord = 33
MoveToNextLine = 34
MoveToPreviousLine = 35
MoveToNextPage = 36
MoveToPreviousPage = 37
MoveToStartOfLine = 38
MoveToEndOfLine = 39
MoveToStartOfBlock = 40
MoveToEndOfBlock = 41
MoveToStartOfDocument = 42
MoveToEndOfDocument = 43
SelectNextChar = 44
SelectPreviousChar = 45
SelectNextWord = 46
SelectPreviousWord = 47
SelectNextLine = 48
SelectPreviousLine = 49
SelectNextPage = 50
SelectPreviousPage = 51
SelectStartOfLine = 52
SelectEndOfLine = 53
SelectStartOfBlock = 54
SelectEndOfBlock = 55
SelectStartOfDocument = 56
SelectEndOfDocument = 57
DeleteStartOfWord = 58
DeleteEndOfWord = 59
DeleteEndOfLine = 60
InsertParagraphSeparator = 61
InsertLineSeparator = 62
SaveAs = 63
Preferences = 64
Quit = 65
StandardKey = c_int # enum
QKeySequence._fields_ = [
    ('d', POINTER(QKeySequencePrivate)),
]

# values for enumeration 'ShortcutContext'
WidgetShortcut = 0
WindowShortcut = 1
ApplicationShortcut = 2
WidgetWithChildrenShortcut = 3
ShortcutContext = c_int # enum
class QGraphicsProxyWidget(Structure):
    pass
class QSizePolicy(Structure):
    pass

# values for enumeration 'Policy'
Fixed = 0
Minimum = 1
Maximum = 4
Preferred = 5
MinimumExpanding = 3
Expanding = 7
Ignored = 13
Policy = c_int # enum
QSizePolicy._fields_ = [
    ('data', quint32),
]
class QLayout(Structure):
    pass
class QAction(Structure):
    pass

# values for enumeration 'WidgetAttribute'
WA_Disabled = 0
WA_UnderMouse = 1
WA_MouseTracking = 2
WA_ContentsPropagated = 3
WA_OpaquePaintEvent = 4
WA_NoBackground = 4
WA_StaticContents = 5
WA_LaidOut = 7
WA_PaintOnScreen = 8
WA_NoSystemBackground = 9
WA_UpdatesDisabled = 10
WA_Mapped = 11
WA_MacNoClickThrough = 12
WA_PaintOutsidePaintEvent = 13
WA_InputMethodEnabled = 14
WA_WState_Visible = 15
WA_WState_Hidden = 16
WA_ForceDisabled = 32
WA_KeyCompression = 33
WA_PendingMoveEvent = 34
WA_PendingResizeEvent = 35
WA_SetPalette = 36
WA_SetFont = 37
WA_SetCursor = 38
WA_NoChildEventsFromChildren = 39
WA_WindowModified = 41
WA_Resized = 42
WA_Moved = 43
WA_PendingUpdate = 44
WA_InvalidSize = 45
WA_MacBrushedMetal = 46
WA_MacMetalStyle = 46
WA_CustomWhatsThis = 47
WA_LayoutOnEntireRect = 48
WA_OutsideWSRange = 49
WA_GrabbedShortcut = 50
WA_TransparentForMouseEvents = 51
WA_PaintUnclipped = 52
WA_SetWindowIcon = 53
WA_NoMouseReplay = 54
WA_DeleteOnClose = 55
WA_RightToLeft = 56
WA_SetLayoutDirection = 57
WA_NoChildEventsForParent = 58
WA_ForceUpdatesDisabled = 59
WA_WState_Created = 60
WA_WState_CompressKeys = 61
WA_WState_InPaintEvent = 62
WA_WState_Reparented = 63
WA_WState_ConfigPending = 64
WA_WState_Polished = 66
WA_WState_DND = 67
WA_WState_OwnSizePolicy = 68
WA_WState_ExplicitShowHide = 69
WA_ShowModal = 70
WA_MouseNoMask = 71
WA_GroupLeader = 72
WA_NoMousePropagation = 73
WA_Hover = 74
WA_InputMethodTransparent = 75
WA_QuitOnClose = 76
WA_KeyboardFocusChange = 77
WA_AcceptDrops = 78
WA_DropSiteRegistered = 79
WA_ForceAcceptDrops = 79
WA_WindowPropagation = 80
WA_NoX11EventCompression = 81
WA_TintedBackground = 82
WA_X11OpenGLOverlay = 83
WA_AlwaysShowToolTips = 84
WA_MacOpaqueSizeGrip = 85
WA_SetStyle = 86
WA_SetLocale = 87
WA_MacShowFocusRect = 88
WA_MacNormalSize = 89
WA_MacSmallSize = 90
WA_MacMiniSize = 91
WA_LayoutUsesWidgetRect = 92
WA_StyledBackground = 93
WA_MSWindowsUseDirect3D = 94
WA_CanHostQMdiSubWindowTitleBar = 95
WA_MacAlwaysShowToolWindow = 96
WA_StyleSheet = 97
WA_ShowWithoutActivating = 98
WA_X11BypassTransientForHint = 99
WA_NativeWindow = 100
WA_DontCreateNativeAncestors = 101
WA_MacVariableSize = 102
WA_DontShowOnScreen = 103
WA_X11NetWmWindowTypeDesktop = 104
WA_X11NetWmWindowTypeDock = 105
WA_X11NetWmWindowTypeToolBar = 106
WA_X11NetWmWindowTypeMenu = 107
WA_X11NetWmWindowTypeUtility = 108
WA_X11NetWmWindowTypeSplash = 109
WA_X11NetWmWindowTypeDialog = 110
WA_X11NetWmWindowTypeDropDownMenu = 111
WA_X11NetWmWindowTypePopupMenu = 112
WA_X11NetWmWindowTypeToolTip = 113
WA_X11NetWmWindowTypeNotification = 114
WA_X11NetWmWindowTypeCombo = 115
WA_X11NetWmWindowTypeDND = 116
WA_MacFrameworkScaled = 117
WA_SetWindowModality = 118
WA_WState_WindowOpacitySet = 119
WA_TranslucentBackground = 120
WA_AcceptTouchEvents = 121
WA_WState_AcceptedTouchBeginEvent = 122
WA_TouchPadAcceptSingleTouchEvents = 123
WA_MergeSoftkeys = 124
WA_MergeSoftkeysRecursively = 125
WA_LockPortraitOrientation = 128
WA_LockLandscapeOrientation = 129
WA_AutoOrientation = 130
WA_X11DoNotAcceptFocus = 132
WA_SymbianNoSystemRotation = 133
WA_AttributeCount = 134
WidgetAttribute = c_int # enum
class QInputContext(Structure):
    pass
class QWindowSurface(Structure):
    pass
class QMouseEvent(Structure):
    pass
class QWheelEvent(Structure):
    pass
class QKeyEvent(Structure):
    pass
class QFocusEvent(Structure):
    pass
class QPaintEvent(Structure):
    pass
class QMoveEvent(Structure):
    pass
class QResizeEvent(Structure):
    pass
class QCloseEvent(Structure):
    pass
class QContextMenuEvent(Structure):
    pass
class QTabletEvent(Structure):
    pass
class QActionEvent(Structure):
    pass
class QDragEnterEvent(Structure):
    pass
class QDragMoveEvent(Structure):
    pass
class QDragLeaveEvent(Structure):
    pass
class QDropEvent(Structure):
    pass
class QShowEvent(Structure):
    pass
class QHideEvent(Structure):
    pass
class _XEvent(Union):
    pass
XEvent = _XEvent
class QInputMethodEvent(Structure):
    pass

# values for enumeration 'InputMethodQuery'
ImMicroFocus = 0
ImFont = 1
ImCursorPosition = 2
ImSurroundingText = 3
ImCurrentSelection = 4
ImMaximumTextLength = 5
ImAnchorPosition = 6
InputMethodQuery = c_int # enum
QWidget._fields_ = [
    ('data', POINTER(QWidgetData)),
]
Type = QWidget
Type = QWidget
class ExternalRefCountData(Structure):
    pass
ExternalRefCountData._fields_ = [
    ('weakref', QBasicAtomicInt),
    ('strongref', QBasicAtomicInt),
]
class ExternalRefCountWithDestroyFn(ExternalRefCountData):
    pass
ExternalRefCountWithDestroyFn._fields_ = [
    ('destroyer', CFUNCTYPE(None, POINTER(ExternalRefCountData))),
]
DestroyerFn = CFUNCTYPE(None, POINTER(ExternalRefCountData))
class QSharedPointer_QImage_(Structure):
    pass
class QSharedPointer_QPixmap_(Structure):
    pass
class QSharedPointer_QIcon_(Structure):
    pass
class QSharedPointer_QKeySequence_(Structure):
    pass
class QSharedPointer_constQWidget_(Structure):
    pass
class QSharedPointer_QBrush_(Structure):
    pass
class QSharedPointer_QWidget_(Structure):
    pass
class QTypeInfo_QSize_(Structure):
    pass
class QTypeInfo_QSizeF_(Structure):
    pass
class QTextCodec(Structure):
    pass
SectionFlags = QFlags_QString__SectionFlag_
iterator = POINTER(QChar)
const_iterator = POINTER(QChar)
Iterator = POINTER(QChar)
ConstIterator = POINTER(QChar)
class Null(Structure):
    pass
Data._fields_ = [
    ('ref', QBasicAtomicInt),
    ('alloc', c_int),
    ('size', c_int),
    ('data', POINTER(ushort)),
    ('clean', ushort, 1),
    ('simpletext', ushort, 1),
    ('righttoleft', ushort, 1),
    ('asciiCache', ushort, 1),
    ('capacity', ushort, 1),
    ('reserved', ushort, 11),
    ('array', ushort * 1),
]
class QAbstractConcatenable(Structure):
    pass
DataPtr = POINTER(Data)
class QCharRef(Structure):
    pass
QCharRef._fields_ = [
    ('s', POINTER(QString)),
    ('i', c_int),
]
class QTypeInfo_QString_(Structure):
    pass
QStringListIterator = QListIterator_QString_
QMutableStringListIterator = QMutableListIterator_QString_
class QStringMatcherPrivate(Structure):
    pass
class QStringMatcher(Structure):
    pass
class N14QStringMatcher5DOT_121E(Union):
    pass
class Data(Structure):
    pass
Data._fields_ = [
    ('q_skiptable', uchar * 256),
    ('uc', POINTER(QChar)),
    ('len', c_int),
]
N14QStringMatcher5DOT_121E._fields_ = [
    ('q_data', uint * 256),
    ('p', Data),
]
QStringMatcher._anonymous_ = ['_0']
QStringMatcher._fields_ = [
    ('d_ptr', POINTER(QStringMatcherPrivate)),
    ('q_pattern', QString),
    ('q_cs', CaseSensitivity),
    ('_0', N14QStringMatcher5DOT_121E),
]
QVectorData._fields_ = [
    ('ref', QBasicAtomicInt),
    ('alloc', c_int),
    ('size', c_int),
    ('sharable', uint, 1),
    ('capacity', uint, 1),
    ('reserved', uint, 30),
]
class QVectorTypedData_QPainterPath__Element_(Structure):
    pass
class QVector_QPainterPath__Element_(Structure):
    pass
class N7QVectorIN12QPainterPath7ElementEE5DOT_128E(Union):
    pass
N7QVectorIN12QPainterPath7ElementEE5DOT_128E._fields_ = [
    ('d', POINTER(QVectorData)),
    ('p', POINTER(QVectorTypedData_QPainterPath__Element_)),
]
QVector_QPainterPath__Element_._anonymous_ = ['_0']
QVector_QPainterPath__Element_._fields_ = [
    ('_0', N7QVectorIN12QPainterPath7ElementEE5DOT_128E),
]
class QVector_double_(Structure):
    pass
Data = QVectorTypedData_QPoint_
Data = QVectorTypedData_QPainterPath__Element_
Data = QVectorTypedData_QPointF_
Data = QVectorTypedData_QPair_doubleQColor__
iterator = POINTER(Element)
iterator = POINTER(QPoint)
iterator = POINTER(QPointF)
iterator = POINTER(QPair_doubleQColor_)
const_iterator = POINTER(Element)
const_iterator = POINTER(QPoint)
const_iterator = POINTER(QPair_doubleQColor_)
const_iterator = POINTER(QPointF)
value_type = Element
value_type = QPointF
value_type = QPoint
value_type = QPair_doubleQColor_
pointer = POINTER(QPoint)
pointer = POINTER(Element)
pointer = POINTER(QPointF)
pointer = POINTER(QPair_doubleQColor_)
const_pointer = POINTER(QPoint)
const_pointer = POINTER(Element)
const_pointer = POINTER(QPointF)
const_pointer = POINTER(QPair_doubleQColor_)
reference = POINTER(QPoint)
reference = POINTER(Element)
reference = POINTER(QPointF)
reference = POINTER(QPair_doubleQColor_)
const_reference = POINTER(QPoint)
const_reference = POINTER(Element)
const_reference = POINTER(QPointF)
const_reference = POINTER(QPair_doubleQColor_)
difference_type = qptrdiff
difference_type = qptrdiff
difference_type = qptrdiff
difference_type = qptrdiff
Iterator = POINTER(QPoint)
Iterator = POINTER(Element)
Iterator = POINTER(QPointF)
Iterator = POINTER(QPair_doubleQColor_)
ConstIterator = POINTER(QPoint)
ConstIterator = POINTER(Element)
ConstIterator = POINTER(QPointF)
ConstIterator = POINTER(QPair_doubleQColor_)
size_type = c_int
size_type = c_int
size_type = c_int
size_type = c_int
class QButtonGroup(Structure):
    pass
class QAbstractButtonPrivate(Structure):
    pass
class QAbstractButton(QWidget):
    pass
class QSessionManager(Structure):
    pass
class QDesktopWidget(Structure):
    pass
class QApplication(QCoreApplication):
    pass

# values for enumeration 'Type'
Tty = 0
GuiClient = 1
GuiServer = 2
Type = c_int # enum
QWidgetList = QList_QWidget*_
class QClipboard(Structure):
    pass

# values for enumeration 'UIEffect'
UI_General = 0
UI_AnimateMenu = 1
UI_FadeMenu = 2
UI_AnimateCombo = 3
UI_AnimateTooltip = 4
UI_FadeTooltip = 5
UI_AnimateToolBox = 6
UIEffect = c_int # enum
class QGraphicsWidget(Structure):
    pass
class QGraphicsItem(Structure):
    pass
class QGraphicsScene(Structure):
    pass
class QWidgetAnimator(Structure):
    pass
class QShortcut(Structure):
    pass
class QLineEdit(Structure):
    pass
class QTextControl(Structure):
    pass
class QFontDatabasePrivate(Structure):
    pass
class QBrushDataPointerDeleter(Structure):
    pass
class QRasterPaintEngine(Structure):
    pass
class QRasterPaintEnginePrivate(Structure):
    pass
class QSpanData(Structure):
    pass
DataPtr = QScopedPointer_QBrushDataQBrushDataPointerDeleter_
class QTypeInfo_QBrush_(Structure):
    pass
QBrushData._fields_ = [
    ('ref', QAtomicInt),
    ('style', BrushStyle),
    ('color', QColor),
    ('transform', QTransform),
]
class QGradientPrivate(Structure):
    pass
QGradientStop = QPair_doubleQColor_
class QLinearGradient(QGradient):
    pass
class QRadialGradient(QGradient):
    pass
class QConicalGradient(QGradient):
    pass
class QColormap(Structure):
    pass
class Q3TextFormatCollection(Structure):
    pass
class QFontDialogPrivate(Structure):
    pass
class QPainterPrivate(Structure):
    pass
class QPSPrintEngineFont(Structure):
    pass
class QTextLayout(Structure):
    pass
class QTextEngine(Structure):
    pass
class QStackTextEngine(Structure):
    pass
class QTextLine(Structure):
    pass
class QScriptLine(Structure):
    pass
class QGLContext(Structure):
    pass
class QWin32PaintEngine(Structure):
    pass
class QAlphaPaintEngine(Structure):
    pass
class QTextItemInt(Structure):
    pass
class QPicturePaintEngine(Structure):
    pass
class QPainterReplayer(Structure):
    pass
class QPaintBufferEngine(Structure):
    pass
class QCommandLinkButtonPrivate(Structure):
    pass
class QFontMetricsF(Structure):
    pass
QFontMetricsF._fields_ = [
    ('d', QExplicitlySharedDataPointer_QFontPrivate_),
]
class QIconEngine(Structure):
    pass
class QIconEngineV2(Structure):
    pass
DataPtr = POINTER(QIconPrivate)
class QTypeInfo_QIcon_(Structure):
    pass
class QImageDataMisc(Structure):
    pass
class QWSOnScreenSurface(Structure):
    pass
class QRasterPixmapData(Structure):
    pass
class QPixmapCacheEntry(Structure):
    pass
DataPtr = POINTER(QImageData)
class QTypeInfo_QImage_(Structure):
    pass
DataPtr = POINTER(QKeySequencePrivate)
class QTypeInfo_QKeySequence_(Structure):
    pass
class QTypeInfo_QMatrix_(Structure):
    pass
class QFontEngineMac(Structure):
    pass
class QX11PaintEngine(Structure):
    pass
class QPainterPathPrivateDeleter(Structure):
    pass
class QVectorPath(Structure):
    pass
QPainterPathPrivate._fields_ = [
    ('ref', QAtomicInt),
    ('elements', QVector_QPainterPath__Element_),
]
class QTypeInfo_QPainterPath__Element_(Structure):
    pass
class QPainterPathStroker(Structure):
    pass

# values for enumeration 'PenCapStyle'
FlatCap = 0
SquareCap = 16
RoundCap = 32
MPenCapStyle = 48
PenCapStyle = c_int # enum

# values for enumeration 'PenJoinStyle'
MiterJoin = 0
BevelJoin = 64
RoundJoin = 128
SvgMiterJoin = 256
MPenJoinStyle = 448
PenJoinStyle = c_int # enum

# values for enumeration 'PenStyle'
NoPen = 0
SolidLine = 1
DashLine = 2
DotLine = 3
DashDotLine = 4
DashDotDotLine = 5
CustomDashLine = 6
MPenStyle = 15
PenStyle = c_int # enum
QPainterPathStroker._fields_ = [
    ('d_ptr', QScopedPointer_QPainterPathStrokerPrivateQScopedPointerDeleter_QPainterPathStrokerPrivate__),
]
class QX11PixmapData(Structure):
    pass
class QMacPixmapData(Structure):
    pass
class QSymbianRasterPixmapData(Structure):
    pass
class QGLWidget(Structure):
    pass
class QCoreGraphicsPaintEngine(Structure):
    pass
class QRasterBuffer(Structure):
    pass
DataPtr = QExplicitlySharedDataPointer_QPixmapData_

# values for enumeration 'QtValidLicenseForGuiModule'
LicensedGui = 1
QtValidLicenseForGuiModule = c_int # enum
QtGuiModule = QtValidLicenseForGuiModule
class QPushButtonPrivate(Structure):
    pass
class QMenu(Structure):
    pass
class QStyleOptionButton(Structure):
    pass
class QPushButton(QAbstractButton):
    pass
class QRegionPrivate(Structure):
    pass
QRegionData._fields_ = [
    ('ref', QBasicAtomicInt),
    ('rgn', Region),
    ('xrectangles', c_void_p),
    ('qt_rgn', POINTER(QRegionPrivate)),
]
ControlTypes = QFlags_QSizePolicy__ControlType_
class QTypeInfo_QTransform_(Structure):
    pass
class QWSRegionManager(Structure):
    pass
class QHoverEvent(Structure):
    pass
QWidgetData._fields_ = [
    ('winid', WId),
    ('widget_attributes', uint),
    ('window_flags', WindowFlags),
    ('window_state', uint, 4),
    ('focus_policy', uint, 4),
    ('sizehint_forced', uint, 1),
    ('is_closing', uint, 1),
    ('in_show', uint, 1),
    ('in_set_window_state', uint, 1),
    ('fstrut_dirty', uint, 1),
    ('context_menu_policy', uint, 3),
    ('window_modality', uint, 2),
    ('in_destructor', uint, 1),
    ('unused', uint, 13),
    ('crect', QRect),
    ('pal', QPalette),
    ('fnt', QFont),
    ('wrect', QRect),
]
RenderFlags = QFlags_QWidget__RenderFlag_
class QBackingStoreDevice(Structure):
    pass
class QWidgetBackingStore(Structure):
    pass
class QBaseApplication(Structure):
    pass
class QWidgetItem(Structure):
    pass
class QWidgetItemV2(Structure):
    pass
class QGLWindowSurface(Structure):
    pass
class QShortcutPrivate(Structure):
    pass
class QGraphicsProxyWidgetPrivate(Structure):
    pass
class QStyleSheetStyle(Structure):
    pass
class QWidgetExceptionCleaner(Structure):
    pass
class QWinNativePanGestureRecognizer(Structure):
    pass
class QWidgetEffectSourcePrivate(Structure):
    pass
class QDialog(Structure):
    pass
class QPen(Structure):
    pass
class QMovie(Structure):
    pass
class QPicture(Structure):
    pass
class QPrinter(Structure):
    pass
class QTimer(Structure):
    pass
class QTime(Structure):
    pass
class _XDisplay(Structure):
    pass
Display = _XDisplay
class _XGC(Structure):
    pass
GC = POINTER(_XGC)
class QHash_longunsignedintQWidget*_(Structure):
    pass
QWidgetMapper = QHash_longunsignedintQWidget*_
QWidgetSet = QSet_QWidget*_
FILE = _IO_FILE
__FILE = _IO_FILE
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
ptrdiff_t = c_int
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
__all__ = ['QAbstractButton', 'cpu_set_t', '__int16_t',
           'Other_PrivateUse', 'WA_NoChildEventsForParent',
           'WA_AlwaysShowToolTips', 'yellow',
           'WA_X11NetWmWindowTypeUtility', '__off64_t',
           'LittleEndian', 'QSpanData', 'QGradientStops',
           'copyfmt_event', 'UnicodeVersion', 'UI_AnimateMenu',
           '__forced_unwind', 'InternalFunction', 'Preferred',
           'QPoint', 'CaseSensitive', 'ApplicationPaletteChange',
           'basic_istringstream_charstd__char_traits_char_std__allocator_char__',
           'digit', 'N14pthread_cond_t4DOT_18E', 'xdigit', 'WA_Hover',
           'DiffuseAlphaDither', 'QFlags_Qt__ItemFlag_',
           'WA_X11NetWmWindowTypeToolBar', 'UIEffect',
           'WidgetWithChildrenShortcut', 'Letter_Titlecase',
           'GestureFlag', 'WA_LayoutUsesWidgetRect', 'ReadPastEnd',
           '__to_type', 'event_callback', 'WA_ForceAcceptDrops',
           'SetQObjectSender', 'QList_QPoint_', 'ShortcutContext',
           'basic_stringbuf_charstd__char_traits_char_std__allocator_char__',
           'TextInteractionFlags', 'QIncompatibleFlag',
           'DefaultCodec', 'QMetaEnum', 'QList_QImageTextKeyLang_',
           'WA_PaintUnclipped', 'QWidgetPrivate', 'QSet_QWidget*_',
           'QPaintBufferEngine', 'SkipEmptyParts', 'QCoreApplication',
           'QStyleOptionButton', '__locale_data', 'SaveAs',
           'QByteArray', 'ctype_char_', 'QNoDebug',
           'QueryPropertyEditable', 'WA_ShowModal', 'pthread_t',
           'QMetaClassInfo', 'CaseInsensitive', 'const_reference',
           'fstream', 'WA_ContentsPropagated', 'UpdateRequest',
           'WaitForMoreEvents', '_S_in', 'MoveToPreviousWord',
           '__numeric_traits_integer_char_', 'LicensedCore',
           'GraphicsSceneMove', 'QSharedPointer_QBrush_',
           'allocator_QString_', 'AlignTrailing', '__equal_true_',
           'Text', 'AlignCenter', '_IO_FILE', 'WinIdChange',
           'wistream', 'PdmWidthMM', 'QLocale',
           'list_QStringstd__allocator_QString__',
           'WA_TouchPadAcceptSingleTouchEvents', 'off_t',
           'ApplicationWindowIconChange', 'SizeHorCursor',
           '__fsblkcnt_t', 'AllEvents', 'LastCursor', 'Wheel',
           'PopupFocusReason', 'Format',
           'basic_ostream_charstd__char_traits_char__',
           'PdmPhysicalDpiY', 'AlphaDither_Mask',
           'istreambuf_iterator_wchar_tstd__char_traits_wchar_t__',
           '__numeric_traits_shortint_', 'N14QStringMatcher5DOT_121E',
           'NoFontMerging', 'ProcessEventsFlags',
           'DockWidgetArea_Mask', 'QVector_QPointF_', 'PdmDepth',
           'ThresholdDither', 'QHash_longunsignedintQWidget*_', 'All',
           'QPainterPathStroker', '__u_int', 'HideToParent',
           '__iter_swap_true_', 'WA_WindowModified', 'green', 'GC',
           'QAbstractConcatenable', 'Hide', 'WindowActive',
           'Selected', 'QGraphicsScene', 'MoveToEndOfLine',
           'AA_S60DontConstructApplicationPanes', 'SizeAllCursor',
           '__is_char_char_', '__numeric_traits_floating_int_',
           'AlignLeft', 'Q3AccelManager',
           'NonClientAreaMouseButtonDblClick', 'blkcnt_t',
           'QScopedPointer_QObjectDataQScopedPointerDeleter_QObjectData__',
           'LinksAccessibleByMouse', 'Capitalize', 'TouchUpdate',
           'PatternSyntax', 'u_char', '_S_skipws', 'uid_t',
           'u_int64_t', 'u_int16_t', '__add_unsigned_int_',
           'QFlags_Qt__WindowType_', 'MacSizeChange',
           'QFlags_Qt__Orientation_', 'MoveToPreviousPage',
           'DragEnter', 'StatusTip',
           'num_put_wchar_tstd__ostreambuf_iterator_wchar_tstd__char_traits_wchar_t___',
           'WA_MacVariableSize', 'QRasterBuffer',
           'N11QMetaObject4DOT_51E', 'AA_DontUseNativeMenuBar',
           'TabletEnterProximity', 'MenuBarFocusReason',
           'QRasterPaintEnginePrivate', 'new_allocator_wchar_t_',
           'sigevent', 'QString', 'Type', 'WA_WState_Created',
           'div_t', '_Rep_base', 'QWidget', 'WA_Disabled', 'Super',
           'AltModifier', 'DirLRO', 'MSWindowsOwnDC', '__io_write_fn',
           'DirLRE', 'LeftToRight', 'N6QColor5DOT_1225DOT_123E',
           'Format_RGB32', 'ApplicationModal', 'nothrow_t',
           'ApplicationDeactivated', 'WA_ForceDisabled',
           'WA_WState_ConfigPending', 'messages', '__cache_type',
           'AlignJustify', 'IgnoreAspectRatio', 'QVector_QObject*_',
           'QTypeInfo_QLine_', '__add_unsigned_longint_',
           '__rlim64_t', 'ino_t', 'Alignment',
           '__is_floating_longdouble_',
           'WA_WState_AcceptedTouchBeginEvent', 'ElideMiddle',
           'difference_type', 'TxRotate', '__blksize_t',
           '__pthread_slist_t', 'LineEdit', 'OkRequest',
           'QDragLeaveEvent', 'Capitalization', 'NoGradient',
           'Format_RGB444', 'PenJoinStyle',
           '__remove_unsigned_unsignedchar_',
           'MSWindowsFixedSizeDialogHint', 'ino64_t',
           'QTypeInfo_shortunsignedint_',
           '__numeric_traits_floating_char_',
           'GraphicsSceneHoverMove', 'Format_RGB666',
           'basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__',
           '__normal_iterator_char*std__basic_string_charstd__char_traits_char_std__allocator_char___',
           'BigEndian', '__blkcnt64_t', 'ImhHiddenText',
           'QScopedPointerDeleter_QDataStreamPrivate_', 'quint8',
           'ToolTip', 'Inactive', 'QPicturePaintEngine',
           'ColorInterpolation', 'AA_MacPluginApplication',
           'SplashScreen', 'PreferMatch', 'Dense7Pattern',
           'QStringList', 'QRegExp', 'wios', '_S_dec',
           'QFlags_Qt__InputMethodHint_', '__rlim_t',
           '_S_ios_openmode_end', 'ImCursorPosition',
           'WA_DontCreateNativeAncestors', 'size_type',
           'QPainterPathStrokerPrivate', '__add_unsigned_signedchar_',
           'AlignTop', 'HoverEnter', 'UnknownKey', 'bad_alloc',
           'RefAdoptedThread', 'LastInternalFunction', 'QVariant',
           '_Callback_list', 'SpacingType', 'QWidgetBackingStore',
           'Button', 'input_iterator_tag', 'QHoverEvent',
           'Dense3Pattern', 'AbsoluteSpacing', 'ostream',
           'QImageReader', 'InputMethod', '_XRegion', 'WindowNoState',
           'streamoff', '__remove_unsigned_longunsignedint_',
           'WA_SymbianNoSystemRotation', '__key_t', 'dev_t',
           'QMetaMethod', 'RadialGradientPattern', 'OpenMode',
           'Dense5Pattern', 'Helvetica', '_5DOT_102',
           '_S_ios_seekdir_end', 'Rgb', 'ActionsContextMenu',
           'OpenModeFlag', 'QFlags_Qt__ToolBarArea_',
           'QFontDialogPrivate', 'QWidgetList', 'FT_FaceRec_',
           'QImageDataMisc', 'WA_SetLayoutDirection',
           'MouseButtonDblClick', 'QBrush', 'TransformationMode',
           'Format_Mono', '__is_integer_longint_',
           'WindowCloseButtonHint', 'KeepAspectRatio',
           'MoveToNextPage', 'Leave', 'color0',
           'QExplicitlySharedDataPointer_QPixmapData_', 'CopyAction',
           'QChar', 'QueryPropertyScriptable', 'Disabled',
           'pthread_once_t', 'collate_byname_char_', '__fsid_t',
           'MatchFlags', 'AcceptDropsChange', 'UniqueConnection',
           'reference', 'ButtonText', 'EmbeddingControl',
           'InsertLineSeparator',
           'QExplicitlySharedDataPointer_QFontPrivate_', 'PanGesture',
           'TouchPointState', 'Spec', 'ControlModifier',
           'NoIntersection', 'Tool', '_Alloc_hider', 'DropActions',
           '__pthread_unwind_buf_t', 'QCharRef', 'ShiftModifier',
           'CreateThreadForAdoption',
           'basic_fstream_charstd__char_traits_char__',
           '__streambuf_type', '__traits_type',
           'GraphicsSceneDragLeave', 'DirNSM',
           'basic_fstream_wchar_tstd__char_traits_wchar_t__',
           'SectionIncludeLeadingSep', 'QScopedPointerPodDeleter',
           'WindowBlocked', 'SectionCaseInsensitiveSeps', 'DirES',
           '_IO_FILE_plus', 'DirET', 'facet', '__gthread_t',
           'Dl_serinfo', 'QTypeInfo_longlongunsignedint_', 'DirEN',
           '__add_unsigned_wchar_t_', 'Letter_Other',
           'CurveToDataElement', 'darkGray', 'int32_t', 'Initial',
           'ForceOutline', 'ControlType', 'TxScale', 'NotOpen',
           'const_pointer', 'QShortcutMap', 'MoveAction',
           'QList_QObject*_', '__numpunct_cache_wchar_t_',
           'QTypeInfo_QMatrix_', 'Dialog', 'Cursive',
           'Punctuation_Dask', 'Punctuation_Dash', 'exception',
           '__suseconds_t', '__lexicographical_compare_true_',
           'ApplicationAttribute', 'WindowActivate', '_S_bin',
           'GrabKeyboard', 'QDataStream', 'SolidPattern', 'streampos',
           '__u_char', 'Format_ARGB4444_Premultiplied', 'RoundJoin',
           'QtDebugMsg', '_Bit_iterator', 'id', 'EnterWhatsThisMode',
           'u_short', 'PdmNumColors', 'WindowMaximized', 'HoverLeave',
           '_IO_marker', 'UpdateLater', '__is_integer_longlongint_',
           'MoveToPreviousChar', 'QVectorPath', 'ImFont', 'blue',
           'InvokeMetaMethod', 'DragMoveCursor', '_IO_lock_t',
           '__ctype_type', 'Decorative', '_Ios_Seekdir',
           '__is_floating_float_', '__numeric_traits_char_',
           'seekdir', 'MatchWildcard', 'ctype_byname_char_',
           'Midlight', 'LinkVisited', 'QMutableStringListIterator',
           'QFlag', 'WA_MacBrushedMetal', 'WA_AcceptTouchEvents',
           'QVector_QRect_', '__timer_t', '_S_eofbit', 'StyleNormal',
           '__uint32_t', 'GraphicsSceneDragEnter', 'QGLContext',
           'WA_MacMiniSize', 'QTypeInfo_QSizeF_', 'MinimumExpanding',
           'SelectPreviousChar', 'QGLWidget', 'FDiagPattern',
           'loff_t', '__is_integer_shortint_', 'SectionFlags',
           'blksize_t', 'QTypeInfo_QKeySequence_', 'RightToLeft',
           'GraphicsSceneHoverEnter',
           'basic_streambuf_wchar_tstd__char_traits_wchar_t__',
           'WA_MacSmallSize', 'GrabMouse', 'ApplicationShortcut',
           'ItemIsDropEnabled', 'Unbuffered',
           'iterator_traits_std___Bit_const_iterator_',
           'ActionRemoved', '__pthread_cleanup_frame',
           'ImhDialableCharactersOnly', 'ReadOnly',
           'basic_iostream_wchar_tstd__char_traits_wchar_t__',
           'iterator_std__random_access_iterator_tagboolintbool*bool&_',
           'bidirectional_iterator_tag', 'darkGreen', 'ZOrderChange',
           'QSharedPointer_QIcon_', 'System', 'WA_SetPalette',
           'Italic', 'ElideLeft', 'CustomizeWindowHint', '__id_t',
           'QTextLayout', 'MacGLClearDrawable', 'QueryWhatsThis',
           'QScopedPointer_QPainterPathStrokerPrivateQScopedPointerDeleter_QPainterPathStrokerPrivate__',
           '__numeric_traits_int_', 'QSharedPointer_constQWidget_',
           'WA_NativeWindow', 'CreateInstance', 'ConnectionType',
           'MatchFixedString', 'QBrushDataPointerDeleter',
           'QWSRegionManager', 'WA_MergeSoftkeys',
           'ApplicationActivated',
           'QScopedPointer_QDataStreamPrivateQScopedPointerDeleter_QDataStreamPrivate__',
           'QTypeInfo_QLineF_', 'SelectStartOfLine', 'PartialMatch',
           'ConstIterator', '_Ios_Iostate', 'Cut',
           'QTypeInfo_unsignedint_', 'DoublePrecision',
           'num_get_charstd__istreambuf_iterator_charstd__char_traits_char___',
           'EventLoopExec', 'allocator_wchar_t_', 'QTextControl',
           'CustomCursor', 'DragMove', 'QObjectUserData',
           'ReflectSpread', 'Lmid_t', '__false_type',
           'BottomToolBarArea', 'QAlphaPaintEngine', 'Format_RGB16',
           'MatchRegExp', 'WhatsThis', 'failure', 'NoItemFlags',
           'MaxUser', 'AlternateBase', 'QTypeInfo_QPoint_',
           'StyleItalic', 'ostringstream', 'WA_WindowPropagation',
           'QDataStreamPrivate', 'SelectStartOfDocument',
           'Unicode_1_1', 'StandardKey', 'AlignBottom', 'DataPtr',
           'Symbol_Math', 'TapAndHoldGesture', 'QLinearGradient',
           'NoTextInteraction', 'stringbuf', '__u_quad_t',
           '__u_short', 'XEvent',
           'N7QVectorI5QPairId6QColorEE5DOT_128E',
           'DefaultContextMenu', 'WA_DropSiteRegistered',
           'useconds_t', 'QIODevice', '__numpunct_cache_char_',
           '_Impl', 'NoFocusReason', 'CodecForTr',
           'GraphicsSceneMouseMove', 'iterator',
           '__conditional_type_true__gnu_cxx____numeric_traits_integer_char___gnu_cxx____numeric_traits_floating_char__',
           'QByteRef', 'SizeFDiagCursor', 'NoDockWidgetArea',
           'Letter_Modifier', 'CrossPattern', 'wifstream',
           'WindowCancelButtonHint', 'MatchEndsWith',
           '__copy_move_falsefalsestd__random_access_iterator_tag_',
           'Bold', 'SelectPreviousLine', 'graph', 'qInternalCallback',
           '__cpu_mask', '_G_int16_t', 'RequestSoftwareInputPanel',
           'MoveToEndOfBlock', 'rtld_global_ro', 'string',
           '__true_type',
           '__normal_iterator_constchar*std__basic_string_charstd__char_traits_char_std__allocator_char___',
           'SmallCaps', 'QInputContext', 'RemovePointer_QWidget*_',
           '__time_t', 'WA_WState_InPaintEvent', 'ButtonBox',
           'NoBrush', 'ModifiedChange', 'Unicode_2_0',
           '__gthread_mutex_t', 'fsfilcnt_t', 'ActionMask',
           'Canonical', 'upper', 'Number_Other', 'timespec',
           'GestureFlags',
           'istreambuf_iterator_charstd__char_traits_char__', 'Label',
           'pthread_mutex_t', 'OddEvenFill', 'QConicalGradient',
           'char_traits_wchar_t_', 'ItemIsUserCheckable',
           'DragResponse', 'DirPDF', 'va_list', 'OtherJoining',
           'TouchPointMoved', 'QtCleanUpFunction', 'LanguageChange',
           'Signed', '__u_long', 'InvertMode', 'WA_SetWindowIcon',
           'BDiagPattern', '_Rep', 'WA_PaintOutsidePaintEvent',
           'QStackTextEngine', 'QPainterPrivate', 'ItemIsTristate',
           'RelativeSize', 'QPaintEngine',
           'WA_X11NetWmWindowTypeSplash', '__off_t',
           'QStringListIterator', 'NoToolBarArea', 'WA_RightToLeft',
           'Node', 'QList_QKeySequence_', 'u_quad_t', 'QFontMetrics',
           'Letter_Uppercase', 'PreferDither', 'daddr_t', '_Bit_type',
           'MatchCaseSensitive', 'clock_t', 'TextInteractionFlag',
           'LicensedGui', '__int8_t', 'ctype', 'QList_void*_',
           'state_type', 'WA_MacNoClickThrough', 'QActionEvent',
           'RenderFlag', 'seek_dir', 'DirCS', 'imbue_event',
           'QSharedPointer_QPixmap_', 'pthread_key_t', 'FocusIn',
           '__locale_struct', 'u_int8_t', 'WheelFocus', 'QSize',
           'DockWidgetAreas', 'Mid', 'ObjectBoundingMode',
           'WA_StyledBackground', 'WindowType_Mask',
           'AA_MacDontSwapCtrlAndMeta', 'allocator_QObject*_',
           'ForbiddenCursor', '_S_beg', 'const_reverse_iterator',
           '__locale_t', 'SizeMode', 'OpenHandCursor',
           'ExcludeUserInputEvents', 'Orientations', 'Unicode_3_1',
           'list_QObject*std__allocator_QObject*__', 'AlignVCenter',
           'QVectorTypedData_QPainterPath__Element_',
           'WA_LockLandscapeOrientation', 'DirectConnection',
           '_Bit_reference', '__is_integer_char_',
           'QFlags_Qt__TouchPointState_', 'ptrdiff_t', 'QInternal',
           'WA_PendingUpdate', 'RadioButton', 'uint', 'QSizePolicy',
           'NColorRoles', 'money_base', 'Other_NotAssigned',
           'QFlags_Qt__ImageConversionFlag_', '__int_type',
           'IgnoreAction', 'Sheet', 'QEventPrivate', 'QLatin1Char',
           'MoveToNextLine', 'FILE', 'size_t', 'CustomDashLine',
           'pointer', 'Direction', 'HorPattern',
           '__conditional_type_true__gnu_cxx____numeric_traits_integer_int___gnu_cxx____numeric_traits_floating_int__',
           'WriteOnly', 'AccessibilityPrepare', 'Letter_Lowercase',
           '__FILE',
           'QScopedPointerDeleter_QPainterPathStrokerPrivate_',
           'wofstream', 'ContextMenuPolicy', 'Maximum', 'QSizeF',
           'cookie_write_function_t', 'QListData', 'WhatsThisClicked',
           'LeaveWhatsThisMode', 'ApplicationActivate', 'sigset_t',
           'ApplicationFontChange', 'MaskOutColor', 'Minimum',
           'DeactivateControl', 'qptrdiff', '__fd_mask',
           'QStringMatcherPrivate', 'QTime',
           '__uninitialized_fill_n_false_', 'Save',
           '__gthread_recursive_mutex_t', 'collate_char_',
           '__useconds_t', 'QPicture', 'space', 'QTabletEvent',
           'InvertRgba', 'TouchBegin',
           'basic_stringstream_charstd__char_traits_char_std__allocator_char__',
           'AvoidDither', 'collate', 'MPenCapStyle', 'MoveToElement',
           'SvgMiterJoin', 'DiffuseDither', 'u_int32_t',
           '__base_class_type_info_pseudo',
           '_IO_cookie_io_functions_t', 'Dense6Pattern',
           'ActionChanged',
           'iterator_std__output_iterator_tagvoidvoidvoidvoid_',
           'QueryPropertyStored', 'N9QGradient5DOT_1415DOT_143E',
           'ZoomOut', 'WindowType', 'IconTextChange', 'QFontInfo',
           'Format_ARGB32', 'QMatrix', 'Isolated',
           'ResetQObjectSender', 'QDragEnterEvent', 'RepeatSpread',
           '__numeric_traits_integer_longunsignedint_',
           '__pthread_cleanup_class', 'Vertical',
           'Punctuation_InitialQuote', '_S_oct',
           'WA_TintedBackground', 'comparison_fn_t', 'DirBN',
           'TapGesture', '_S_cur', 'RoundCap', 'white', 'MonoOnly',
           'Data', '__mbstate_t', 'QtWarningMsg', 'darkBlue',
           '_S_floatfield', 'QLatin1String', 'QLayout',
           'BlockingQueuedConnection', 'alnum',
           'num_put_charstd__ostreambuf_iterator_charstd__char_traits_char___',
           'QTypeInfo_float_', '_XDisplay', 'quad_t',
           'QFlags_Qt__MouseButton_', 'ItemIsDragEnabled',
           'QTextEngine', 'CurveToElement',
           'QTypeInfo_QPainterPath__Element_', 'numpunct_wchar_t_',
           'sched_param', 'SelectEndOfLine', 'SubWindow',
           'pthread_cond_t', 'QAction', 'MoveToStartOfDocument',
           'WA_DeleteOnClose', 'Call', 'MatchStartsWith',
           'QGenericReturnArgument', 'QFlags_Qt__KeyboardModifier_',
           '__istream_type', 'random_access_iterator_tag', 'nlink_t',
           'FloatingPointPrecision', 'ImhNoPredictiveText',
           'StyleOblique', 'LayoutRequest', 'ZoomIn',
           'CustomContextMenu', '__numeric_traits_integer_shortint_',
           'QPainter', 'Off', 'ulong', 'Drop',
           'QFlags_QSizePolicy__ControlType_', 'u_int',
           'WindowDeactivate', 'UpArrowCursor', '_S_adjustfield',
           '_S_out', '__remove_unsigned_longlongunsignedint_',
           'WA_CanHostQMdiSubWindowTitleBar', 'Dither_Mask',
           'fsblkcnt_t', 'NoRole', 'allocator_char_',
           'N16pthread_rwlock_t4DOT_21E', '__uint16_t', 'PenStyle',
           'qint64', 'NoMatch', 'const_iterator', '__swblk_t',
           'WA_TransparentForMouseEvents', 'ResetProperty',
           'DontStartGestureOnChildren', '__ostream_type',
           'DeleteStartOfWord', 'QFontEngineMac', 'TopDockWidgetArea',
           'black', 'ctype_base', 'AspectRatioMode', 'intptr_t',
           'WindowUnblocked', 'allocator_QPoint_',
           'QCommandLinkButtonPrivate', 'ClickFocus',
           'QStringMatcher', 'Other_Surrogate', 'ElementType',
           'Right', '__gthread_cond_t', 'ctype_byname_wchar_t_',
           'QTransform', 'SetCurrentThreadToMainThread',
           'ProcessEventsFlag', 'iostate', 'LastCallback',
           'QTypeInfo_QByteArray_', 'QPSPrintEngineFont',
           'ComponentInterpolation', 'Unsigned', 'Shortcut',
           '__gthread_time_t', 'Spread', 'wctrans_t', 'Fraction',
           'mbstate_t', 'SplitBehavior', 'NonModal',
           'ActiveWindowFocusReason', 'ldiv_t', 'QImageTextKeyLang',
           'NoFormatConversion',
           '__copy_move_backward_falsefalsestd__random_access_iterator_tag_',
           'QApplication', 'QFocusEvent', '__blkcnt_t', 'QVectorData',
           'DeferredDelete', 'AbsoluteSize', 'W3CXmlSchema11',
           'PdmWidth', 'Number_Letter', 'wostream',
           'Punctuation_Connector',
           'QFlags_QEventLoop__ProcessEventsFlag_',
           'allocator_QPainterPath__Element_',
           'codecvt_wchar_tchar__mbstate_t_', 'SinglePrecision',
           'Truncate', 'QGradient', 'QVector_QPair_doubleQColor__',
           'N5QListIP7QObjectE5DOT_111E', 'TextEditorInteraction',
           'MidButton', 'TouchEnd', 'N4wait3DOT_6E', 'WA_LaidOut',
           'Other_Format', 'WindowModal', 'QueryPropertyUser',
           'collate_byname_wchar_t_', 'Highlight',
           'QFlags_QWidget__RenderFlag_', '_S_app',
           'num_get_wchar_tstd__istreambuf_iterator_wchar_tstd__char_traits_wchar_t___',
           'QColormap', '__ctype_abstract_base_wchar_t_', 'Open',
           'ParentAboutToChange', 'DragCopyCursor',
           'numpunct_byname_char_', 'DirAN', 'DirAL',
           'AA_DontCreateNativeWidgetSiblings', 'QETWidget',
           '_S_trunc', 'FutureCallOut', 'QIconPrivate',
           'QShortcutPrivate', 'time_t', 'WindowFullScreen',
           'DeleteEndOfWord', 'WindowText', 'fsblkcnt64_t',
           'OtherFocusReason', 'InputMethodQuery',
           'ImhPreferLowercase', 'WA_StyleSheet', 'Resize',
           'OpenGLCompatible', 'QHideEvent', '__is_void_void_',
           'XAxis', 'NoBreak', 'WA_NoX11EventCompression',
           'CaseSensitivity', 'ImhEmailCharactersOnly',
           'SelectStartOfBlock', 'QListIterator_QString_', '__max',
           'Joining', 'ReadCorruptData', 'lldiv_t',
           'ImhPreferUppercase', 'QSharedDataPointer_QPixmap_',
           'WindowStaysOnTopHint', 'BrightText', 'MouseButtons',
           'ChildRemoved', '__num_get_type', 'DynamicPropertyChange',
           '_S_unitbuf', 'QRegExpPrivate', 'FileOpen', 'BusyCursor',
           'ios_base', '_S_goodbit', 'StateMachineSignal',
           'QFontDatabasePrivate', 'DrawChildren', 'QThread',
           'RightDockWidgetArea', 'Mark_SpacingCombining',
           'basic_ios_wchar_tstd__char_traits_wchar_t__',
           'QEventLoopPrivate', 'Dense2Pattern', 'QFont',
           'BitmapCursor', 'AlignAbsolute', 'TextBrowserInteraction',
           '_G_uint32_t', 'ImCurrentSelection', 'AlignmentFlag',
           'ifstream', 'Show', 'ImhUppercaseOnly', 'QMetaObject',
           '__nlink_t', 'QTypeInfo_unsignedchar_',
           'PercentageSpacing',
           'reverse_iterator___gnu_cxx____normal_iterator_constchar*std__basic_string_charstd__char_traits_char_std__allocator_char____',
           'SequenceFormat', 'XButton1', 'XButton2',
           'SelectPreviousPage', 'Destroy', 'WindowStateChange',
           'Punctuation_Open', 'cookie_io_functions_t',
           'allocator_void_', 'KeyboardModifierMask', 'int_type',
           'NColorGroups', 'Q3TextFormatCollection',
           'QIntegerForSizeof_void*_', 'N9QGradient5DOT_141E',
           'MouseButtonMask', 'ApplicationLayoutDirectionChange',
           'AccessibilityDescription', 'WA_OutsideWSRange',
           'ImAnchorPosition', 'WA_SetCursor', 'StateMachineWrapped',
           'basic_istream_wchar_tstd__char_traits_wchar_t__',
           'WindowSystemMenuHint', 'LinearGradientPattern',
           'QCoreApplicationPrivate', 'WA_AcceptDrops', 'obstack',
           'WA_InputMethodTransparent', 'Symbol_Modifier',
           'WA_WState_DND', 'QMargins', 'TouchPointStationary',
           'Paint', 'ParentChange', 'GraphicsSceneDrop',
           'N4wait3DOT_7E', 'new_allocator_char_', 'QVector_QPoint_',
           'QSysInfo',
           'reverse_iterator___gnu_cxx____normal_iterator_char*std__basic_string_charstd__char_traits_char_std__allocator_char____',
           'vector_QPointstd__allocator_QPoint__', 'TabFocus',
           'Ignored', '__caddr_t', 'QGraphicsItem',
           'MoveToEndOfDocument', 'ToolBarArea_Mask', '__io_seek_fn',
           'AA_ImmediateWidgetCreation', 'CursorShape',
           'WA_MacFrameworkScaled', 'Small', 'PdmDpiY', 'PdmDpiX',
           'SelectAll', 'unexpected_handler', 'MenubarUpdated',
           'WA_X11NetWmWindowTypeCombo', 'WA_PendingResizeEvent',
           'CaretWontMatch', 'DockWidgetArea', '_List_node_base',
           'Close', 'TouchPointStateMask', 'SelectNextLine',
           'GuiClient', 'WA_Moved', 'Monospace',
           'AA_S60DisablePartialScreenInputMode', 'WA_Resized',
           'Dark', 'Slider', '_S_showpos', 'WindowOkButtonHint',
           '__numeric_traits_longunsignedint_', 'Wide', '__pid_t',
           'time', 'Element',
           'basic_iostream_charstd__char_traits_char__',
           'ActionAdded', 'KeepEmptyParts', 'PreferDevice',
           'LinkAction', 'KeyPress', 'enum_type', 'mask',
           'QList_QSize_', 'PreventContextMenu', 'PinchGesture',
           'LinksAccessibleByKeyboard', 'QTypeInfo_QPointF_',
           'Unicode_5_0', 'QList_QAction*_', 'QCursorData', 'all',
           'istringstream', 'MoveToStartOfBlock',
           '__numeric_traits_integer_int_', 'AllDockWidgetAreas',
           'QTypeInfo_int_',
           'basic_ifstream_wchar_tstd__char_traits_wchar_t__',
           'MatchContains', 'WA_MacOpaqueSizeGrip', 'tm',
           '_S_basefield', 'QTypeInfo_bool_', 'PdmPhysicalDpiX',
           'reverse_iterator_std___Bit_iterator_', '_S_internal',
           'ImhLowercaseOnly', 'WA_PaintOnScreen', 'Refresh',
           'Format_MonoLSB', 'Desktop', 'AnyStyle',
           'AlignVertical_Mask', '__remove_unsigned_wchar_t_',
           'iterator_std__random_access_iterator_tagboolintconstbool*bool_',
           'PointingHandCursor', '_IO_jump_t', 'ImhDigitsOnly',
           '_Ios_Openmode', 'TxNone', 'WA_X11NetWmWindowTypeMenu',
           '__uint64_t', 'WA_MacShowFocusRect',
           'QTypeInfo_longdouble_', 'FocusPolicy', '__type', 'AddTab',
           'Circle', 'HelpRequest', '__remove_unsigned_bool_',
           '__clockid_t', 'numpunct_byname_wchar_t_',
           'basic_filebuf_wchar_tstd__char_traits_wchar_t__',
           'DragLeave', '__is_integer_unsignedchar_', 'EventFilter',
           'WA_WState_Visible', 'QVector_double_',
           'MacGLWindowChange', 'DragLinkCursor', 'Dl_info',
           'IBeamCursor', 'MetaCall', 'PreferAntialias',
           'WriteProperty', 'ToolTipBase',
           'QMutableListIterator_QString_', 'DrawWindowBackground',
           'N15pthread_mutex_t17__pthread_mutex_s4DOT_15E', 'Append',
           'Style', 'PreferQuality', 'QSharedPointer_QImage_',
           '__mode_t', 'iterator_traits_wchar_t*_',
           'ShortcutOverride', 'NoModifier', 'HighlightedText',
           'N7QVectorI7QPointFE5DOT_128E', 'MatchWrap',
           'SizeBDiagCursor', '__is_integer_longunsignedint_',
           'LocaleChange', 'MaskInColor', '_Ios_Fmtflags', 'cntrl',
           'none', 'MouseTrackingChange', 'pid_t', 'Expanding',
           'sentry', 'WA_MergeSoftkeysRecursively', '__fsfilcnt64_t',
           'SplitHCursor', 'QMovie', 'AllLowercase', 'ImhNone',
           'BevelJoin',
           'basic_ostream_wchar_tstd__char_traits_wchar_t__',
           '__io_read_fn', 'WA_MacNormalSize', 'WA_SetWindowModality',
           'QX11PaintEngine', 'QMouseEvent', 'magenta',
           'Other_Control', 'ColorMode_Mask', 'CaretMode',
           'AlignHCenter', 'QRadialGradient', 'QRegionPrivate',
           'X11BypassWindowManagerHint', '__c_locale',
           'wistringstream', 'Shadow', 'Region', 'QPrinter',
           'QIntegerForSize_1_', 'QCoreGraphicsPaintEngine',
           'QSharedDataPointer_QIcon_', 'lconv', 'UI_General',
           'KeyboardModifiers', 'SplitVCursor',
           '__normal_iterator_wchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t___',
           'DefaultType', '__pthread_internal_slist', 'qlonglong',
           'ThresholdAlphaDither', 'PenCapStyle', '_S_badbit',
           'Symbol_Other', '__clock_t', '__fsfilcnt_t', 'DirON',
           'Separator_Space', 'SquareCap', 'cyan', 'WinEventAct',
           'QtSystemMsg', 'QLineEdit', 'AlignLeading',
           'Unicode_2_1_2', 'QPushButtonPrivate', '__gthread_once_t',
           'QBackingStoreDevice', 'QWidgetAnimator',
           'NonClientAreaMouseButtonRelease',
           'QExplicitlySharedDataPointer_QPixmap_', 'fpos64_t',
           '__numeric_traits_floating_longunsignedint_',
           'QueryPropertyDesignable', '__truth_type_true_',
           'QVector_QPainterPath__Element_', 'QList_QByteArray_',
           'Paste', 'QAbstractButtonPrivate', 'BlankCursor',
           '__is_byte_signedchar_', 'ImhUrlCharactersOnly',
           'TextElideMode', 'FocusReason', 'off64_t',
           'QFlags_Qt__WindowState_', 'pthread_spinlock_t',
           'QBrushData', 'QContextMenuEvent',
           'WA_X11BypassTransientForHint', 'numeric',
           'SelectNextWord', '__ios_type', 'Format_Indexed8',
           'InsertParagraphSeparator', 'event',
           'WA_X11NetWmWindowTypePopupMenu', 'KeyboardLayoutChange',
           'ComboBox', 'ctype_wchar_t_', '__num_base',
           'TabFocusReason', 'ItemFlag', 'WA_NoSystemBackground',
           'FindPrevious', 'print', '__jmp_buf_tag', 'None',
           'FillRule', 'ios', '_pthread_cleanup_buffer',
           'TargetMoveAction', 'FlatCap', 'Delete', 'MatchFlag',
           'N6QColor5DOT_1225DOT_124E', 'QTypeInfo_QImage_',
           'wfilebuf', 'TextSelectableByMouse', 'QGradientPrivate',
           'ThreadChange', '__is_integer_unsignedint_', '_S_failbit',
           'QTypeInfo_QRegExp_', 'NoContextMenu',
           'NormalizationForm_D', 'NormalizationForm_C',
           '__remove_unsigned_char_', 'QRegion', 'TexturePattern',
           'Punctuation_FinalQuote', 'QImageWriter', 'Foreground',
           'Courier', 'QTypeInfo_QIcon_', 'QTypeInfo_QSize_',
           'WA_Mapped', 'qint16', 'output_iterator_tag',
           'WA_DontShowOnScreen', 'AA_X11InitThreads', 'HANDLE',
           'codecvt_charchar__mbstate_t_', 'QWidgetItem', 'Cmyk',
           'Callback', 'QTypeInfo_longint_', 'BacktabFocusReason',
           'quint16', 'ReceivePartialGestures', 'QWidgetData',
           'ReadProperty', 'QNoImplicitBoolCast',
           'WA_ShowWithoutActivating', 'QueuedConnection',
           'LayoutDirectionAuto', 'QIntegerForSize_2_',
           'QScopedPointer_QBrushDataQBrushDataPointerDeleter_',
           'KeyRelease', 'Current', 'Window', 'itimerspec',
           '__jmp_buf', 'ColorOnly', 'GestureOverride',
           'WA_MouseTracking', 'timeval', '__int64_t',
           'GraphicsSceneContextMenu', 'WA_GrabbedShortcut',
           'basic_ofstream_wchar_tstd__char_traits_wchar_t__',
           'StyleHint', 'ImhPreferNumbers', 'MouseButton', 'alpha',
           'FixedString', 'TabletLeaveProximity', 'RenderFlags',
           'SelectPreviousWord', '__is_byte_unsignedchar_',
           'WA_NoChildEventsFromChildren', 'WA_AutoOrientation',
           'qreal', 'QShowEvent', 'ApplicationDeactivate',
           'ItemIsSelectable',
           'N7QVectorIN12QPainterPath7ElementEE5DOT_128E',
           'NoDecomposition', 'DirS', 'DirR', 'QtMsgHandler',
           'WidgetAttribute', 'WindowIconChange', 'Punctuation_Close',
           'quint32', 'DirB', '__remove_unsigned_shortunsignedint_',
           'mode_t', 'Forward', 'WaitCursor', 'BottomDockWidgetArea',
           'PaletteChange', 'QDialog', 'Base', 'BrushStyle',
           'WA_NoMousePropagation', '__loff_t', '_S_showpoint',
           'QIconEngine', 'AA_AttributeCount', 'N5DOT_1025DOT_103E',
           'WindowTitleChange', 'cookie_seek_function_t',
           'QEventDispatcherUNIXPrivate', 'WindowMinimized',
           'QTypeInfo_QRect_', 'WA_MSWindowsUseDirect3D',
           'PreviousChild', 'allocator_QPair_doubleQColor__',
           'InputMethodHint', '_S_uppercase', 'SelectNextChar',
           'fd_mask', 'PreferBitmap', 'cookie_close_function_t',
           'ActivationChange', 'Create', '__wmask_type', 'TabWidget',
           'QGraphicsViewPrivate', 'N6QColor5DOT_1225DOT_125E',
           'QStyleSheetStyle', 'wostringstream', 'Hsl', 'Hsv',
           'QVectorTypedData_QPair_doubleQColor__',
           'SmoothTransformation', 'QPaintEvent',
           'basic_istringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__',
           'UpdateSoftKeys', 'MoveToNextChar', 'time_base',
           'QDynamicPropertyChangeEvent', 'value_type', 'streambuf',
           'QSharedPointer_QWidget_', '__intptr_t', 'QtFatalMsg',
           'QGraphicsWidget', 'GraphicsSceneResize',
           'WA_X11DoNotAcceptFocus', 'WA_UnderMouse', 'QPolygon',
           'EnabledChange', 'WA_X11NetWmWindowTypeDialog',
           '__lc_rai_std__random_access_iterator_tagstd__random_access_iterator_tag_',
           'X11ExcludeTimers', 'WA_WState_ExplicitShowHide', 'Compat',
           'AA_NativeWindows', 'CursorChange',
           'QExplicitlySharedDataPointer_QImage_', 'MaskMode',
           'QMetaProperty', 'N11__mbstate_t3DOT_2E',
           'NonClientAreaMouseButtonPress', 'Separator_Paragraph',
           'EventNotifyCallback', 'GraphicsSceneHelp',
           'WhatsThisCursor', 'QFlags_Qt__DropAction_',
           'UnboundedIntersection', 'InputMethodHints',
           'WindowModality', 'QShortcut', 'ZAxis', 'MatchExactly',
           'QPainterPathPrivate', 'rebind_char_', 'UI_AnimateToolBox',
           'BoundedIntersection', 'QtValidLicenseForGuiModule',
           'ControlTypes', 'QClipboard', 'ImhNoAutoUppercase',
           'QMenu', 'AA_MSWindowsUseDirect3DByDefault', 'u_long',
           'SelectEndOfDocument', 'allocator_type', 'QCloseEvent',
           'Format_RGB555', 'WindowSoftkeysVisibleHint', 'wstreampos',
           'basic_ifstream_charstd__char_traits_char__', 'Invalid',
           'QPalette', 'CloseSoftwareInputPanel', 'drand48_data',
           'quintptr', 'DeferredDeletion',
           'BypassGraphicsProxyWidget', 'PreferOutline', 'Dl_serpath',
           'Copy', 'WA_WState_Hidden', 'QtCriticalMsg',
           'MouseFocusReason', 'MetaModifier', 'QDesktopWidget',
           'MouseMove', 'UI_AnimateCombo', 'PdmHeightMM', 'open_mode',
           'lower', 'Drawer', 'AutoDither',
           'basic_ostringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__',
           'PreferDefault', 'suseconds_t',
           'N7QVectorI6QPointE5DOT_128E', '__is_integer_bool_',
           'QGraphicsProxyWidgetPrivate', 'QTextItemInt', 'fd_set',
           'On', 'QTypeInfo_double_', 'Ok', '_S_ate',
           'AlignHorizontal_Mask', 'TxShear',
           'iterator_traits_std___Bit_iterator_', 'register_t',
           'SectionSkipEmpty', 'QWindowSurface', 'ImplicitlyShared',
           '__is_floating_double_', 'Unicode_4_0', 'Unicode_4_1',
           'Font', 'KeypadModifier', 'WA_InputMethodEnabled',
           'QPainterPath',
           'basic_stringbuf_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__',
           'ItemIsEditable', 'darkMagenta', 'IconDrag', 'HoverMove',
           'socklen_t', 'QBitmap', 'QTimerEvent',
           'MacWindowToolBarButtonHint', 'QGraphicsView', 'PadSpread',
           '_S_ios_fmtflags_end', 'QInputMethodEvent', '_G_uint16_t',
           'Timer', 'Times', 'WildcardUnix',
           'QScopedPointerDeleter_QObjectData_', 'QLine',
           '__compar_fn_t', 'ExternalRefCountWithDestroyFn',
           'QPainterPathPrivateDeleter', 'GraphicsSceneWheel',
           'Gesture', 'allocator_QPointF_', 'N6QColor5DOT_122E',
           'Square', 'QFlags_Qt__TextInteractionFlag_',
           'QSet_QObject*_', 'darkRed', 'GroupBox', 'Unicode_3_0',
           'Unicode_3_2', 'QFontMetricsF', 'SectionFlag',
           '_Raw_bytes_alloc', 'QButtonGroup', 'AccessibilityHelp',
           'wint_t', 'CustomGesture', 'Speech', 'DeleteEndOfLine',
           'PdmHeight', 'InvertRgb', 'ShortcutFocusReason', 'Normal',
           'RegExp2', '__add_unsigned_longlongint_',
           'RightToolBarArea', 'CaretAtZero', 'User',
           '_IO_cookie_file', 'QChildEvent', 'wiostream',
           'wstringbuf', 'TxProject', 'SwipeGesture', 'ElideNone',
           'WA_KeyboardFocusChange', 'QWidgetMapper', 'int8_t',
           'OldEnglish', 'Wildcard', '_Destroy_aux_true_', 'gid_t',
           'N6QColor5DOT_1225DOT_126E', 'AdoptCurrentThread',
           'WA_WState_CompressKeys', 'QIcon',
           'cookie_read_function_t', 'ToolBarAreas', 'blkcnt64_t',
           'WA_LayoutOnEntireRect', 'wfstream', 'DialogExec',
           'messages_base', 'off_type', 'LogicalMode', 'RightButton',
           'QObject', 'Background', 'qint32', 'UI_AnimateTooltip',
           'PixmapType', 'iterator_category', '_S_left', 'MPenStyle',
           'Medial', 'CoordinateMode', 'UI_FadeTooltip',
           'Format_ARGB8565_Premultiplied', '__sched_param',
           'QSharedDataPointer_QBrush_', '__socklen_t',
           'WA_WState_Polished',
           '__normal_iterator_constwchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t___',
           'KeyboardModifier', 'ChildPolished', '__pthread_mutex_s',
           '__is_byte_char_', 'FocusOut', 'WA_NoBackground',
           'QTypeInfo_signedchar_', 'WFlags', 'ExplicitlyShared',
           'QIntegerForSize_4_', 'QThreadData',
           'ConicalGradientPattern', 'QX11Info', 'fpos_t',
           'WA_X11NetWmWindowTypeDropDownMenu', 'QTimer', 'istream',
           'ConnectCallback', 'QMacPixmapData', 'char_type',
           'WA_SetLocale', 'QStyle', 'QFlags_Qt__MatchFlag_',
           'MouseButtonRelease', 'DiagCrossPattern', 'qulonglong',
           'Fixed', 'QSet_QString_', '_Atomic_word',
           'PaintDeviceMetric', 'TxTranslate',
           'WA_MacAlwaysShowToolWindow', 'WA_SetStyle',
           'WA_MacMetalStyle', 'QBaseApplication',
           'WA_TranslucentBackground',
           'iterator_std__random_access_iterator_tagboolintstd___Bit_reference*std___Bit_reference_',
           'GetQObjectSender', 'State', 'Decomposition',
           'SequenceMatch', 'KeepAspectRatioByExpanding',
           'ConicalGradient', 'WindowMaximizeButtonHint',
           'NativeGesture', 'DestroyerFn', 'LayoutDirection',
           'TransformationType', 'StretchToDeviceMode', 'Link',
           'id_t', 'Line', 'DirL', '_G_fpos_t', '_S_hex', 'Light',
           'SpinBox', 'WindowFlags', 'punct', 'TabletRelease',
           'AlignRight', 'MoveToPreviousLine', 'ActivateControl',
           'Tty', 'ShareMode', 'Back', 'ExactMatch', 'Null', 'QImage',
           'QMetaObjectExtraData', 'Category', 'NoPen',
           'QPixmapCacheEntry', 'InterpolationMode', 'MoveToNextWord',
           '_Destroy_aux_false_',
           'ostreambuf_iterator_wchar_tstd__char_traits_wchar_t__',
           '__is_integer_int_', 'Status', 'fsid_t', 'pos_type',
           'rebind_wchar_t_', 'QGenericArgument', 'fsfilcnt64_t',
           'QEventLoop', '_S_fixed', 'Format_ARGB8555_Premultiplied',
           'fmtflags', 'Format_ARGB32_Premultiplied',
           '__fsblkcnt64_t', 'QPen', 'LineToElement', 'QScriptLine',
           'QFlags_Qt__GestureFlag_', 'QTypeInfo_QMargins_',
           'WindowState', 'QWidgetExceptionCleaner', 'ReadWrite',
           'timer_t', 'Frame', 'TouchPointPressed',
           'TouchPointPrimary', 'WA_KeyCompression', '__digits',
           'QVector_QString_', 'Policy', 'MiterJoin',
           'RemovePointer_constQWidget*_',
           'N9QGradient5DOT_1415DOT_142E', 'reverse_iterator',
           'QColor', 'uchar', '__add_unsigned_shortint_',
           'reverse_iterator_std___Bit_const_iterator_',
           'LastGestureType', 'QPostEventList', 'fpos___mbstate_t_',
           'QKeySequence', 'key_t', 'ByteOrder', 'color1', 'QRect',
           'QSessionManager', 'QKeySequencePrivate', 'QRgb',
           'wctype_t', 'Punctuation_Other', 'ssize_t',
           'DitherMode_Mask', 'ItemIsEnabled', 'ShowWindowRequest',
           'QPixmapData', '_XEvent',
           'reverse_iterator___gnu_cxx____normal_iterator_wchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t____',
           'ofstream', 'Final', 'iterator_type',
           'GraphicsSceneMouseRelease',
           'basic_ostringstream_charstd__char_traits_char_std__allocator_char__',
           'Display', 'ImhFormattedNumbersOnly', 'DashLine',
           'TouchPointStates',
           'basic_istream_charstd__char_traits_char__',
           'ostreambuf_iterator_charstd__char_traits_char__',
           'WindowSoftkeysRespondHint', 'QList_QPointF_',
           'transparent', 'QFlags_Qt__AlignmentFlag_',
           'WA_WState_Reparented', 'WA_ForceUpdatesDisabled',
           'Iterator', 'WindowShadeButtonHint', '__type_info_pseudo',
           'QCursor', 'traits_type', '__int32_t',
           'QVectorTypedData_QPoint_', 'SectionIncludeTrailingSep',
           'QPixmap', 'ToolTipText', 'WA_X11NetWmWindowTypeDesktop',
           '__conditional_type_true__gnu_cxx____numeric_traits_integer_shortint___gnu_cxx____numeric_traits_floating_shortint__',
           'Preferences', 'WA_NoMouseReplay',
           'TextSelectableByKeyboard', 'stringstream',
           'QWin32PaintEngine', '__num_put_type', 'Print',
           '__uninitialized_fill_true_', 'AutoColor', '_S_scientific',
           'category', 'collate_wchar_t_', 'ContentsRectChange',
           'BitmapType', 'GraphicsSceneMousePress', 'QPushButton',
           'VerPattern', 'red', '__numeric_traits_floating_shortint_',
           'PolishRequest', 'iostream', 'QObjectData',
           'N5QListI7QStringE5DOT_111E', 'forward_iterator_tag',
           '__gnuc_va_list', 'QSharedDataPointer_QImage_', 'QEvent',
           'NImageFormats', 'StrongFocus',
           'Format_ARGB6666_Premultiplied', 'RestrictedBool',
           'ToolTipChange', 'TopToolBarArea', 'MixedCase',
           'WA_X11NetWmWindowTypeToolTip', 'ExcludeSocketNotifiers',
           'streamsize', 'rtld_global', 'QIconEngineV2', 'RegExp',
           'QFontPrivate', 'Format_RGB888', 'locale', 'QAtomicInt',
           '__is_integer_signedchar_', 'lightGray', '__uint8_t',
           'qint8', 'WA_X11NetWmWindowTypeNotification', 'QPolygonF',
           'basic_filebuf_charstd__char_traits_char__',
           'WA_MouseNoMask', 'QPalettePrivate', 'UngrabKeyboard',
           'UnicodeUTF8', 'LayoutDirectionChange', '__sig_atomic_t',
           '_XGC', 'WA_AttributeCount', 'GlobalColor',
           'QList_QPolygonF_',
           'vector_QPainterPath__Elementstd__allocator_QPainterPath__Element__',
           'IgnoreMask', 'Orientation', 'ContextMenu',
           'WA_LockPortraitOrientation', 'ZeroTimerEvent',
           'QStringRef', '__uninitialized_copy_true_',
           'QTypeInfo_QTransform_', 'Redo', 'WA_GroupLeader',
           'DirRLO', 'QWheelEvent', 'LeftDockWidgetArea',
           'ToolBarArea', 'DirRLE', 'string_type',
           'WindowMinimizeButtonHint', 'WindowStates',
           'ImMaximumTextLength', 'QTextLine', 'DotLine', 'ColorRole',
           'filebuf', 'QTypeInfo_QBrush_', 'QPair_doubleQColor_',
           '__vmi_class_type_info_pseudo2',
           '__vmi_class_type_info_pseudo1', 'MatchRecursive',
           'wstreambuf', 'QList_QPainterPath__Element_', 'Mode',
           'DropAction', 'ImhExclusiveInputMask', '_S_end',
           'QGraphicsEffect', 'Dense1Pattern', '__quad_t',
           'Unicode_Unassigned', '__uid_t',
           'reverse_iterator___gnu_cxx____normal_iterator_constwchar_t*std__basic_string_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t____',
           'GraphicsSceneHoverLeave', 'codecvt_base',
           'LinearGradient', 'ImageConversionFlag',
           'QTypeInfo_shortint_', 'MouseButtonPress', 'YAxis',
           'NonClientAreaMouseMove', 'Undo', 'char_traits_char_',
           'QPaintDevice', 'Serif', 'WindowMinMaxButtonsHint',
           'QDragMoveEvent', 'HelpContents', 'FramelessWindowHint',
           'NoButton', 'ImMicroFocus',
           '__is_integer_shortunsignedint_', 'DirWS', 'Narrow',
           '_S_showbase', 'Find', 'gray', 'WA_X11NetWmWindowTypeDND',
           'QWidgetSet', 'New', 'Move',
           'basic_streambuf_charstd__char_traits_char__',
           'ChildAdded', 'WindowStaysOnBottomHint', 'QStdWString',
           'WA_WState_WindowOpacitySet', 'QTypeInfo_longlongint_',
           'TextEditable', '__ssize_t',
           'vector_QPair_doubleQColor_std__allocator_QPair_doubleQColor___',
           'ItemFlags',
           'QScopedPointer_QPainterPathPrivateQPainterPathPrivateDeleter_',
           'Separator_Line', 'int16_t', 'WA_OpaquePaintEvent',
           'QTypeInfo_QRectF_', 'AutoCompatConnection',
           'GraphicsSceneDragMove', '__remove_unsigned_unsignedint_',
           'QObjectPrivate', '__sigset_t', 'StyleStrategy', 'Popup',
           'QWSOnScreenSurface', 'QTypeInfo_QChar_', 'TabletPress',
           'QObjectList', 'darkYellow', 'Number_DecimalDigit',
           'Format_Invalid', 'QApplicationPrivate', 'Widget',
           'FindNext', 'QSymbianRasterPixmapData', 'CaretAtOffset',
           'WindingFill', 'QX11PixmapData', 'ArrowCursor',
           'erase_event', 'QList_QWidget*_', 'ColorGroup',
           'QFlags_QIODevice__OpenModeFlag_', 'IntersectType',
           'ushort', 'clockid_t', 'caddr_t', 'QPointF', 'Axis',
           '_S_boolalpha',
           'basic_stringstream_wchar_tstd__char_traits_wchar_t_std__allocator_wchar_t__',
           'ElideRight', 'QBasicAtomicInt', 'NetworkReplyUpdated',
           'GroupSwitchModifier', 'Enter', 'SelectEndOfBlock',
           'ToolButton', '__compar_d_fn_t', 'WA_StaticContents',
           'QVectorTypedData_QPointF_',
           'basic_ios_charstd__char_traits_char__',
           '_CharT_alloc_type', 'Active', 'Horizontal',
           'QGLWindowSurface', 'SolidLine', 'QGradientStop',
           'SelectNextPage', 'QtGuiModule', 'WidgetShortcut',
           'Center', 'QWinNativePanGestureRecognizer',
           'QClassFactory', 'WA_WState_OwnSizePolicy', '__dev_t',
           '__qaddr_t', 'MiddleButton', 'QRegionData', 'QtMsgType',
           'AllUppercase', 'MoveToStartOfLine', 'QIntegerForSize_8_',
           'TypeWriter', '__add_unsigned_char_',
           'QWidgetEffectSourcePrivate', 'SockAct', 'Init',
           'MPenJoinStyle', 'terminate_handler', '_Words',
           'SizeVerCursor', '_S_ios_iostate_end', 'PortableText',
           'vector_QPointFstd__allocator_QPointF__', 'Mark_Enclosing',
           'QExplicitlySharedDataPointer_QKeySequence_', 'NoAlpha',
           'LeftToolBarArea', '__ino_t', 'ClosedHandCursor',
           'iter_type', 'Symbol_Currency', 'UI_FadeMenu',
           'bad_exception', 'Fantasy', 'GestureType',
           'AA_DontShowIconsInMenus', 'DashDotDotLine',
           'WA_CustomWhatsThis', 'WA_SetFont',
           'GraphicsSceneMouseDoubleClick', 'new_handler',
           'LeftButton', 'NormalizationForm', 'QTranslator',
           'QSharedData', '__is_integer_longlongunsignedint_',
           'random_data', 'FontChange',
           'N9QGradient5DOT_1415DOT_144E',
           'IgnoredGesturesPropagateToParent',
           '__uninitialized_fill_false_', 'ForceIntegerMetrics',
           'DashDotLine', 'WindowTitleHint', '__ino64_t',
           'QPainterPathData', 'OrderedAlphaDither',
           'QList_QPair_doubleQColor__', 'darkCyan', 'QDropEvent',
           'WA_QuitOnClose', 'Dense4Pattern', 'wstring',
           'QTypeInfo_longunsignedint_', 'AllToolBarAreas',
           'TabletMove', 'Encoding', '_G_fpos64_t', 'NoCategory',
           'QMetaObjectAccessor', 'Polish', 'QImageData', 'Quit',
           'CheckBox', 'QRasterPixmapData', 'Sub', '__io_close_fn',
           'WA_X11NetWmWindowTypeDock', 'PushButton', 'Clipboard',
           'WA_UpdatesDisabled', 'UngrabMouse',
           'QFlags_Qt__DockWidgetArea_', 'ExternalRefCountData',
           'QWidgetItemV2', 'DerefAdoptedThread',
           'QVector_unsignedint_', '__gthread_key_t',
           'WA_InvalidSize', 'CrossCursor', 'OrderedDither',
           'WA_PendingMoveEvent', 'monetary', 'numpunct_char_',
           '__add_unsigned_bool_', 'WindowShortcut', 'RadialGradient',
           'QList_QString_', 'Replace', 'Zero', 'FastTransformation',
           'openmode', 'NoFocus', '__uninitialized_copy_false_',
           'FT_Face', 'QSharedDataPointer_QKeySequence_',
           'QFlags_QString__SectionFlag_', 'StyleChange',
           'Mark_NonSpacing', 'QDebug', 'NoOpaqueDetection',
           '__gid_t', 'io_state', 'ImageConversionFlags',
           '__conditional_type_true__gnu_cxx____numeric_traits_integer_longunsignedint___gnu_cxx____numeric_traits_floating_longunsignedint__',
           '__is_integer_wchar_t_', 'NativeText',
           'QGraphicsScenePrivate', '__daddr_t', 'QKeyEvent',
           'SectionDefault', 'QRectF', 'WId', 'ShowToParent',
           'NormalizationForm_KC',
           '__conditional_type_truelongunsignedintlonglongunsignedint_',
           'NormalizationForm_KD', 'QIODevicePrivate', 'GuiServer',
           'QtCoreModule', 'locale_t', 'WA_X11OpenGLOverlay',
           'ImSurroundingText',
           'QExplicitlySharedDataPointer_QBrush_',
           '_Bit_iterator_base', 'QTypeInfo_char_',
           'WindowContextHelpButtonHint', 'NoAntialias',
           'QGraphicsProxyWidget', 'QBool', 'QLineF', 'NextChild',
           'QTextCodec',
           'basic_string_charstd__char_traits_char_std__allocator_char__',
           'ToolBarChange', 'int64_t', 'QMoveEvent',
           'TouchPointReleased',
           'basic_ofstream_charstd__char_traits_char__',
           'QPainterReplayer', 'DisconnectCallback',
           'QRasterPaintEngine', '_S_right', 'other', 'quint64',
           'wstringstream', 'QSharedPointer_QKeySequence_',
           '__uninitialized_fill_n_true_', 'SansSerif',
           'QtValidLicenseForCoreModule', '_Bit_const_iterator',
           'QExplicitlySharedDataPointer_QIcon_', '__min',
           'QGestureManager', 'QResizeEvent', 'QTypeInfo_QString_',
           'AutoConnection', 'Private', '__is_char_wchar_t_', 'Dual',
           '_G_int32_t', 'Underline']
