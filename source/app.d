import std.stdio;
import std.range;
import std.algorithm;
import std.system;
import std.datetime;
import std.traits;
import std.typecons;

template debug_write(T){
	import std.meta;
	alias field_names = FieldNameTuple!T;
	enum typename = fullyQualifiedName!T;

	template to_tuple(string name){
		import std.meta;
		import std.format;
		alias to_tuple = AliasSeq!(
				mixin(format("%s.%s.offsetof",typename,name)),
				mixin(format("%s.%s.sizeof",typename,name)),
				mixin(format("(%s self) => self.%s",typename,name)));
	}

	template get_len(string name){
		alias get_len = AliasSeq!(name.length);
	}

	auto debug_write(T val){
		auto name_len = max(staticMap!(get_len,field_names));
		writefln("| %*s | Offset | Size |    Value |",name_len,"Field");
		foreach(name;field_names){
			auto tuple = to_tuple!name;
			writefln("| %*s | %6x | %4x | %8x |",name_len,name,tuple[0],tuple[1],tuple[2](val));
		}
	}
}

align(1)
struct PEFileHeader{
	ushort machine;
	ushort number_of_sections;
	uint timestamp;
	uint pointer_to_symbol_table;
	uint number_of_symbols;
	ushort optional_header_size;
	ushort characteristics;
}

align(1)
struct PEOptionalHeader{
	//standard fields
	align(1)
	struct StandardFields{
		ushort magic;
		ubyte lmajor;
		ubyte lminor;
		uint code_size;
		uint initialized_data_size;
		uint uninitialized_data_size;
		uint entry_point_rva;
		uint base_of_code;
		uint base_of_data;
	}
	//Windows NT-specific fields
	align(1)
	struct NT_SpecificFields{
		uint image_base;
		uint section_alignment;
		uint file_alignment;
		ushort os_major;
		ushort os_minor;
		ushort user_major;
		ushort user_minor;
		ushort subsys_major;
		ushort subsys_minor;
		uint reserved;
		uint image_size;
		uint header_size;
		uint file_checksum;
		ushort subsystem;
		ushort dll_flags;
		uint stack_reserve_size;
		uint stack_commit_size;
		uint heap_reserve_size;
		uint heap_commit_size;
		uint loader_flags;
		uint number_of_data_directories;
	}
	//data directories
	align(1)
	struct DataDirectories{
		ulong export_table;
		ulong import_table;
		ulong resource_table;
		ulong exception_table;
		ulong certificate_table;
		ulong base_relocation_table;
		//conflict with D's debug keyword
		ulong _debug;
		ulong copyright;
		ulong global_ptr;
		ulong tls_table;
		ulong load_config_table;
		ulong bound_import;
		ulong iat;
		ulong delay_import_descriptor;
		ulong cli_header;
		ulong reserved;
	}
	StandardFields standard_fields;
	NT_SpecificFields nt_specific_fields;
	DataDirectories data_directories;
}

template read_impl(T,R){
	static if(isInputRange!R && is(ElementType!R == ubyte)){
		static if(isScalarType!T){
			auto read_impl(ref R range,Endian endian = Endian.littleEndian){
				struct Arena{
					union{
						ubyte[T.sizeof] buffer;
						T value;
					}
				}
				Arena arena;
				if(endian == std.system.endian){
					for(size_t i = 0;i < T.sizeof;i++){
						arena.buffer[i] = range.front;
						range.popFront();
					}
				}
				else{
					for(size_t i = 1;i <= T.sizeof;i++){
						arena.buffer[$-i] = range.front;
						range.popFront();
					}
				}
				return arena.value;
			}
		}
		else static if(isAggregateType!T){
			auto read_impl(ref R range,Endian endian = Endian.littleEndian){
				T ret = void;
				//suppose no padding
				//suppose tuple is sorted by offset
				foreach(string name;FieldNameTuple!T){
					enum member = "ret." ~ name;
					mixin(member) = range.read!(typeof(mixin(member)))(endian);
				}
				return ret;
			}
		}
	}
}
auto read(T,R)(ref R range,Endian endian = Endian.littleEndian){
	return read_impl!(T,R)(range,endian);
}

auto readSome(T,R)(ref R range,size_t count,Endian endian = Endian.littleEndian){
	return generate!(() => read!T(range,endian)).take(count).array;
}

struct Assembly{
	this(R)(R range)
	if (isInputRange!R && is(ElementType!R == ubyte)){
		//Read PE header
		//Read MS-DOS header in PE header
		//"MZ"
		assert(range.readSome!ubyte(2) == [0x4d,0x5a]);

		//pop until 0x3c(where lfanew, offset to PE signature from the beginning of file)
		range.popFrontN(0x3c - 2);
		auto lfanew = range.read!uint; 
		
		//Skip until PE signature
		//MS-DOS header shall have exactly 128 bytes so PE signature must be placed 128 byte after the beginning
		assert(lfanew >= 128);
		range.popFrontN(lfanew - 4 - 0x3c);

		//PE signature
		//PE signature must be "PE\0\0"
		assert(range.readSome!ubyte(4) == [0x50,0x45,0,0]);

		//Read PE file header in PE header
		/*PE_file_header pe_file_header = void;
		pe_file_header.machine = range.read!ushort;
		pe_file_header.number_of_sections = range.read!ushort;
		pe_file_header.timestamp = range.read!uint;
		pe_file_header.pointer_to_symbol_table = range.read!uint;
		pe_file_header.number_of_symbols = range.read!uint;
		pe_file_header.optional_header_size = range.read!ushort;
		pe_file_header.characteristics = range.read!ushort;*/
		//This may fail in another endian environment
		auto pe_file_header = range.read!PEFileHeader;
		assert(pe_file_header.machine == 0x14c);
		assert(pe_file_header.pointer_to_symbol_table == 0);
		assert(pe_file_header.number_of_symbols == 0);
		writefln("sections : %d\ntime : %s\nheader size : %d\ncharacteristics : %d",
				pe_file_header.number_of_sections,
				SysTime.fromUnixTime(pe_file_header.timestamp).toSimpleString,
				pe_file_header.optional_header_size,
				pe_file_header.characteristics);

		auto pe_optional_header = range.read!PEOptionalHeader;
		assert(pe_optional_header.standard_fields.sizeof == 28);
		assert(pe_optional_header.nt_specific_fields.sizeof == 68);
		assert(pe_optional_header.data_directories.sizeof == 128);
		assert(pe_optional_header.sizeof == 28 + 68 + 128);

		//PE header standard fields assertion
		pe_optional_header.standard_fields.debug_write();
		assert(pe_optional_header.standard_fields.magic == 0x10B);
		//linker major of my DLL generated by VC# doesn't match 
		//assert(pe_optional_header.standard_fields.lmajor == 6);
		assert(pe_optional_header.standard_fields.lminor == 0);
		
		//PE header windows NT-specific fields assertion
		assert(pe_optional_header.nt_specific_fields.image_base % 0x10000 == 0);
		assert(pe_optional_header.nt_specific_fields.section_alignment > pe_optional_header.nt_specific_fields.file_alignment);
		assert(pe_optional_header.nt_specific_fields.file_alignment == 0x200);
		//OS major of my DLL generated by VC# doesn't match 
		//assert(pe_optional_header.nt_specific_fields.os_major == 5);
		assert(pe_optional_header.nt_specific_fields.os_minor == 0);
		assert(pe_optional_header.nt_specific_fields.user_major == 0);
		assert(pe_optional_header.nt_specific_fields.user_minor == 0);
		//subsystem major of my DLL generated by VC# doesn't match 
		//assert(pe_optional_header.nt_specific_fields.subsys_major == 5);
		assert(pe_optional_header.nt_specific_fields.subsys_minor == 0);
		assert(pe_optional_header.nt_specific_fields.reserved == 0);
		assert(pe_optional_header.nt_specific_fields.image_size % pe_optional_header.nt_specific_fields.section_alignment == 0);
		assert(pe_optional_header.nt_specific_fields.header_size % pe_optional_header.nt_specific_fields.file_alignment == 0);
		assert(pe_optional_header.nt_specific_fields.file_checksum == 0);
		assert(pe_optional_header.nt_specific_fields.subsystem == 0x3 //IMAGE_SUBSYSTEM_WINDOWS_CUI
			   || pe_optional_header.nt_specific_fields.subsystem == 0x2); //IMAGE_SUBSYSTEM_WINDOWS_GUI
		assert((pe_optional_header.nt_specific_fields.dll_flags & 0x100f) == 0);
		assert(pe_optional_header.nt_specific_fields.stack_reserve_size == 0x100000);
		assert(pe_optional_header.nt_specific_fields.stack_commit_size == 0x1000);
		assert(pe_optional_header.nt_specific_fields.heap_reserve_size == 0x100000);
		assert(pe_optional_header.nt_specific_fields.heap_commit_size == 0x1000);
		assert(pe_optional_header.nt_specific_fields.loader_flags == 0);
		assert(pe_optional_header.nt_specific_fields.number_of_data_directories == 0x10);

		//PE header data directories assertion
		assert(pe_optional_header.data_directories.export_table == 0);
		//My dll dont follow this assertion
		//assert(pe_optional_header.data_directories.resource_table == 0);
		assert(pe_optional_header.data_directories.exception_table == 0);
		assert(pe_optional_header.data_directories.certificate_table == 0);
		//My dll dont follow this assertion
		//assert(pe_optional_header.data_directories._debug == 0);
		assert(pe_optional_header.data_directories.copyright == 0);
		assert(pe_optional_header.data_directories.global_ptr == 0);
		assert(pe_optional_header.data_directories.tls_table == 0);
		assert(pe_optional_header.data_directories.load_config_table == 0);
		assert(pe_optional_header.data_directories.bound_import == 0);
		assert(pe_optional_header.data_directories.delay_import_descriptor == 0);
		assert(pe_optional_header.data_directories.reserved == 0);
	}
}

auto readAssembly(File file){
	return Assembly(binaryDebugRange(file.byChunk(1024).joiner));
}

class BinaryDebugRange(R)
if(isInputRange!R && is(ElementType!R == ubyte)){
	R range;
	size_t consumed = 0;

	this(R r){
		range = r;
	}
	bool empty(){
		return range.empty;
	}
	void popFront(){
		range.popFront();
		consumed++;
	}
	ubyte front(){
		return range.front;
	}
	@property
	size_t ConsumedLength(){
		return consumed;
	}
}
auto binaryDebugRange(R)(R range){
	return new BinaryDebugRange!R(range);
}

void main()
{
	auto assembly = readAssembly(File("test.dll"));
}
