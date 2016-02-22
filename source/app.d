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

	template is_numeric(string name){
		import std.format;
		alias is_numeric = isNumeric!(mixin(format("typeof(%s.%s)",typename,name)));
	}

	auto debug_write(T val){
		auto name_len = max(staticMap!(get_len,field_names));
		writefln("| %*s | Offset | Size |    Value |",name_len,"Field");
		foreach(name;field_names){
			alias tuple = to_tuple!name;
			if(is_numeric!name){
				writefln("| %*s | %6x | %4x | %8x |",name_len,name,tuple[0],tuple[1],tuple[2](val));
			}
			else{
				import std.conv;
				import std.string;
				writefln("| %*s | %6x | %4x | %s |",name_len,name,tuple[0],tuple[1],tuple[2](val).to!string.rightJustify(8));
			}
		}
		writeln;
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

//represents null padded (ASCII) string
//if underlying string is shorter than given length, remainder is filled with null
//if the length of underlying string is exactly same as given length, the string is not null terminated 
align(1)
struct PaddedString(size_t len){
	ubyte[len] content;

	size_t length() const{
		size_t ret = 0;
		while(ret < len && content[ret] != 0){
			ret++;
		}
		return ret;
	}

	string toString() const{
		import std.conv;

		return content[0..this.length].map!"cast(char)a".array.idup;
	}
}

align(1)
struct SectionHeader{
	PaddedString!8 name;
	uint virtual_size;
	uint virtual_address;
	uint size_of_raw_data;
	uint pointer_to_raw_data;
	uint pointer_to_relocations;
	uint pointer_to_line_numbers;
	ushort number_of_relocations;
	ushort number_of_line_numbers;
	enum Characteristics : uint{
		IMAGE_SCN_CNT_CODE = 0x20, //section contains code
		IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40, //section contains initialized data
		IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80, //section contains uninitialized data
		IMAGE_SCN_MEM_EXECUTE = 0x20000000, //section can be executed as code
		IMAGE_SCN_MEM_READ = 0x40000000, //section can be read
		IMAGE_SCN_MEM_WRITE = 0x80000000 //section can be written to
	}
	Characteristics characteristics;
}

struct Section{
	SectionHeader header;
	ubyte[] data;
}

align(1)
struct Directory{
	uint relative_virtual_address;
	uint size;
}

align(1)
struct CLIHeader{
	uint cb;
	ushort major_runtime_version;
	ushort minor_runtime_version;
	ulong metadata;
	uint flags;
	uint entry_point_token;
	ulong resources;
	ulong strong_name_sigunature;
	ulong code_manager_table;
	ulong vtable_fixups;
	ulong exported_address_table_jumps;
	ulong managed_native_header;
}

template read_impl(T,R){
	static if(isInputRange!R && isImplicitlyConvertible!(ElementType!R,ubyte)){
		static if(isScalarType!T){
			auto read_impl(ref R range,Endian endian){
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
			auto read_impl(ref R range,Endian endian){
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
		else static if(isArray!T){
			template util(U : U[N],size_t N){
				alias element_type = U;
				alias length = N;
			}

			auto read_impl(ref R range,Endian endian){
				return range.readSome!(util!T.element_type)(util!T.length,endian);
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

uint get_rva(ulong directory){
	return directory & 0x00000000FFFFFFFFuL;
}
uint get_size(ulong directory){
	return (directory & 0xFFFFFFFF00000000uL) >> 32;
}

auto read_by_rva(T)(in Section[] sections,ulong directory){
	auto rva = directory.get_rva;
	auto size = directory.get_size;
	assert(T.sizeof == size);
	foreach(const section;sections){
		if(section.header.virtual_address <= rva &&
		   rva < section.header.virtual_address + section.header.virtual_size){
			   auto begin = rva - section.header.virtual_address;
			   auto end = begin + size;
			   assert(end <= section.header.virtual_size);
			   const(ubyte)[] buffer = section.data[begin..end];
			   return buffer.read!T;
		   }
	}
	assert(0);
}

struct Assembly{
	this(R)(R input_range)
	if (isInputRange!R && is(ElementType!R == ubyte)){
		auto range = consumptionRecordedRange(input_range);
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

		auto sections = range.readSome!SectionHeader(pe_file_header.number_of_sections).map!(header => Section(header,[])).array;
		foreach(const section;sections){
			section.header.debug_write;
			//section header assertion
			assert(section.header.size_of_raw_data % pe_optional_header.nt_specific_fields.file_alignment == 0);
			assert(section.header.pointer_to_raw_data % pe_optional_header.nt_specific_fields.file_alignment == 0);
			//do not treat uninitialized data now
			assert(!(section.header.characteristics & SectionHeader.Characteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA));
		}

		//read each section
		foreach(ref section;sections){
			range.popFrontN(section.header.pointer_to_raw_data - range.ConsumedLength);
			section.data = range.readSome!ubyte(section.header.size_of_raw_data);
		}

		//extract CLI header
		auto cli_header = read_by_rva!CLIHeader(sections,pe_optional_header.data_directories.cli_header);
		cli_header.debug_write;
	}
}

auto readAssembly(File file){
	return Assembly(file.byChunk(1024).joiner);
}

class ConsumptionRecordedRange(R)
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
auto consumptionRecordedRange(R)(R range){
	return new ConsumptionRecordedRange!R(range);
}

void main()
{
	auto assembly = readAssembly(File("test.dll"));
}
