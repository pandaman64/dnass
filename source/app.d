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
struct PE_file_header{
	ushort machine;
	ushort number_of_sections;
	uint timestamp;
	uint pointer_to_symbol_table;
	uint number_of_symbols;
	ushort optional_header_size;
	ushort characteristics;
}

auto read(T,R)(ref R range,Endian endian = Endian.littleEndian)
if(isInputRange!R && is(ElementType!R == ubyte)){
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
		PE_file_header pe_file_header = void;
		pe_file_header.machine = range.read!ushort;
		pe_file_header.number_of_sections = range.read!ushort;
		pe_file_header.timestamp = range.read!uint;
		pe_file_header.pointer_to_symbol_table = range.read!uint;
		pe_file_header.number_of_symbols = range.read!uint;
		pe_file_header.optional_header_size = range.read!ushort;
		pe_file_header.characteristics = range.read!ushort;
		assert(pe_file_header.machine == 0x14c);
		assert(pe_file_header.pointer_to_symbol_table == 0);
		assert(pe_file_header.number_of_symbols == 0);
		writefln("sections : %d\ntime : %s\nheader size : %d\ncharacteristics : %d",
				pe_file_header.number_of_sections,
				SysTime.fromUnixTime(pe_file_header.timestamp).toSimpleString,
				pe_file_header.optional_header_size,
				pe_file_header.characteristics);
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
