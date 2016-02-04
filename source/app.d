import std.stdio;
import std.range;
import std.algorithm;
import std.system;

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
	}
}

auto readAssembly(File file){
	return Assembly(file.byChunk(1024).joiner);
}

void main()
{
	auto assembly = readAssembly(File("test.dll"));
}
