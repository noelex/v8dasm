#include <iostream>
#include <string>

#include <libplatform/libplatform.h>
#include <v8.h>
#include <cmath>

#pragma comment(lib, "v8_libbase.lib")
#pragma comment(lib, "v8_libplatform.lib")
#pragma comment(lib, "wee8.lib")

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "dmoguids.lib")
#pragma comment(lib, "wmcodecdspuuid.lib")
#pragma comment(lib, "msdmo.lib")
#pragma comment(lib, "Strmiids.lib")
#pragma comment(lib, "DbgHelp.lib")

using namespace v8;

static Isolate* isolate = nullptr;

static v8::ScriptCompiler::CachedData* compileCode(const char* data)
{
	auto str = String::NewFromUtf8(isolate, data).ToLocalChecked();
	auto script = Script::Compile(isolate->GetCurrentContext(), str).ToLocalChecked();
	auto unboundScript = script->GetUnboundScript();

	return ScriptCompiler::CreateCodeCache(unboundScript);
}

static void fixBytecode(uint8_t* bytecodeBuffer, const char* code) {
	auto dummyBytecode = compileCode(code);

	// Copy version hash, source hash and flag hash from dummy bytecode to source bytecode.
	// Offsets of these value may differ in different version of V8.
	// Refer V8 src/snapshot/code-serializer.h for details.
	for (int i = 4;i < 16;i++) {
		bytecodeBuffer[i] = dummyBytecode->data[i];
	}
	delete dummyBytecode;
}

static void runBytecode(uint8_t* bytecodeBuffer,int len) {
	// Compile some dummy code to get version hash, source hash and flag hash.
	const char* code = "\"ಠ_ಠ\"";
	fixBytecode(bytecodeBuffer, code);

	// Load code into code cache.
	auto cached_data = new ScriptCompiler::CachedData(bytecodeBuffer, len);

	// Create dummy source.
	ScriptOrigin origin(String::NewFromUtf8Literal(isolate,"code.jsc"));
	ScriptCompiler::Source source(String::NewFromUtf8(isolate, code).ToLocalChecked(), origin, cached_data);

	// Compile code from code cache to print disassembly.
	MaybeLocal<UnboundScript> v8_script =
		ScriptCompiler::CompileUnboundScript(isolate, &source, ScriptCompiler::kConsumeCodeCache);
}

static void readAllBytes(const std::string& file, std::vector<char> &buffer) {
	std::ifstream infile(file,std::ifstream::binary);

	infile.seekg(0, infile.end);
	size_t length = infile.tellg();
	infile.seekg(0, infile.beg);

	if (length > 0) {
		buffer.resize(length);
		infile.read(&buffer[0], length);
	}
}

int main(int argc, char *argv[])
{
	// Set flags here, flags that affects code generation and seririalzation should be same as the target program.
	// You can add other flags freely because flag hash will be overrided in fixBytecode().
	v8::V8::SetFlagsFromString("--no-lazy --no-flush-bytecode --log-all");

	v8::V8::InitializeICU();
	auto plat = v8::platform::NewDefaultPlatform();
	v8::V8::InitializePlatform(plat.get());
	v8::V8::Initialize();

	Isolate::CreateParams p = {};
	p.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
	
	isolate = Isolate::New(p);
	{
		v8::HandleScope scope(isolate);
		auto ctx = v8::Context::New(isolate);
		Context::Scope context_scope(ctx);

		std::vector<char> data;
		readAllBytes(argv[1], data);
		runBytecode((uint8_t*)data.data(), data.size());
	}
}