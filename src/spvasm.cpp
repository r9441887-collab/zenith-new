#include "spvasm.h"
#include <cstring>
#include <cstdlib>
#include <unordered_map>
#include <unordered_set>

namespace spv {

// ---- opcode table (subset of SPIR-V 1.0 spec, alphabetical) ----
struct OpNameRec { const char* name; uint32_t opcode; };
static const OpNameRec kOps[] = {
    {"OpAccessChain", OpAccessChain},
    {"OpBitcast", OpBitcast},
    {"OpBranch", OpBranch},
    {"OpBranchConditional", OpBranchConditional},
    {"OpCapability", OpCapability},
    {"OpCompositeConstruct", OpCompositeConstruct},
    {"OpCompositeExtract", OpCompositeExtract},
    {"OpConstant", OpConstant},
    {"OpConstantComposite", OpConstantComposite},
    {"OpConstantFalse", OpConstantFalse},
    {"OpConstantTrue", OpConstantTrue},
    {"OpConvertFToS", OpConvertFToS},
    {"OpConvertSToF", OpConvertSToF},
    {"OpDecorate", OpDecorate},
    {"OpEntryPoint", OpEntryPoint},
    {"OpExecutionMode", OpExecutionMode},
    {"OpExtInst", OpExtInst},
    {"OpExtInstImport", OpExtInstImport},
    {"OpFAdd", OpFAdd},
    {"OpFDiv", OpFDiv},
    {"OpFNegate", OpFNegate},
    {"OpFMul", OpFMul},
    {"OpFOrdEqual", OpFOrdEqual},
    {"OpFOrdGreaterThan", OpFOrdGreaterThan},
    {"OpFOrdGreaterThanEqual", OpFOrdGreaterThanEqual},
    {"OpFOrdLessThan", OpFOrdLessThan},
    {"OpFOrdLessThanEqual", OpFOrdLessThanEqual},
    {"OpFOrdNotEqual", OpFOrdNotEqual},
    {"OpFSub", OpFSub},
    {"OpFunction", OpFunction},
    {"OpFunctionEnd", OpFunctionEnd},
    {"OpFunctionParameter", OpFunctionParameter},
    {"OpIAdd", OpIAdd},
    {"OpIEqual", OpIEqual},
    {"OpIMul", OpIMul},
    {"OpINotEqual", OpINotEqual},
    {"OpISub", OpISub},
    {"OpLabel", OpLabel},
    {"OpLoad", OpLoad},
    {"OpLogicalAnd", OpLogicalAnd},
    {"OpLogicalEqual", OpLogicalEqual},
    {"OpLogicalNot", OpLogicalNot},
    {"OpLogicalNotEqual", OpLogicalNotEqual},
    {"OpLogicalOr", OpLogicalOr},
    {"OpMatrixTimesMatrix", OpMatrixTimesMatrix},
    {"OpMatrixTimesScalar", OpMatrixTimesScalar},
    {"OpMatrixTimesVector", OpMatrixTimesVector},
    {"OpMemberDecorate", OpMemberDecorate},
    {"OpMemberName", OpMemberName},
    {"OpMemoryModel", OpMemoryModel},
    {"OpName", OpName},
    {"OpNop", OpNop},
    {"OpReturn", OpReturn},
    {"OpReturnValue", OpReturnValue},
    {"OpSDiv", OpSDiv},
    {"OpSNegate", OpSNegate},
    {"OpSLessThan", OpSLessThan},
    {"OpSLessThanEqual", OpSLessThanEqual},
    {"OpSelect", OpSelect},
    {"OpShiftLeftLogical", OpShiftLeftLogical},
    {"OpShiftRightArithmetic", OpShiftRightArithmetic},
    {"OpShiftRightLogical", OpShiftRightLogical},
    {"OpSource", OpSource},
    {"OpSourceExtension", OpSourceExtension},
    {"OpString", OpString},
    {"OpStore", OpStore},
    {"OpSwitch", OpSwitch},
    {"OpTypeArray", OpTypeArray},
    {"OpTypeBool", OpTypeBool},
    {"OpTypeFloat", OpTypeFloat},
    {"OpTypeFunction", OpTypeFunction},
    {"OpTypeInt", OpTypeInt},
    {"OpTypeMatrix", OpTypeMatrix},
    {"OpTypePointer", OpTypePointer},
    {"OpTypeRuntimeArray", OpTypeRuntimeArray},
    {"OpTypeStruct", OpTypeStruct},
    {"OpTypeVector", OpTypeVector},
    {"OpTypeVoid", OpTypeVoid},
    {"OpUDiv", OpUDiv},
    {"OpUndef", OpUndef},
    {"OpVariable", OpVariable},
    {"OpVectorShuffle", OpVectorShuffle},
    {"OpVectorTimesMatrix", OpVectorTimesMatrix},
};
static const size_t kOpsCount = sizeof(kOps) / sizeof(kOps[0]);

bool lookupOpcode(const std::string& name, uint32_t& opcode) {
    for (size_t i = 0; i < kOpsCount; i++) {
        if (name == kOps[i].name) { opcode = kOps[i].opcode; return true; }
    }
    return false;
}

// ---- enum literal -> word (subset used by glslang-emitted shaders) ----
struct EnumLit { const char* name; uint32_t value; };
static const EnumLit kEnums[] = {
    // Capability
    {"Shader", 1}, {"Matrix", 0}, {"ShaderPacking", 12},
    {"Geometry", 4}, {"Tessellation", 3}, {"Float64", 8}, {"Int64", 9},
    // AddressingModel
    {"Logical", 0}, {"Physical32", 1}, {"Physical64", 2},
    // SourceLanguage
    {"ESSL", 0}, {"GLSL", 1}, {"OpenCL_C", 2}, {"OpenCL_CPP", 3}, {"HLSL", 4},
    // MemoryModel
    {"Simple", 0}, {"GLSL450", 1}, {"OpenCL", 2},
    // ExecutionModel
    {"Vertex", 0}, {"TessellationControl", 1}, {"TessellationEvaluation", 2},
    {"Geometry", 4}, {"Fragment", 4}, {"GLCompute", 5}, {"Kernel", 6},
    // ExecutionMode
    {"OriginUpperLeft", 7}, {"OriginLowerLeft", 8}, {"EarlyFragmentTests", 9},
    {"DepthReplacing", 12}, {"DepthGreater", 14}, {"DepthLess", 15},
    {"DepthUnchanged", 16},
    // StorageClass
    {"UniformConstant", 0}, {"Input", 1}, {"Uniform", 2}, {"Output", 3},
    {"Workgroup", 4}, {"CrossWorkgroup", 5}, {"Private", 6}, {"Function", 7},
    {"Generic", 8}, {"PushConstant", 9}, {"AtomicCounter", 10}, {"Image", 11},
    {"StorageBuffer", 12},
    // Decoration
    {"RelaxedPrecision", 0}, {"SpecId", 1}, {"Block", 2}, {"BufferBlock", 3},
    {"RowMajor", 4}, {"ColMajor", 5}, {"ArrayStride", 6}, {"MatrixStride", 7},
    {"GLSLShared", 8}, {"GLSLPacked", 9}, {"CPacked", 10}, {"BuiltIn", 11},
    {"NoPerspective", 13}, {"Flat", 14}, {"Patch", 15}, {"Centroid", 16},
    {"Sample", 17}, {"Invariant", 18}, {"Restrict", 19}, {"Aliased", 20},
    {"Volatile", 21}, {"Constant", 22}, {"Coherent", 23}, {"NonWritable", 24},
    {"NonReadable", 25}, {"Uniform", 26}, {"SaturatedConversion", 28},
    {"Stream", 29}, {"Location", 30}, {"Component", 31}, {"Index", 32},
    {"Binding", 33}, {"DescriptorSet", 34}, {"Offset", 35}, {"XfbBuffer", 36},
    {"XfbStride", 37},
    // BuiltIn
    {"Position", 0}, {"PointSize", 1}, {"ClipDistance", 3}, {"CullDistance", 4},
    {"VertexId", 5}, {"InstanceId", 6}, {"PrimitiveId", 7}, {"InvocationId", 8},
    {"Layer", 9}, {"ViewportIndex", 10}, {"TessLevelOuter", 11},
    {"TessLevelInner", 12}, {"TessCoord", 13}, {"PatchVertices", 14},
    {"FragCoord", 15}, {"PointCoord", 16}, {"FrontFacing", 17},
    {"SampleId", 18}, {"SamplePosition", 19}, {"SampleMask", 20},
    {"FragDepth", 22}, {"HelperInvocation", 23}, {"NumWorkgroups", 24},
    {"WorkgroupSize", 25}, {"WorkgroupId", 26}, {"LocalInvocationId", 27},
    {"GlobalInvocationId", 28}, {"LocalInvocationIndex", 29},
    {"SubgroupSize", 36}, {"SubgroupLocalInvocationId", 37},
    // FunctionControl
    {"None", 0}, {"Inline", 1}, {"Pure", 2}, {"Const", 4}, {"DontInline", 8},
    // Image/Sampler dim, masks
    {"ReadOnly", 2}, {"WriteOnly", 4},
    // LoopControl / SelectionControl
    {"DontFlatten", 2}, {"Flatten", 1}, {"Unroll", 1}, {"DontUnroll", 2},
    // MemoryAccess
    {"Aligned", 2}, {"Nontemporal", 4},
};
static const size_t kEnumsCount = sizeof(kEnums) / sizeof(kEnums[0]);

static bool lookupEnum(const std::string& name, uint32_t& value) {
    for (size_t i = 0; i < kEnumsCount; i++) {
        if (name == kEnums[i].name) { value = kEnums[i].value; return true; }
    }
    return false;
}

// Split a line into whitespace/comma-separated tokens; honor "..." strings and
// drop everything after an unquoted '#'.
static std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    bool inStr = false, comment = false;
    for (size_t i = 0; i < line.size(); i++) {
        char c = line[i];
        if (comment) break;
        if (c == '"') { inStr = !inStr; cur += c; continue; }
        if (inStr) { cur += c; continue; }
        if (c == ' ' || c == '\t' || c == ',') {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else if (c == '#') {
            comment = true;
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

bool parseString(const std::string& tok, std::string& out) {
    if (tok.size() < 2 || tok.front() != '"' || tok.back() != '"') return false;
    out.clear();
    for (size_t i = 1; i + 1 < tok.size(); i++) {
        char c = tok[i];
        if (c == '\\' && i + 2 < tok.size()) {
            char e = tok[i + 1];
            if (e == 'n') out += '\n';
            else if (e == 't') out += '\t';
            else if (e == '\\') out += '\\';
            else if (e == '"') out += '"';
            else if (e == 'r') out += '\r';
            else out += e;
            i++;
        } else out += c;
    }
    return true;
}

// Append a literal word; interprets hex, decimal (with '-' -> two's complement)
// and named SPIR-V enum literals.
static bool pushLiteral(const std::string& t, std::vector<uint32_t>& words, std::string& err) {
    if (t[0] == '%') {
        words.push_back(0); // id placeholder — resolved in pass 3
        return true;
    }
    if (t[0] == '"') {
        std::string s;
        if (!parseString(t, s)) { err = "bad string '" + t + "'"; return false; }
        size_t n = (s.size() + 1 + 3) & ~3u;
        std::vector<uint8_t> bytes(n, 0);
        std::memcpy(bytes.data(), s.data(), s.size());
        for (size_t k = 0; k < n; k += 4)
            words.push_back((uint32_t)bytes[k] | ((uint32_t)bytes[k+1] << 8) |
                            ((uint32_t)bytes[k+2] << 16) | ((uint32_t)bytes[k+3] << 24));
        return true;
    }
    uint32_t v;
    if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) {
        v = (uint32_t)strtoul(t.c_str() + 2, nullptr, 16);
    } else if (lookupEnum(t, v)) {
        // ok
    } else {
        char* end = nullptr;
        long long val = strtoll(t.c_str(), &end, 10);
        if (!end || *end != '\0' || t.empty()) { err = "bad literal '" + t + "'"; return false; }
        v = (uint32_t)val;
    }
    words.push_back(v);
    return true;
}

// The result id of an instruction (from the leading '%r =') or 0.
struct RawLine {
    std::vector<std::string> toks;
    uint32_t resultIdWordIdx;   // index into toks if a '%r =' prefix exists
};

bool assemble(const std::string& text, std::vector<uint32_t>& out, std::string& err) {
    // Split into lines.
    std::vector<std::string> lines;
    {
        std::string cur;
        for (size_t i = 0; i < text.size(); i++) {
            char c = text[i];
            if (c == '\r') continue;
            if (c == '\n') { lines.push_back(cur); cur.clear(); }
            else cur += c;
        }
        if (!cur.empty()) lines.push_back(cur);
    }

    // Tokenize, drop empty lines.
    std::vector<std::vector<std::string>> linetoks;
    for (auto& l : lines) {
        auto t = tokenize(l);
        if (!t.empty()) linetoks.push_back(t);
    }

    // Collect every '%name' -> id. This includes the leading '%r =' result id
    // and all references, so `bound` is right even with forward references.
    std::unordered_map<std::string, uint32_t> idMap;
    uint32_t bound = 1;
    auto getId = [&](const std::string& name) -> uint32_t {
        auto it = idMap.find(name);
        if (it != idMap.end()) return it->second;
        uint32_t id = bound++;
        idMap[name] = id;
        return id;
    };
    for (auto& toks : linetoks) {
        size_t i = 0;
        if (toks[i][0] == '%') {
            std::string name = toks[i].substr(1);
            if (!name.empty() && name.back() == '=') name.pop_back();
            getId(name);
            i++;
            if (i < toks.size() && toks[i] == "=") i++;   // skip '%5 ='
        }
        for (; i < toks.size(); i++) {
            if (toks[i][0] == '%') getId(toks[i].substr(1));
        }
    }
    // Assign ids deterministically in first-use order (same as spirv-as).

    // Second pass: emit. Instructions that produce a typed *value* lay out the
    // binary operands as [Result Type][Result <id>]...; the exceptions (result
    // first, "Result <id>" then other operands, no Result Type) are OpName,
    // OpMemberName, OpLabel, OpExtInstImport, OpType* family, OpCapability...
    static const std::unordered_set<uint32_t> kResultFirst = {
        OpName, OpMemberName, OpLabel, OpExtInstImport, OpTypeVoid, OpTypeBool,
        OpTypeInt, OpTypeFloat, OpTypeVector, OpTypeMatrix, OpTypeStruct,
        OpTypePointer, OpTypeFunction, OpTypeArray, OpTypeRuntimeArray,
    };
    std::vector<uint32_t> operands;
    out.clear();
    out.push_back(0x07230203u);   // magic
    out.push_back(0x00010000u);   // version 1.0
    out.push_back(0);             // generator
    out.push_back(bound);         // id bound
    out.push_back(0);             // schema

    auto parseOperand = [&](const std::string& t) -> bool {
        if (t[0] == '%') { operands.push_back(idMap[t.substr(1)]); return true; }
        return pushLiteral(t, operands, err);
    };

    for (auto& toks : linetoks) {
        size_t i = 0;
        uint32_t resultId = 0;
        if (toks[i][0] == '%') {
            std::string name = toks[i].substr(1);
            if (!name.empty() && name.back() == '=') name.pop_back();
            resultId = idMap[name];
            i++;
            if (i < toks.size() && toks[i] == "=") i++;   // skip '%5 ='
        }
        std::string opname = toks[i++];
        uint32_t opcode;
        if (!lookupOpcode(opname, opcode)) { err = "unknown opcode '" + opname + "'"; return false; }

        operands.clear();
        for (; i < toks.size(); i++) {
            if (!parseOperand(toks[i])) return false;
        }

        // Rearrange [Result Type][Result <id>] vs [Result <id>].
        if (resultId) {
            if (kResultFirst.count(opcode)) {
                operands.insert(operands.begin(), resultId);
            } else {
                if (operands.empty()) { err = "opcode '" + opname + "' missing result type"; return false; }
                operands.insert(operands.begin() + 1, resultId);
            }
        }
        uint32_t wc = (uint32_t)(operands.size() + 1);
        out.push_back((wc << 16) | opcode);
        for (auto w : operands) out.push_back(w);
    }
    return true;
}

} // namespace spv