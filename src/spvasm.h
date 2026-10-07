#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace spv {

// ============================================================================
// Build-time SPIR-V assembler: turns a small, human-writable subset of the
// SPIR-V assembly language (the same grammar emit by `spirv-dis`) into a
// binary SPIR-V module that vkCreateShaderModule accepts.
//
// Supported forms (one instruction per line; whitespace-separated tokens):
//   %5 = OpTypeFloat 32
//   %8 = OpConstant %5 0                      # float 0.0  (integer literal bits)
//   %9 = OpConstant %5 0x3F800000             # float 1.0  (hex accepted)
//   %10 = OpTypeVector %5 4
//   %11 = OpTypePointer Input %10
//   %12 = OpVariable %11 Input                 # default Initializer=0; %12 = id
//   OpCapability Shader                        # no result id
//   OpMemoryModel Logical GLSL450
//   OpEntryPoint Vertex %main "main" %a %b
//   OpExecutionMode %main OriginUpperLeft
//   OpDecorate %12 Location 0
//   OpMemberDecorate %12 3 BuiltIn Position    # member index is a literal
//   OpMemberName %12 0 "gl_Position"
//   OpName %12 "main"
//   OpExtInstImport "GLSL.std.450"
//   %x = OpFunction %void None %3             # None = literal control mask
//   %5 = OpLabel
//   %22 = OpLoad %10 %12
//   %24 = OpCompositeConstruct %10 %22 %23 %1
//   %26 = OpAccessChain %ptr %base %int_0
//   OpStore %26 %24
//   OpReturn
//   OpFunctionEnd
//
// Grammar:
//   line        = [ '%' id '=' ] opname ('%' id | literal )* ['#comment']
//   literal     = [0-9]+ | 0x[0-9a-fA-F]+ | -[0-9]+  (u32 bit pattern)
//   string      = '"..."' with \n \t \\ \" escapes (no NUL)
//
// Rules:
//   - Every result-id reference must use the SAME id ("%5"); ids are resolved
//     by name, so `%void = OpTypeVoid` + `%5 = OpTypeFunction %void` work.
//   - The result id is assigned in the header as you'd expect (bound = max id).
//   - OpMEMBERDECORATE: first operand is the target id, second is the member
//     index (literal), rest are decoration operands.
//   - OpDECORATE/OpNAME/OpMEMBERNAME never take a result id.
//   - OpEXTINSTIMPORT produces a result id.
//   - The assembler computes all instruction word counts automatically.
//
// Not handled (yet): labels/branches with negative literal ids, floats typed
// as 1.5 (use bit patterns), OpSpecConstant expressions, OpSwitch. These can
// be added if a later 3D stage needs them.
// ============================================================================

struct SpvInstr {
    uint32_t opcode;
    std::vector<uint32_t> words;   // operands including the result id
    bool hasResult;                // first operand word is the result id
};

enum Opcode : uint32_t {
    OpNop                    = 0,
    OpUndef                  = 1,
    OpString                 = 7,
    OpSource                 = 3,
    OpSourceExtension        = 4,
    OpName                   = 5,
    OpMemberName             = 6,
    OpLine                   = 8,
    OpNoLine                 = 317,
    OpExtInst                 = 12,
    OpExtInstImport           = 11,
    OpCapability              = 17,
    OpMemoryModel             = 14,
    OpEntryPoint              = 15,
    OpExecutionMode           = 16,
    OpDecorate                = 71,
    OpMemberDecorate          = 72,
    OpTypeVoid                = 19,
    OpTypeBool                = 20,
    OpTypeInt                 = 21,
    OpTypeFloat               = 22,
    OpTypeVector              = 23,
    OpTypeMatrix              = 24,
    OpTypeStruct              = 30,
    OpTypePointer             = 32,
    OpTypeFunction            = 33,
    OpTypeArray               = 28,
    OpTypeRuntimeArray        = 29,
    OpConstant                = 43,
    OpConstantTrue            = 41,
    OpConstantFalse           = 42,
    OpConstantComposite       = 44,
    OpVariable                = 59,
    OpLoad                    = 61,
    OpStore                   = 62,
    OpAccessChain             = 65,
    OpCompositeExtract        = 81,
    OpCompositeConstruct      = 80,
    OpFunction                = 54,
    OpFunctionParameter       = 55,
    OpFunctionEnd             = 56,
    OpLabel                   = 248,
    OpBranch                  = 249,
    OpBranchConditional       = 250,
    OpSwitch                  = 251,
    OpReturn                  = 253,
    OpReturnValue             = 254,
    OpImport                  = 7,
    OpVectorShuffle           = 79,
    OpIAdd                    = 128,
    OpISub                    = 130,
    OpIMul                    = 132,
    OpUDiv                    = 133,
    OpSDiv                    = 134,
    OpFAdd                    = 129,
    OpFSub                    = 131,
    OpFMul                    = 135,
    OpFDiv                    = 136,
    OpSNegate                 = 126,
    OpFNegate                 = 127,
    OpShiftLeftLogical        = 140,
    OpShiftRightLogical       = 141,
    OpShiftRightArithmetic    = 142,
    OpLogicalAnd              = 137,
    OpLogicalOr               = 139,
    OpLogicalEqual            = 158,
    OpLogicalNotEqual         = 159,
    OpLogicalNot              = 143,
    OpSelect                  = 170,
    OpFOrdEqual               = 172,
    OpFOrdNotEqual            = 173,
    OpFOrdLessThan            = 174,
    OpFOrdGreaterThan         = 176,
    OpFOrdLessThanEqual       = 178,
    OpFOrdGreaterThanEqual    = 180,
    OpBitcast                 = 124,
    OpConvertFToS             = 113,
    OpConvertSToF             = 117,
    OpIEqual                  = 160,
    OpINotEqual               = 161,
    OpSLessThan               = 163,
    OpSLessThanEqual          = 165,
    OpMatrixTimesScalar       = 188,
    OpMatrixTimesVector       = 189,
    OpVectorTimesMatrix       = 190,
    OpMatrixTimesMatrix       = 191,
};

// Map from the SPIR-V assembly opname to its opcode. Returns false if unknown.
bool lookupOpcode(const std::string& name, uint32_t& opcode);

// Assemble `text` (split on '\n') into the binary SPIR-V words. On success
// returns true and fills `out` with the module (words 4,5,6 = boundary, id
// bound, 0). On failure returns false and sets `err` to a message.
bool assemble(const std::string& text, std::vector<uint32_t>& out, std::string& err);

} // namespace spv