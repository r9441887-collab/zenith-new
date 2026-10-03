#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum class TokenKind {
    Func, Var, Let, Const, If, Else, While, For, Return, End, True, False, Import,
    Use,
    Struct, Class, Extern, App, From, Type, Switch, Case, Break, Continue, Loop,
    Extends, Interface, Implements, Abstract,
    Interrupt,  // interrupt(n) - software interrupt
    TypeInt, TypeFloat, TypeBool, TypeString, TypeVoid,
    TypeVec2, TypeVec3, TypeColor, TypeEntity,
    Virt, Phys, Ptr, Asm,
    Ident, Number, FloatLit, StringLit, PercentLit,
    Plus, Minus, Star, Slash, SlashSlash, Percent, Dot, Bang, Amp,
    Eq, EqEq, NotEq, Lt, Gt, LtEq, GtEq, Arrow,
    AmpAmp, PipePipe, Pipe, Caret, ShiftLeft, ShiftRight, Tilde,
    LParen, RParen, LBrace, RBrace, LBrack, RBrack,
    Comma, Colon, At, Newline, Eof, Error
};

struct Token {
    TokenKind kind;
    std::string text;
    int64_t intVal = 0;
    double floatVal = 0.0;
    int line = 0;
    int col = 0;
};

// Tokenize `src` with the selfhost lexer: selfhost/lexer.z, compiled to an
// ET_REL with `zenith --obj` (selfhost/lexobj.o) and linked into this binary
// — src/lexembed.cpp calls lexInit/lexAll/lex*At directly, in-process.
// Returns false only when the source cannot be tokenized at all; in-source
// lexer errors are printed by the lexer on stderr and skipped, like the old
// Lexer::all().
bool lexSource(const std::string& src, std::vector<Token>& out, std::string& err);

// The old C++ tokenizer. Its implementation lives in
// selfhost/reference/lexer.cpp and is compiled only into the differential
// tools (selfhost/lexref.cpp / lexdiff) — the compiler itself never uses it.
class Lexer {
public:
    explicit Lexer(const std::string& source);
    Token next();
    const std::vector<Token>& all();

private:
    void skipWhitespace();
    Token scanToken();
    Token scanNumber();
    Token scanIdentOrKeyword();
    Token scanString();
    void advance();
    char peek() const;
    char peekNext() const;
    bool match(char c);
    bool isAtEnd() const;
    Token makeToken(TokenKind kind);
    Token makeError(const std::string& msg);

    std::string source;
    size_t start;
    size_t current;
    int line;
    int col;
    std::vector<Token> tokens;
    bool tokenized;
};
