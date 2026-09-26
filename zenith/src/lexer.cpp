#include "lexer.h"
#include <iostream>
#include <unordered_map>
#include <cstdlib>
const int x = 10;
Lexer::Lexer(const std::string& source)
    : source(source), start(0), current(0), line(1), col(1), tokenized(false) {}

void Lexer::advance() {
    if (!isAtEnd()) {
        if (source[current] == '\n') { line++; col = 1; }
        else { col++; }
        current++;
    }
}

char Lexer::peek() const {
    return isAtEnd() ? '\0' : source[current];
}

char Lexer::peekNext() const {
    return current + 1 >= source.size() ? '\0' : source[current + 1];
}

bool Lexer::match(char c) {
    if (peek() == c) { advance(); return true; }
    return false;
}

bool Lexer::isAtEnd() const {
    return current >= source.size();
}

Token Lexer::makeToken(TokenKind kind) {
    Token t;
    t.kind = kind;
    t.text = source.substr(start, current - start);
    t.line = line;
    t.col = col - (int)(current - start);
    t.intVal = 0;
    t.floatVal = 0.0;
    return t;
}

Token Lexer::makeError(const std::string& msg) {
    Token t;
    t.kind = TokenKind::Error;
    t.text = msg;
    t.line = line;
    t.col = col;
    t.intVal = 0;
    t.floatVal = 0.0;
    return t;
}

void Lexer::skipWhitespace() {
    while (!isAtEnd()) {
        char c = peek();
        if (c == ' ' || c == '\t' || c == '\r') {
            advance();
        } else if (c == '#') {
            while (!isAtEnd() && peek() != '\n') advance();
        } else if (c == '\\') {
            // block comment: \ ... \ (multi-line, no nesting; '\\' pairs also work)
            advance();  // skip first backslash
            if (!isAtEnd() && peek() == '\\') advance();  // '\\' opener
            while (!isAtEnd() && peek() != '\\') advance();
            if (!isAtEnd()) advance();  // skip closing backslash
            if (!isAtEnd() && peek() == '\\') advance();  // '\\' closer
        } else {
            break;
        }
    }
}

Token Lexer::scanNumber() {
    bool isFloat = false;
    bool isHex = false;

    if (peek() == '0' && (peekNext() == 'x' || peekNext() == 'X')) {
        isHex = true;
        advance(); advance();
        if (isAtEnd() || !isxdigit((unsigned char)peek())) {
            return makeError("Invalid hex literal: expected digits after '0x'");
        }
        while (!isAtEnd() && isxdigit((unsigned char)peek())) advance();
    } else {
        while (!isAtEnd() && isdigit((unsigned char)peek())) advance();
        // Fraction part ('1.5') or trailing dot ('1.') — but NOT a member
        // access like '1.foo', which must stay Number '.' Ident.
        if (peek() == '.' &&
            (isdigit((unsigned char)peekNext()) ||
             (!isalpha((unsigned char)peekNext()) && peekNext() != '_'))) {
            isFloat = true;
            advance();
            while (!isAtEnd() && isdigit((unsigned char)peek())) advance();
        }
        // Exponent suffix 'e'/'E' with optional sign, e.g. '1e3', '2.5E-2'.
        // Only consumed when it forms a valid exponent so that an identifier
        // like '1e' keeps lexing as Number + Ident.
        if (peek() == 'e' || peek() == 'E') {
            bool expValid = isdigit((unsigned char)peekNext());
            if (!expValid && (peekNext() == '+' || peekNext() == '-') &&
                current + 2 < source.size() &&
                isdigit((unsigned char)source[current + 2])) {
                expValid = true;
            }
            if (expValid) {
                isFloat = true;
                advance();  // 'e'/'E'
                if (peek() == '+' || peek() == '-') advance();
                while (!isAtEnd() && isdigit((unsigned char)peek())) advance();
            }
        }
        // Floating suffix 'f'/'F': '1f', '1.5f'.
        if (!isAtEnd() && (peek() == 'f' || peek() == 'F') && !isalpha((unsigned char)peekNext())) {
            isFloat = true;
            advance();
        }
    }

    std::string numStr = source.substr(start, current - start);
    try {
        if (isFloat) {
            Token t = makeToken(TokenKind::FloatLit);
            t.floatVal = std::stod(numStr);
            return t;
        }
        if (!isHex && !isAtEnd() && peek() == '%') {
            advance();
            Token t = makeToken(TokenKind::PercentLit);
            t.intVal = std::stoll(numStr);
            return t;
        }
        Token t = makeToken(TokenKind::Number);
        t.intVal = isHex ? std::stoll(numStr, 0, 16) : std::stoll(numStr);
        return t;
    } catch (const std::exception&) {
        return makeError("Invalid number: " + numStr);
    }
}

Token Lexer::scanIdentOrKeyword() {
    while (!isAtEnd() && (isalnum((unsigned char)peek()) || peek() == '_')) advance();
    std::string word = source.substr(start, current - start);

    static const std::unordered_map<std::string, TokenKind> keywords = {
        {"func", TokenKind::Func}, {"var", TokenKind::Var}, {"let", TokenKind::Let},
        {"const", TokenKind::Const},
        {"if", TokenKind::If}, {"else", TokenKind::Else},
        {"while", TokenKind::While}, {"for", TokenKind::For},
        {"return", TokenKind::Return}, {"end", TokenKind::End},
        {"true", TokenKind::True}, {"false", TokenKind::False},
        {"import", TokenKind::Import},
        {"struct", TokenKind::Struct},         {"class", TokenKind::Class}, {"extends", TokenKind::Extends}, {"extern", TokenKind::Extern},
        {"interface", TokenKind::Interface},   {"implements", TokenKind::Implements},
        {"abstract", TokenKind::Abstract},
        {"app", TokenKind::App}, {"from", TokenKind::From},
        {"switch", TokenKind::Switch}, {"case", TokenKind::Case}, {"break", TokenKind::Break},
        {"continue", TokenKind::Continue}, {"loop", TokenKind::Loop},
        {"interrupt", TokenKind::Interrupt},
        {"int", TokenKind::TypeInt}, {"float", TokenKind::TypeFloat},
        {"bool", TokenKind::TypeBool}, {"string", TokenKind::TypeString},
        {"void", TokenKind::TypeVoid}, {"vec2", TokenKind::TypeVec2},
        {"vec3", TokenKind::TypeVec3}, {"color", TokenKind::TypeColor},
        {"entity", TokenKind::TypeEntity},
        {"virt", TokenKind::Virt}, {"phys", TokenKind::Phys},
        {"ptr", TokenKind::Ptr},         {"asm", TokenKind::Asm},
    };

    auto it = keywords.find(word);
    if (it != keywords.end()) return makeToken(it->second);
    return makeToken(TokenKind::Ident);
}

Token Lexer::scanString() {
    int startLine = line;
    int startCol = col;
    advance(); // skip opening "
    std::string result;
    while (!isAtEnd() && peek() != '"') {
        if (peek() == '\\') {
            advance(); // skip backslash
            if (isAtEnd()) return makeError("Unterminated string escape");
            char esc = peek();
            advance();
            switch (esc) {
                case 'n': result += '\n'; break;
                case 't': result += '\t'; break;
                case 'r': result += '\r'; break;
                case '\\': result += '\\'; break;
                case '"': result += '"'; break;
                case '0': result += '\0'; break;
                default: return makeError(std::string("Unknown escape sequence: \\") + esc);
            }
        } else {
            result += peek();
            advance(); // advance() tracks line/col, so raw newlines are safe
        }
    }
    if (isAtEnd()) return makeError("Unterminated string");
    Token t;
    t.kind = TokenKind::StringLit;
    t.text = result;
    t.line = startLine;
    t.col = startCol;
    t.intVal = 0;
    t.floatVal = 0.0;
    advance(); // skip closing "
    return t;
}

Token Lexer::scanToken() {
    skipWhitespace();
    start = current;
    if (isAtEnd()) return makeToken(TokenKind::Eof);

    char c = peek();
    int preLine = line;
    int preCol = col;
    advance();

    if (c == '\n') {
        Token t = makeToken(TokenKind::Newline);
        t.line = preLine;
        t.col = preCol;
        return t;
    }
    if (isdigit((unsigned char)c)) { current--; col--; return scanNumber(); }
    if (c == '.' && isdigit((unsigned char)peek())) { current--; col--; return scanNumber(); }
    if (isalpha((unsigned char)c) || c == '_') { current--; col--; return scanIdentOrKeyword(); }

    if (c == '"') { current--; col--; return scanString(); }

    switch (c) {
        case '+': return makeToken(TokenKind::Plus);
        case '-':
            if (match('>')) return makeToken(TokenKind::Arrow);
            return makeToken(TokenKind::Minus);
        case '*': return makeToken(TokenKind::Star);
        case '/':
            if (match('/')) return makeToken(TokenKind::SlashSlash);
            return makeToken(TokenKind::Slash);
        case '%': return makeToken(TokenKind::Percent);
        case '.': return makeToken(TokenKind::Dot);
        case '(': return makeToken(TokenKind::LParen);
        case ')': return makeToken(TokenKind::RParen);
        case '{': return makeToken(TokenKind::LBrace);
        case '}': return makeToken(TokenKind::RBrace);
        case '[': return makeToken(TokenKind::LBrack);
        case ']': return makeToken(TokenKind::RBrack);
        case ',': return makeToken(TokenKind::Comma);
        case ':': return makeToken(TokenKind::Colon);
        case '@': return makeToken(TokenKind::At);
        case '=':
            if (match('=')) return makeToken(TokenKind::EqEq);
            return makeToken(TokenKind::Eq);
        case '!':
            if (match('=')) return makeToken(TokenKind::NotEq);
            return makeToken(TokenKind::Bang);
        case '<':
            if (match('<')) return makeToken(TokenKind::ShiftLeft);
            if (match('=')) return makeToken(TokenKind::LtEq);
            return makeToken(TokenKind::Lt);
        case '>':
            if (match('>')) return makeToken(TokenKind::ShiftRight);
            if (match('=')) return makeToken(TokenKind::GtEq);
            return makeToken(TokenKind::Gt);
        case '&':
            if (match('&')) return makeToken(TokenKind::AmpAmp);
            return makeToken(TokenKind::Amp);
        case '|':
            if (match('|')) return makeToken(TokenKind::PipePipe);
            return makeToken(TokenKind::Pipe);
        case '^':
            return makeToken(TokenKind::Caret);
        case '~':
            return makeToken(TokenKind::Tilde);
        default:
            return makeError("Unexpected character: " + std::string(1, c));
    }
}

Token Lexer::next() {
    Token t = scanToken();
    tokens.push_back(t);
    return t;
}

const std::vector<Token>& Lexer::all() {
    if (!tokenized) {
        while (true) {
            Token t = scanToken();
            if (t.kind == TokenKind::Error) {
                // Report the offending character, then keep scanning:
                // an error must not silently truncate the rest of the file.
                // scanToken() already advanced past the bad character, so an
                // extra advance() here would skip the next valid char.
                std::cerr << "Lexer error at line " << t.line << ": " << t.text << std::endl;
                continue;
            }
            tokens.push_back(t);
            if (t.kind == TokenKind::Eof) break;
        }
        tokenized = true;
    }
    return tokens;
}
