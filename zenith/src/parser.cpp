#include "parser.h"
#include <iostream>
#include <filesystem>
#include <functional>
#include <unordered_set>
#include <algorithm>
#include <climits>

Parser::Parser(const std::vector<Token>& tokens) : tokens(tokens), pos(0) {}

Token Parser::peek() const { if (tokens.empty() || pos >= tokens.size()) return {TokenKind::Eof, "", 0, 0.0, 0, 0}; return tokens[pos]; }
Token Parser::peekNext() const {
    if (pos + 1 < tokens.size()) return tokens[pos + 1];
    return Token{TokenKind::Eof, "", 0, 0.0, 0, 0};
}
Token Parser::previous() const { if (pos > 0) return tokens[pos - 1]; return {TokenKind::Error, "", 0, 0.0, 0, 0}; }
Token Parser::advance() { if (tokens.empty() || pos >= tokens.size()) return {TokenKind::Eof, "", 0, 0.0, 0, 0}; Token t = tokens[pos]; if (!check(TokenKind::Eof)) pos++; return t; }
bool Parser::check(TokenKind kind) const { return peek().kind == kind; }

bool Parser::match(TokenKind kind) {
    if (check(kind)) { advance(); return true; }
    return false;
}

Token Parser::consume(TokenKind kind, const std::string& msg) {
    if (check(kind)) return advance();
    throw std::runtime_error(msg);
}

Type Parser::parseType() {
    // phys/virt qualifiers
    AddressSpace addrSpace = AddressSpace::Virtual;
    if (check(TokenKind::Virt)) { advance(); }
    else if (check(TokenKind::Phys)) {
        advance(); addrSpace = AddressSpace::Physical;
        if (appType != AppType::EFI && appType != AppType::Bare)
            throw std::runtime_error("phys requires EFI/bare");
    }
    // ptr<T> handling (accepts both `ptr T` and `ptr<T>`)
    if (check(TokenKind::Ptr)) {
        advance(); Type inner;
        bool angled = false;
        if (check(TokenKind::Lt)) { advance(); angled = true; }
        if (check(TokenKind::TypeInt))    { advance(); inner = {TypeKind::Int}; }
        else if (check(TokenKind::TypeFloat))  { advance(); inner = {TypeKind::Float}; }
        else if (check(TokenKind::TypeBool))   { advance(); inner = {TypeKind::Bool}; }
        else if (check(TokenKind::TypeString)) { advance(); inner = {TypeKind::String}; }
        else if (check(TokenKind::TypeVoid))   { advance(); inner = {TypeKind::Void}; }
        else if (check(TokenKind::Ident)) { inner.kind=TypeKind::Struct; inner.structName=advance().text; }
        else throw std::runtime_error("Expected type after ptr");
        if (angled) consume(TokenKind::Gt, "Expected '>' after ptr<type>");
        inner.isPtr=true; inner.addrSpace=addrSpace; return inner;
    }
    switch (peek().kind) {
        case TokenKind::TypeInt:    advance(); return {TypeKind::Int};
        case TokenKind::TypeFloat:  advance(); return {TypeKind::Float};
        case TokenKind::TypeBool:   advance(); return {TypeKind::Bool};
        case TokenKind::TypeString: advance(); return {TypeKind::String};
        case TokenKind::TypeVoid:   advance(); return {TypeKind::Void};
        case TokenKind::TypeVec2:
            if (appType != AppType::GUI) {
                std::cerr << "Error at line " << peek().line << ": 'vec2' type is only available in GUI applications (add 'app gui' at top)\n";
                throw std::runtime_error("vec2 requires GUI");
            }
            advance(); return {TypeKind::Vec2};
        case TokenKind::TypeVec3:
            if (appType != AppType::GUI) {
                std::cerr << "Error at line " << peek().line << ": 'vec3' type is only available in GUI applications (add 'app gui' at top)\n";
                throw std::runtime_error("vec3 requires GUI");
            }
            advance(); return {TypeKind::Vec3};
        case TokenKind::TypeColor:
            if (appType != AppType::GUI) {
                std::cerr << "Error at line " << peek().line << ": 'color' type is only available in GUI applications (add 'app gui' at top)\n";
                throw std::runtime_error("color requires GUI");
            }
            advance(); return {TypeKind::Color};
        case TokenKind::TypeEntity: advance(); return {TypeKind::Entity};
        case TokenKind::Ident: {
            std::string typeName = advance().text;
            Type t;
            t.kind = TypeKind::Struct;
            t.structName = typeName;
            return t;
        }
        default:
            throw std::runtime_error("Expected type at line " + std::to_string(peek().line));
    }
}

Param Parser::parseParam() {
    Param p;
    p.name = consume(TokenKind::Ident, "Expected parameter name").text;
    consume(TokenKind::Colon, "Expected ':' after parameter name");
    p.type = parseType();
    return p;
}

void Parser::skipToSyncPoint() {
    while (!check(TokenKind::Eof)) {
        if (check(TokenKind::Newline)) { advance(); return; }
        if (check(TokenKind::End)) return;
        if (check(TokenKind::Else)) return;
        if (check(TokenKind::Func)) return;
        advance();
    }
}

Block Parser::parseBlock(TokenKind terminator) {
    Block block;
    while (!check(TokenKind::Eof) && !check(terminator) && !check(TokenKind::Func)) {
        if (check(TokenKind::Else)) break;
        if (check(TokenKind::Newline)) { advance(); continue; }
        if (check(TokenKind::Struct)) {
            std::cerr << "Error at line " << peek().line << ": 'struct' cannot be declared inside a block" << std::endl;
            parseStruct();
            continue;
        }
        if (check(TokenKind::Class)) {
            std::cerr << "Error at line " << peek().line << ": 'class' cannot be declared inside a block" << std::endl;
            parseClass();
            continue;
        }
        if (check(TokenKind::Interface)) {
            std::cerr << "Error at line " << peek().line << ": 'interface' cannot be declared inside a block" << std::endl;
            parseInterface();
            continue;
        }
        if (check(TokenKind::Abstract)) {
            advance();
            std::cerr << "Error at line " << previous().line << ": 'abstract class' cannot be declared inside a block" << std::endl;
            parseClass(true);
            continue;
        }
        block.stmts.push_back(parseStatement());
    }
    return block;
}

std::unique_ptr<FunctionDecl> Parser::parseFunction() {
    auto func = std::make_unique<FunctionDecl>();
    func->line = peek().line;
    consume(TokenKind::Func, "Expected 'func'");
    func->name = consume(TokenKind::Ident, "Expected function name").text;
    consume(TokenKind::LParen, "Expected '('");

    if (!check(TokenKind::RParen)) {
        func->params.push_back(parseParam());
        while (match(TokenKind::Comma)) {
            func->params.push_back(parseParam());
        }
    }
    consume(TokenKind::RParen, "Expected ')'");

    if (match(TokenKind::Arrow)) {
        func->returnType = parseType();
    } else if (check(TokenKind::TypeInt) || check(TokenKind::TypeFloat) ||
               check(TokenKind::TypeBool) || check(TokenKind::TypeString) ||
               check(TokenKind::TypeVoid) || check(TokenKind::TypeVec2) ||
               check(TokenKind::TypeVec3) || check(TokenKind::TypeColor) ||
               check(TokenKind::TypeEntity) || check(TokenKind::Ident)) {
        func->returnType = parseType();
    } else {
        func->returnType = {TypeKind::Void};
    }

    if (check(TokenKind::Newline)) advance();
    else if (!check(TokenKind::Eof) && !check(TokenKind::End)) {
        consume(TokenKind::Newline, "Expected newline after function signature");
    }

    func->body = parseBlock(TokenKind::End);
    consume(TokenKind::End, "Expected 'end' after function body");
    if (check(TokenKind::Newline)) advance();
    return func;
}

std::unique_ptr<FunctionDecl> Parser::parseExternFunc() {
    consume(TokenKind::Extern, "Expected 'extern'");
    auto func = std::make_unique<FunctionDecl>();
    func->isExtern = true;
    consume(TokenKind::Func, "Expected 'func' after 'extern'");
    func->name = consume(TokenKind::Ident, "Expected function name").text;
    consume(TokenKind::LParen, "Expected '('");

    if (!check(TokenKind::RParen)) {
        func->params.push_back(parseParam());
        while (match(TokenKind::Comma)) {
            func->params.push_back(parseParam());
        }
    }
    consume(TokenKind::RParen, "Expected ')'");

    // Return type: accept "-> type" or just "type" directly
    if (match(TokenKind::Arrow)) {
        func->returnType = parseType();
    } else if (check(TokenKind::TypeInt) || check(TokenKind::TypeFloat) ||
               check(TokenKind::TypeBool) || check(TokenKind::TypeString) ||
               check(TokenKind::TypeVoid) || check(TokenKind::TypeVec2) ||
               check(TokenKind::TypeVec3) || check(TokenKind::TypeColor) ||
               check(TokenKind::TypeEntity) || check(TokenKind::Ident)) {
        func->returnType = parseType();
    } else {
        func->returnType = {TypeKind::Void};
    }

    // Optional: from "dll.dll"
    if (check(TokenKind::From)) {
        advance();
        Token dllTok = consume(TokenKind::StringLit, "Expected DLL name after 'from'");
        func->dllName = dllTok.text;
    }

    if (check(TokenKind::Newline)) advance();
    return func;
}

std::unique_ptr<StructDecl> Parser::parseStruct() {
    auto sd = std::make_unique<StructDecl>();
    consume(TokenKind::Struct, "Expected 'struct'");
    sd->name = consume(TokenKind::Ident, "Expected struct name").text;
    while (check(TokenKind::Newline)) advance();
    if (check(TokenKind::LBrace)) {
        advance();
        while (!check(TokenKind::Eof) && !check(TokenKind::RBrace)) {
            if (check(TokenKind::Newline)) { advance(); continue; }
            if (check(TokenKind::Var) || check(TokenKind::Let)) {
                advance();
                StructField f;
                f.name = consume(TokenKind::Ident, "Expected field name").text;
                consume(TokenKind::Colon, "Expected ':'");
                f.type = parseType();
                sd->fields.push_back(f);
                if (check(TokenKind::Newline)) advance();
            } else {
                std::cerr << "Error at line " << peek().line << ": expected 'var'/'let' keyword for struct field, or '}' to end struct" << std::endl;
                break;
            }
        }
        consume(TokenKind::RBrace, "Expected '}'");
    } else {
        while (!check(TokenKind::Eof) && !check(TokenKind::End)) {
            if (check(TokenKind::Newline)) { advance(); continue; }
    if (check(TokenKind::Var) || check(TokenKind::Let)) {
        advance();
        StructField f;
        f.name = consume(TokenKind::Ident, "Expected field name").text;
        consume(TokenKind::Colon, "Expected ':'");
        f.type = parseType();
        sd->fields.push_back(f);
                if (check(TokenKind::Newline)) advance();
            } else {
                break;
            }
        }
        consume(TokenKind::End, "Expected 'end' after struct");
    }
    if (check(TokenKind::Newline)) advance();
    return sd;
}

std::unique_ptr<ClassDecl> Parser::parseClass(bool isAbstract) {
    if (appType != AppType::Console && appType != AppType::GUI) {
        std::cerr << "Error at line " << peek().line << ": 'class' is only supported in console/gui applications (add 'app console' or 'app gui' at the top of the file)\n";
        fatalError = true;
        throw std::runtime_error("class requires console/gui app");
    }
    consume(TokenKind::Class, "Expected 'class'");
    auto cd = std::make_unique<ClassDecl>();
    cd->isAbstract = isAbstract;
    cd->name = consume(TokenKind::Ident, "Expected class name").text;
    if (match(TokenKind::Extends)) {
        cd->base = consume(TokenKind::Ident, "Expected base class name after 'extends'").text;
    }
    if (match(TokenKind::Implements)) {
        cd->interfaces.push_back(consume(TokenKind::Ident, "Expected interface name after 'implements'").text);
        while (match(TokenKind::Comma)) {
            cd->interfaces.push_back(consume(TokenKind::Ident, "Expected interface name").text);
        }
    }
    while (check(TokenKind::Newline)) advance();

    while (!check(TokenKind::Eof) && !check(TokenKind::End) && !check(TokenKind::RBrace)) {
        if (check(TokenKind::Newline)) { advance(); continue; }
        if (check(TokenKind::Var) || check(TokenKind::Let) || check(TokenKind::Const)) {
            advance();
            StructField f;
            f.name = consume(TokenKind::Ident, "Expected field name").text;
            consume(TokenKind::Colon, "Expected ':'");
            f.type = parseType();
            cd->fields.push_back(f);
            if (check(TokenKind::Newline)) advance();
        } else if (check(TokenKind::Func)) {
            ClassMethod m = parseClassMethod();
            if (check(TokenKind::Newline)) advance();
            m.body = parseBlock(TokenKind::End);
            consume(TokenKind::End, "Expected 'end' after method body");
            if (check(TokenKind::Newline)) advance();
            cd->methods.push_back(std::move(m));
        } else if (check(TokenKind::Abstract)) {
            advance();
            if (!check(TokenKind::Func))
                throw std::runtime_error("Expected 'func' after 'abstract' in class '" + cd->name + "'");
            ClassMethod m = parseClassMethod();
            m.isAbstract = true;
            if (check(TokenKind::Newline)) advance();
            cd->methods.push_back(std::move(m));
        } else {
            std::cerr << "Error at line " << peek().line << ": expected 'var' field, 'func' method, or 'end' in class '" << cd->name << "'\n";
            break;
        }
    }
    if (check(TokenKind::RBrace)) advance();
    else consume(TokenKind::End, "Expected 'end' after class");
    if (check(TokenKind::Newline)) advance();
    return cd;
}

ClassMethod Parser::parseClassMethod() {
    ClassMethod m;
    consume(TokenKind::Func, "Expected 'func'");
    m.name = consume(TokenKind::Ident, "Expected method name").text;
    consume(TokenKind::LParen, "Expected '('");
    if (!check(TokenKind::RParen)) {
        m.params.push_back(parseParam());
        while (match(TokenKind::Comma)) {
            m.params.push_back(parseParam());
        }
    }
    consume(TokenKind::RParen, "Expected ')'");
    if (match(TokenKind::Arrow)) {
        m.returnType = parseType();
    } else if (check(TokenKind::TypeInt) || check(TokenKind::TypeFloat) ||
               check(TokenKind::TypeBool) || check(TokenKind::TypeString) ||
               check(TokenKind::TypeVoid) || check(TokenKind::TypeVec2) ||
               check(TokenKind::TypeVec3) || check(TokenKind::TypeColor) ||
               check(TokenKind::TypeEntity) || check(TokenKind::Ident)) {
        m.returnType = parseType();
    } else {
        m.returnType = {TypeKind::Void};
    }
    return m;
}

std::unique_ptr<InterfaceDecl> Parser::parseInterface() {
    if (appType != AppType::Console && appType != AppType::GUI) {
        std::cerr << "Error at line " << peek().line << ": 'interface' is only supported in console/gui applications (add 'app console' or 'app gui' at the top of the file)\n";
        fatalError = true;
        throw std::runtime_error("interface requires console/gui app");
    }
    consume(TokenKind::Interface, "Expected 'interface'");
    auto id = std::make_unique<InterfaceDecl>();
    id->name = consume(TokenKind::Ident, "Expected interface name").text;
    while (check(TokenKind::Newline)) advance();

    while (!check(TokenKind::Eof) && !check(TokenKind::End) && !check(TokenKind::RBrace)) {
        if (check(TokenKind::Newline)) { advance(); continue; }
        if (check(TokenKind::Func)) {
            ClassMethod m = parseClassMethod();
            m.isAbstract = true;  // all interface methods are abstract
            id->methods.push_back(std::move(m));
            // interface methods have no body — the declaration ends here
            if (check(TokenKind::Newline)) advance();
            continue;
        } else if (check(TokenKind::Abstract)) {
            advance();
            if (!check(TokenKind::Func))
                throw std::runtime_error("Expected 'func' after 'abstract' in interface '" + id->name + "'");
            ClassMethod m = parseClassMethod();
            m.isAbstract = true;
            id->methods.push_back(std::move(m));
            if (check(TokenKind::Newline)) advance();
        } else {
            std::cerr << "Error at line " << peek().line << ": expected 'func' method or 'end' in interface '" << id->name << "'\n";
            break;
        }
    }
    if (check(TokenKind::RBrace)) advance();
    else consume(TokenKind::End, "Expected 'end' after interface");
    if (check(TokenKind::Newline)) advance();
    return id;
}

static TypeKind inferExprType(Expr* e) {
    if (auto n = dynamic_cast<NumberExpr*>(e)) { (void)n; return TypeKind::Int; }
    if (auto f = dynamic_cast<FloatExpr*>(e)) { (void)f; return TypeKind::Float; }
    if (auto s = dynamic_cast<StringExpr*>(e)) { (void)s; return TypeKind::String; }
    if (auto b = dynamic_cast<BinaryExpr*>(e))
        return (inferExprType(b->left.get()) == TypeKind::Float ||
                inferExprType(b->right.get()) == TypeKind::Float)
                   ? TypeKind::Float : TypeKind::Int;
    if (auto u = dynamic_cast<UnaryExpr*>(e)) return inferExprType(u->operand.get());
    if (auto c = dynamic_cast<CallExpr*>(e)) {
        // Known builtins whose return type is stable across targets/backends.
        // (User functions can be forward-referenced, and function bodies are
        // parsed sequentially, so their return types aren't resolvable here.)
        if (c->name == "peek32" || c->name == "peek16" || c->name == "peek8" ||
            c->name == "shader" || c->name == "shader_file") {
            return TypeKind::Int;
        }
        if (c->name == "http_download" || c->name == "http_download_ask" ||
            c->name == "http_download_speed" || c->name == "http_server" ||
            c->name == "http_download_ghreleases" ||
             c->name == "http_download_ask_gh" || c->name == "http_download_msiso" ||
             c->name == "http_download_winpe" ||
             c->name == "http_download_winpe_media" || c->name == "iso_extract" ||
            c->name == "http_download_iso" || c->name == "http_get" ||
            c->name == "http_last_error") {
            return TypeKind::Int;
        }
        static const char* kFloat[] = {
            "sqrt","abs","floor","ceil","trunc","neg",
            "sin","cos","tan","atan2","min","max","fmod","pow","itof" };
        for (auto k : kFloat) if (c->name == k) return TypeKind::Float;
        return TypeKind::Void;
    }
    return TypeKind::Void;
}

std::unique_ptr<VarDecl> Parser::parseVarDecl() {
    auto vd = std::make_unique<VarDecl>();
    vd->line = peek().line;
    if (!check(TokenKind::Var) && !check(TokenKind::Let) && !check(TokenKind::Const)) {
        std::cerr << "Error at line " << peek().line << ": Expected 'var', 'let' or 'const'" << std::endl;
        throw std::runtime_error("Expected 'var', 'let' or 'const'");
    }
    if (check(TokenKind::Const)) vd->isConst = true;
    advance();
    vd->name = consume(TokenKind::Ident, "Expected variable name").text;

    if (check(TokenKind::Colon)) {
        advance();
        if (check(TokenKind::LBrack)) {
            advance();
            int64_t sz = consume(TokenKind::Number, "Expected array size").intVal;
            if (sz <= 0 || sz > INT_MAX) {
                std::cerr << "Error at line " << previous().line << ": array size must be positive and fit in an int" << std::endl;
                throw std::runtime_error("Invalid array size");
            }
            vd->arraySize = (int)sz;
            consume(TokenKind::RBrack, "Expected ']'");
        }

        vd->type = parseType();
    } else if (check(TokenKind::Eq)) {
        // 'var x = expr' without an explicit type: infer it from the expression
        advance();
        vd->init = parseExpression();
        TypeKind tk = inferExprType(vd->init.get());
        if (tk != TypeKind::Void) {
            vd->type = {tk};
        } else {
            std::cerr << "Error at line " << previous().line
                      << ": cannot infer the type of 'var " << vd->name
                      << "' from this expression (add an explicit type, e.g. ': int')" << std::endl;
            throw std::runtime_error("Cannot infer variable type");
        }
    } else {
        consume(TokenKind::Colon, "Expected ':' or '=' after variable name");
    }

    // BUG FIX: The old code unconditionally did the `Eq` match below the
    // type-inference branch, silently overwriting the init from `var x = expr`
    // (parsed at line ~422). Now a trailing `=` is only accepted when a type
    // was explicitly declared, so the `var x = expr` initializer is preserved.
    if (vd->init == nullptr && match(TokenKind::Eq)) {
        vd->init = parseExpression();
    }

    if (check(TokenKind::Newline)) advance();
    return vd;
}

std::unique_ptr<Stmt> Parser::parseStatementImpl() {
    if (check(TokenKind::Var) || check(TokenKind::Let) || check(TokenKind::Const)) return parseVarDecl();
    if (check(TokenKind::If)) return parseIf();
    if (check(TokenKind::While)) return parseWhile();
    if (check(TokenKind::Loop)) return parseLoop();
    if (check(TokenKind::Switch)) return parseSwitch();
    if (check(TokenKind::Break)) { advance(); if (check(TokenKind::Newline)) advance(); return std::make_unique<BreakStmt>(); }
    if (check(TokenKind::Continue)) { advance(); if (check(TokenKind::Newline)) advance(); return std::make_unique<ContinueStmt>(); }
    if (check(TokenKind::For)) return parseFor();
    if (check(TokenKind::Asm) ||
        (check(TokenKind::Ident) && (peek().text == "asm32" || peek().text == "asm16"))) {
        int32_t asmWord = 0; // 0 = native target width; resolved per backend
        if (check(TokenKind::Ident) && peek().text == "asm32") asmWord = 32;
        else if (check(TokenKind::Ident) && peek().text == "asm16") asmWord = 16;
        advance();
        if (appType == AppType::WASM)
            throw std::runtime_error("asm is not supported for 'app wasm'");
        consume(TokenKind::LBrace, "Expected '{' after 'asm'");
        auto stmt = std::make_unique<AsmStmt>();
        stmt->wordSize = asmWord;
        while (!check(TokenKind::Eof) && !check(TokenKind::RBrace)) {
            if (check(TokenKind::Newline)) { advance(); continue; }
            AsmInstr instr;
            if (check(TokenKind::Ident) || check(TokenKind::TypeInt)) {
                instr.mnemonic = advance().text;
            } else {
                consume(TokenKind::Ident, "Expected mnemonic");
            }
            while (check(TokenKind::Dot) && peekNext().kind == TokenKind::Ident) {
                advance();
                instr.mnemonic += '.';
                instr.mnemonic += advance().text;
            }
            for (auto& c : instr.mnemonic) c = (char)tolower((unsigned char)c);
            {
                size_t w = instr.mnemonic.find(".w");
                if (w != std::string::npos && w == instr.mnemonic.size() - 2) instr.mnemonic.erase(w);
            }
            if (!check(TokenKind::Newline) && !check(TokenKind::RBrace)) {
                instr.op1 = readAsmOperand();
                if (check(TokenKind::Comma)) {
                    advance();
                    instr.op2 = readAsmOperand();
                }
                if (check(TokenKind::Comma)) {
                    advance();
                    instr.op3 = readAsmOperand();
                }
            }
            stmt->instrs.push_back(std::move(instr));
            if (check(TokenKind::Newline)) advance();
        }
        consume(TokenKind::RBrace, "Expected '}' after asm");
        if (check(TokenKind::Newline)) advance();
        return stmt;
    }
    if (check(TokenKind::Return)) {
        advance();
        auto stmt = std::make_unique<ReturnStmt>();
        if (!check(TokenKind::Newline) && !check(TokenKind::End) &&
            !check(TokenKind::Else) && !check(TokenKind::Eof)) {
            stmt->value = parseExpression();
        }
        if (check(TokenKind::Newline)) advance();
        return stmt;
    }
    if (check(TokenKind::Ident) && peekNext().kind == TokenKind::Eq) {
        auto stmt = std::make_unique<AssignStmt>();
        stmt->name = advance().text;
        advance();
        stmt->value = parseExpression();
        if (check(TokenKind::Newline)) advance();
        return stmt;
    }
    if (check(TokenKind::Ident) && peekNext().kind == TokenKind::LBrack) {
        auto stmt = std::make_unique<AssignStmt>();
        stmt->name = advance().text;
        advance();
        stmt->indexExpr = parseExpression();
        consume(TokenKind::RBrack, "Expected ']'");
        consume(TokenKind::Eq, "Expected '='");
        stmt->value = parseExpression();
        if (check(TokenKind::Newline)) advance();
        return stmt;
    }
    if (check(TokenKind::Ident) && peekNext().kind == TokenKind::Dot) {
        size_t scan = pos + 2;
        while (scan + 1 < tokens.size() &&
               tokens[scan].kind == TokenKind::Ident &&
               tokens[scan + 1].kind == TokenKind::Dot) {
            scan += 2;
        }
        if (scan < tokens.size() &&
            tokens[scan].kind == TokenKind::Ident &&
            scan + 1 < tokens.size() &&
            tokens[scan + 1].kind == TokenKind::Eq) {
            std::string firstName = advance().text;
            auto stmt = std::make_unique<AssignStmt>();
            stmt->name = firstName;
            while (check(TokenKind::Dot)) {
                advance();
                stmt->memberPath.push_back(
                    consume(TokenKind::Ident, "Expected field name").text);
            }
            consume(TokenKind::Eq, "Expected '='");
            stmt->value = parseExpression();
            if (check(TokenKind::Newline)) advance();
            return stmt;
        }
    }
    // *ptr = value (pointer assignment)
    if (check(TokenKind::Star)) {
        advance();
        auto stmt = std::make_unique<PtrAssignStmt>();
        stmt->ptr = parseUnary();
        consume(TokenKind::Eq, "Expected '=' after pointer expression");
        stmt->value = parseExpression();
        if (check(TokenKind::Newline)) advance();
        return stmt;
    }

    auto stmt = std::make_unique<ExprStmt>();
    stmt->expr = parseExpression();
    if (check(TokenKind::Eq)) {
        std::cerr << "Error at line " << peek().line
                  << ": '=' with unsupported left-hand side (expected simple name, "
                     "name[i], name.field... or *ptr)" << std::endl;
        throw std::runtime_error("Unsupported assignment target");
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(stmt->expr.get())) {
        if (bin->op == "%of") {
            std::cerr << "Error at line " << peek().line
                      << ": percent expression result must be used" << std::endl;
            throw std::runtime_error("Unused percent expression");
        }
    }
    // the result of a computation must be stored into a variable:
    // either an existing one (assignment) or a new one (var x = ...)
    if (dynamic_cast<BinaryExpr*>(stmt->expr.get()) ||
        dynamic_cast<UnaryExpr*>(stmt->expr.get()) ||
        dynamic_cast<NumberExpr*>(stmt->expr.get()) ||
        dynamic_cast<FloatExpr*>(stmt->expr.get())) {
        std::cerr << "Error at line " << peek().line
                  << ": the result of a computation must be assigned to a variable "
                     "(use 'x = expr' or 'var x = expr')" << std::endl;
        throw std::runtime_error("Unused computation result");
    }
    if (check(TokenKind::Newline)) advance();
    return stmt;
}

// Tag every statement (top-level and nested) with the source line it starts
// on, so the codegen backend can emit DWARF line tables / subprogram ranges.
std::unique_ptr<Stmt> Parser::parseStatement() {
    int stmtLine = peek().line;
    auto stmt = parseStatementImpl();
    if (stmt && stmtLine > 0) stmt->line = stmtLine;
    return stmt;
}

std::string Parser::readAsmOperand() {
    std::string result;
    auto collectUntil = [&](TokenKind closer) {
        std::vector<std::string> parts;
        parts.push_back(advance().text);
        int depth = 1;
        while (depth > 0) {
            if (check(TokenKind::Eof) || check(TokenKind::Newline)) break;
            if (check(TokenKind::LBrack)) depth++;
            if (check(closer)) depth--;
            parts.push_back(advance().text);
        }
        for (size_t i = 0; i < parts.size(); i++) {
            if (i) result += ' ';
            result += parts[i];
        }
    };
    if (check(TokenKind::LBrace)) { collectUntil(TokenKind::RBrace); return result; }
    if (check(TokenKind::LBrack)) { collectUntil(TokenKind::RBrack); return result; }
    if (check(TokenKind::Minus)) {
        result = advance().text;
        if (check(TokenKind::Number) || check(TokenKind::Ident)) result += advance().text;
        return result;
    }
    if (check(TokenKind::Ident) || check(TokenKind::Number)) {
        return advance().text;
    }
    return "";
}

std::unique_ptr<Stmt> Parser::parseIf() {
    advance();
    auto stmt = std::make_unique<IfStmt>();
    stmt->condition = parseExpression();
    if (check(TokenKind::Eq)) {
        std::cerr << "Error at line " << peek().line
                  << ": use '==' for comparison in if condition, not '='" << std::endl;
        throw std::runtime_error("Bad condition");
    }
    if (check(TokenKind::Newline)) advance();

    stmt->thenBlock = parseBlock(TokenKind::End);

    if (check(TokenKind::Else)) {
        advance();
        if (check(TokenKind::If)) {
            Block elseIfBlock;
            elseIfBlock.stmts.push_back(parseIf());
            stmt->elseBlock = std::move(elseIfBlock);
            return stmt;
        }
        if (check(TokenKind::Newline)) advance();
        stmt->elseBlock = parseBlock(TokenKind::End);
    }

    consume(TokenKind::End, "Expected 'end' after if");
    if (check(TokenKind::Newline)) advance();
    return stmt;
}

std::unique_ptr<Stmt> Parser::parseWhile() {
    advance();
    auto stmt = std::make_unique<WhileStmt>();
    stmt->condition = parseExpression();
    if (check(TokenKind::Eq)) {
        std::cerr << "Error at line " << peek().line
                  << ": use '==' for comparison in while condition, not '='" << std::endl;
        throw std::runtime_error("Bad condition");
    }
    if (check(TokenKind::Newline)) advance();

    stmt->body = parseBlock(TokenKind::End);
    consume(TokenKind::End, "Expected 'end' after while");
    if (check(TokenKind::Newline)) advance();
    return stmt;
}

std::unique_ptr<Stmt> Parser::parseLoop() {
    advance(); // 'loop'
    auto stmt = std::make_unique<LoopStmt>();
    if (check(TokenKind::Newline)) advance();
    stmt->body = parseBlock(TokenKind::End);
    consume(TokenKind::End, "Expected 'end' after loop");
    if (check(TokenKind::Newline)) advance();
    return stmt;
}

std::unique_ptr<Stmt> Parser::parseSwitch() {
    advance(); // 'switch'
    auto stmt = std::make_unique<SwitchStmt>();
    stmt->condition = parseExpression();
    if (check(TokenKind::Eq)) {
        std::cerr << "Error at line " << peek().line
                  << ": use '==' for comparison in switch condition, not '='" << std::endl;
        throw std::runtime_error("Bad condition");
    }
    if (check(TokenKind::Newline)) advance();
    while (check(TokenKind::Case)) {
        advance();
        SwitchCase sc;
        if (!check(TokenKind::Newline) && !check(TokenKind::Colon)) {
            sc.condition = parseExpression();
            if (check(TokenKind::Eq)) {
                std::cerr << "Error at line " << peek().line
                          << ": use '==' for comparison in case condition, not '='" << std::endl;
                throw std::runtime_error("Bad condition");
            }
        }
        if (check(TokenKind::Colon)) advance();
        if (check(TokenKind::Newline)) advance();
        while (!check(TokenKind::Eof) && !check(TokenKind::End) && !check(TokenKind::Case)) {
            if (check(TokenKind::Newline)) { advance(); continue; }
            sc.body.stmts.push_back(parseStatement());
        }
        stmt->cases.push_back(std::move(sc));
    }
    consume(TokenKind::End, "Expected 'end' after switch");
    if (check(TokenKind::Newline)) advance();
    return stmt;
}

std::unique_ptr<Stmt> Parser::parseFor() {
    advance(); // consume 'for'
    auto stmt = std::make_unique<ForStmt>();
    stmt->varName = consume(TokenKind::Ident, "Expected loop variable name").text;
    consume(TokenKind::Eq, "Expected '=' after loop variable");
    stmt->start = parseExpression();
    consume(TokenKind::Comma, "Expected ',' after start value");
    stmt->end = parseExpression();
    if (match(TokenKind::Comma)) {
        stmt->step = parseExpression();
    }
    if (check(TokenKind::Newline)) advance();
    stmt->body = parseBlock(TokenKind::End);
    consume(TokenKind::End, "Expected 'end' after for");
    if (check(TokenKind::Newline)) advance();
    return stmt;
}

std::unique_ptr<Expr> Parser::parseExpression() {
    return parseLogicalOr();
}

std::unique_ptr<Expr> Parser::parseLogicalOr() {
    auto left = parseLogicalAnd();
    while (check(TokenKind::PipePipe)) {
        auto op = advance();
        auto right = parseLogicalAnd();
        auto bin = std::make_unique<BinaryExpr>();
        bin->left = std::move(left);
        bin->op = op.text;
        bin->right = std::move(right);
        left = std::move(bin);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parseLogicalAnd() {
    auto left = parseComparison();
    while (check(TokenKind::AmpAmp)) {
        auto op = advance();
        auto right = parseComparison();
        auto bin = std::make_unique<BinaryExpr>();
        bin->left = std::move(left);
        bin->op = op.text;
        bin->right = std::move(right);
        left = std::move(bin);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parseBitOr() {
    auto left = parseBitXor();
    while (check(TokenKind::Pipe)) {
        auto op = advance();
        auto right = parseBitXor();
        auto bin = std::make_unique<BinaryExpr>();
        bin->left = std::move(left);
        bin->op = op.text;
        bin->right = std::move(right);
        left = std::move(bin);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parseBitXor() {
    auto left = parseBitAnd();
    while (check(TokenKind::Caret)) {
        auto op = advance();
        auto right = parseBitAnd();
        auto bin = std::make_unique<BinaryExpr>();
        bin->left = std::move(left);
        bin->op = op.text;
        bin->right = std::move(right);
        left = std::move(bin);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parseBitAnd() {
    auto left = parseShift();
    while (check(TokenKind::Amp)) {
        auto op = advance();
        auto right = parseShift();
        auto bin = std::make_unique<BinaryExpr>();
        bin->left = std::move(left);
        bin->op = op.text;
        bin->right = std::move(right);
        left = std::move(bin);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parseComparison() {
    auto left = parseBitOr();
    while (check(TokenKind::EqEq) || check(TokenKind::NotEq) ||
           check(TokenKind::Lt) || check(TokenKind::Gt) ||
           check(TokenKind::LtEq) || check(TokenKind::GtEq)) {
        auto op = advance();
        auto right = parseBitOr();
        auto bin = std::make_unique<BinaryExpr>();
        bin->left = std::move(left);
        bin->op = op.text;
        bin->right = std::move(right);
        left = std::move(bin);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parseShift() {
    auto left = parseTerm();
    while (check(TokenKind::ShiftLeft) || check(TokenKind::ShiftRight)) {
        auto op = advance();
        auto right = parseTerm();
        auto bin = std::make_unique<BinaryExpr>();
        bin->left = std::move(left);
        bin->op = op.text;
        bin->right = std::move(right);
        left = std::move(bin);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parseTerm() {
    auto left = parseFactor();
    while (check(TokenKind::Plus) || check(TokenKind::Minus)) {
        auto op = advance();
        auto right = parseFactor();
        auto bin = std::make_unique<BinaryExpr>();
        bin->left = std::move(left);
        bin->op = op.text;
        bin->right = std::move(right);
        left = std::move(bin);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parseFactor() {
    auto left = parseUnary();
    while (check(TokenKind::Star) || check(TokenKind::Slash) || check(TokenKind::SlashSlash) || check(TokenKind::Percent)) {
        auto op = advance();
        auto right = parseUnary();
        auto bin = std::make_unique<BinaryExpr>();
        bin->left = std::move(left);
        bin->op = op.text;
        bin->right = std::move(right);
        left = std::move(bin);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parseUnary() {
    if (check(TokenKind::Star)) { advance(); auto d = std::make_unique<DerefExpr>(); d->ptr = parseUnary(); return d; }
    if (check(TokenKind::Amp)) { advance(); auto a = std::make_unique<AddressOfExpr>(); a->name = consume(TokenKind::Ident, "Expected var").text; return a; }
    if (check(TokenKind::Bang)) { advance(); auto u = std::make_unique<UnaryExpr>(); u->op = "!"; u->operand = parseUnary(); return u; }
    if (check(TokenKind::Tilde)) { advance(); auto u = std::make_unique<UnaryExpr>(); u->op = "~"; u->operand = parseUnary(); return u; }
    if (check(TokenKind::Minus)) {
        advance();
        if (check(TokenKind::Number)) { auto n = std::make_unique<NumberExpr>(); n->value = -advance().intVal; return n; }
        if (check(TokenKind::FloatLit)) { auto f = std::make_unique<FloatExpr>(); f->value = -advance().floatVal; return f; }
        auto u = std::make_unique<UnaryExpr>(); u->op = "-"; u->operand = parseUnary(); return u;
    }
    if (check(TokenKind::Plus)) { advance(); return parseUnary(); }
    return parsePrimary();
}

std::unique_ptr<Expr> Parser::parsePrimary() {
    std::unique_ptr<Expr> expr;
    if (check(TokenKind::PercentLit)) {
        int64_t pct = advance().intVal;
        if (pct < 1 || pct > 100) {
            std::cerr << "Error at line " << previous().line
                      << ": percent must be between 1 and 100" << std::endl;
            throw std::runtime_error("Invalid percent");
        }
        match(TokenKind::Eq); // '=' is optional: 50% = 20 and 50% 20 both work
        auto bin = std::make_unique<BinaryExpr>();
        bin->op = "%of";
        auto left = std::make_unique<NumberExpr>();
        left->value = pct;
        bin->left = std::move(left);
        bin->right = parseShift();
        return bin;
    }
    if (check(TokenKind::Number)) {
        auto n = std::make_unique<NumberExpr>();
        n->value = advance().intVal;
        expr = std::move(n);
    } else if (check(TokenKind::FloatLit)) {
        auto f = std::make_unique<FloatExpr>();
        f->value = advance().floatVal;
        expr = std::move(f);
    } else if (check(TokenKind::StringLit)) {
        auto s = std::make_unique<StringExpr>();
        s->value = advance().text;
        expr = std::move(s);
    } else if (check(TokenKind::Interrupt)) {
        expr = parseCallOrIdent();
    } else if (check(TokenKind::LParen)) {
        advance();
        expr = parseExpression();
        consume(TokenKind::RParen, "Expected ')'");
    } else if (check(TokenKind::Ident)) {
        std::string idName = peek().text;
        if (idName == "Red" || idName == "Green" || idName == "Blue" ||
            idName == "White" || idName == "Black" || idName == "Yellow" ||
            idName == "Cyan" || idName == "Magenta" || idName == "Gray") {
            advance();
            uint32_t c;
            if (idName == "Red")     c = 0xFFFF0000;
            else if (idName == "Green")  c = 0xFF00FF00;
            else if (idName == "Blue")   c = 0xFF0000FF;
            else if (idName == "White")  c = 0xFFFFFFFF;
            else if (idName == "Black")  c = 0xFF000000;
            else if (idName == "Yellow") c = 0xFFFFFF00;
            else if (idName == "Cyan")   c = 0xFF00FFFF;
            else if (idName == "Magenta")c = 0xFFFF00FF;
            else                         c = 0xFF808080;
            auto n = std::make_unique<NumberExpr>();
            n->value = c;
            expr = std::move(n);
        } else {
            expr = parseCallOrIdent();
        }
    } else if (check(TokenKind::True)) {
        advance();
        auto n = std::make_unique<NumberExpr>();
        n->value = 1;
        expr = std::move(n);
    } else if (check(TokenKind::False)) {
        advance();
        auto n = std::make_unique<NumberExpr>();
        n->value = 0;
        expr = std::move(n);
    } else if (check(TokenKind::TypeVec2) || check(TokenKind::TypeVec3) || check(TokenKind::TypeColor)) {
        if (appType != AppType::GUI) {
            std::cerr << "Error at line " << peek().line << ": '" << peek().text << "' type is only available in GUI applications (add 'app gui' at top)\n";
            throw std::runtime_error(std::string(peek().text) + " requires GUI");
        }
        std::string typeName = advance().text;
        if (check(TokenKind::LParen)) {
            advance();
            auto call = std::make_unique<CallExpr>();
            call->name = typeName;
            while (check(TokenKind::Newline)) advance();
            if (!check(TokenKind::RParen)) {
                call->args.push_back(parseExpression());
                while (match(TokenKind::Comma)) {
                    while (check(TokenKind::Newline)) advance();
                    call->args.push_back(parseExpression());
                }
            }
            while (check(TokenKind::Newline)) advance();
            consume(TokenKind::RParen, "Expected ')'");
            expr = std::move(call);
        } else {
            auto id = std::make_unique<IdentExpr>();
            id->name = typeName;
            expr = std::move(id);
        }
    } else {
        throw std::runtime_error("Unexpected token '" + peek().text + "' at line " + std::to_string(peek().line));
    }

    while (check(TokenKind::LBrack) || check(TokenKind::Dot)) {
        if (check(TokenKind::LBrack)) {
            advance();
            auto arr = std::make_unique<ArrayAccessExpr>();
            arr->array = std::move(expr);
            arr->index = parseExpression();
            consume(TokenKind::RBrack, "Expected ']'");
            expr = std::move(arr);
        } else {
            advance();
            auto memb = std::make_unique<MemberExpr>();
            memb->object = std::move(expr);
            memb->member = consume(TokenKind::Ident, "Expected field name after '.'").text;
            if (check(TokenKind::LParen)) {
                advance();
                auto call = std::make_unique<CallExpr>();
                call->name = memb->member;
                call->receiver = std::move(memb);
                if (!check(TokenKind::RParen)) {
                    call->args.push_back(parseExpression());
                    while (match(TokenKind::Comma)) {
                        call->args.push_back(parseExpression());
                    }
                }
                consume(TokenKind::RParen, "Expected ')'");
                expr = std::move(call);
            } else {
                expr = std::move(memb);
            }
        }
    }

    return expr;
}

std::unique_ptr<Expr> Parser::parseCallOrIdent() {
    std::string name;
    if (check(TokenKind::Ident) || check(TokenKind::Interrupt)) {
        Token nameTok = advance();
        name = nameTok.text;
        // Namespaced builtin names written without spaces (e.g. Create:File):
        // merge "Ident:Ident" into a single name. Both sides must be adjacent
        // so type annotations ("var x: int") and switch cases ("case x: ...")
        // are not affected.
        if (check(TokenKind::Colon) && peekNext().kind == TokenKind::Ident) {
            Token colonTok = peek();
            Token afterTok = peekNext();
            if (colonTok.col == nameTok.col + (int)nameTok.text.size() &&
                afterTok.col == colonTok.col + 1) {
                advance();
                name += ":" + advance().text;
            }
        }
    } else {
        // Handle case where it's not an ident (shouldn't happen for function calls)
        name = advance().text;
    }
    if (check(TokenKind::LParen)) {
        advance();
        auto call = std::make_unique<CallExpr>();
        call->name = name;
        while (check(TokenKind::Newline)) advance();
        if (!check(TokenKind::RParen)) {
            call->args.push_back(parseExpression());
            while (match(TokenKind::Comma)) {
                while (check(TokenKind::Newline)) advance();
                call->args.push_back(parseExpression());
            }
        }
        while (check(TokenKind::Newline)) advance();
        consume(TokenKind::RParen, "Expected ')'");
        return parseDotChain(std::move(call));
    }
    auto id = std::make_unique<IdentExpr>();
    id->name = name;
    return parseDotChain(std::move(id));
}

std::unique_ptr<Expr> Parser::parseDotChain(std::unique_ptr<Expr> left) {
    while (check(TokenKind::Dot)) {
        advance();
        auto memb = std::make_unique<MemberExpr>();
        memb->object = std::move(left);
        memb->member = consume(TokenKind::Ident, "Expected field name after '.'").text;
        if (check(TokenKind::LParen)) {
            advance();
            auto call = std::make_unique<CallExpr>();
            call->name = memb->member;
            call->receiver = std::move(memb);
            while (check(TokenKind::Newline)) advance();
            if (!check(TokenKind::RParen)) {
                call->args.push_back(parseExpression());
                while (match(TokenKind::Comma)) {
                    while (check(TokenKind::Newline)) advance();
                    call->args.push_back(parseExpression());
                }
            }
            while (check(TokenKind::Newline)) advance();
            consume(TokenKind::RParen, "Expected ')'");
            left = std::move(call);
        } else {
            left = std::move(memb);
        }
    }
    return left;
}

void Parser::checkDriverModifier(Program& prog) {
#ifndef _WIN32
    prog.koDriver = true;
#else
    std::cerr << "Error: 'app console/linux driver' is only supported on Linux (kernel modules)\n";
    throw std::runtime_error("Driver mode requires Linux");
#endif
}

void Parser::parseAppType(Program& prog) {
    consume(TokenKind::App, "Expected 'app' directive at top of file");
    if (check(TokenKind::Ident)) {
        std::string type = advance().text;
        if (type == "gui") {
            prog.appType = AppType::GUI;
            prog.renderType = RenderType::Software;  // default
            prog.appCategory = AppCategory::Tool;    // overwritten if 'tool'/'game' keyword present
            // Optional keywords in any order: 'sr'/'dx'/'vulkan' (render type), 'tool'/'game' (category)
            bool sawCategory = false;
            while (check(TokenKind::Ident)) {
                std::string kw = peek().text;
                if (kw == "sr") {
                    advance();
                    prog.renderType = RenderType::Software;
                } else if (kw == "dx11" || kw == "dx") {
                    advance();
                    prog.renderType = RenderType::DX11;
                } else if (kw == "vulkan") {
                    advance();
                    prog.renderType = RenderType::Vulkan;
                } else if (kw == "tool") {
                    advance();
                    prog.appCategory = AppCategory::Tool;
                    sawCategory = true;
                } else if (kw == "game") {
                    advance();
                    prog.appCategory = AppCategory::Game;
                    sawCategory = true;
                } else {
                    break;
                }
            }
            if (!sawCategory) {
                std::cerr << "Error at line " << previous().line << ": 'app gui' requires a category: use 'app gui tool' or 'app gui game'\n";
                throw std::runtime_error("Missing app gui category");
            }
            // Render backend implies the target OS:
            //   dx/dx11 -> Windows (PE); vulkan/sr -> Linux;
            //   sr (software) with no explicit system -> current host OS.
            if (prog.renderType == RenderType::DX11) {
                prog.appType = AppType::GUI;   // Windows GUI
            } else if (prog.renderType == RenderType::Vulkan) {
                prog.appType = AppType::Linux; // Linux (real Vulkan)
            } else {
                // Software renderer, no system given -> current host.
#ifdef _WIN32
                prog.appType = AppType::GUI;
#else
                prog.appType = AppType::Linux;
#endif
            }
        } else if (type == "console") {
            // No render backend specified: target the current host OS.
#ifdef _WIN32
            prog.appType = AppType::Console;
#else
            prog.appType = AppType::Linux;
#endif
            prog.renderType = RenderType::Software;
            prog.appCategory = AppCategory::Tool;
            // 'app console driver' -> Linux kernel module (.ko)
            if (peek().text == "driver") {
                advance();
                checkDriverModifier(prog);
            }
        } else if (type == "linux") {
            prog.appType = AppType::Linux;
            prog.renderType = RenderType::Software;
            prog.appCategory = AppCategory::Tool;
            // 'app linux driver' -> Linux kernel module (.ko)
            if (peek().text == "driver") {
                advance();
                checkDriverModifier(prog);
            }
        } else if (type == "efi") {
            prog.appType = AppType::EFI;
        } else if (type == "bios") {
            prog.appType = AppType::BIOS;
        } else if (type == "bare") {
            prog.appType = AppType::Bare;
        } else if (type == "stm32") {
            prog.appType = AppType::STM32;
        } else if (type == "arm64") {
            prog.appType = AppType::ARM64;
        } else if (type == "wasm") {
            prog.appType = AppType::WASM;
            prog.appCategory = AppCategory::Tool;
        } else {
            std::cerr << "Error at line " << previous().line << ": expected 'gui', 'console', 'efi', 'bios', 'bare', 'stm32', 'arm64', or 'wasm' after 'app', got '" << type << "'\n";
            throw std::runtime_error("Invalid app type");
        }
    } else {
        std::cerr << "Error at line " << peek().line << ": expected 'gui', 'console', 'efi', 'bios', 'bare', 'stm32', 'arm64', or 'wasm' after 'app'\n";
        throw std::runtime_error("Expected app type");
    }
    if (check(TokenKind::Newline)) advance();

    // =============================================================
    // NEW: Parse optional kernel_mode: independent/dependent
    // =============================================================
    while (check(TokenKind::Newline)) advance();
    
    if (check(TokenKind::Ident) && peek().text == "kernel_mode") {
        advance();
        
        // Expect colon
        if (check(TokenKind::Colon)) {
            advance();
        } else {
            std::cerr << "Error at line " << peek().line << ": expected ':' after 'kernel_mode'\n";
            throw std::runtime_error("Expected ':' after kernel_mode");
        }
        
        // Expect independent or dependent
        if (check(TokenKind::Ident)) {
            std::string km = advance().text;
            if (km == "independent") {
                prog.kernelMode = KernelMode::Independent;
                prog.kernelModeExplicit = true;
            } else if (km == "dependent") {
                prog.kernelMode = KernelMode::Dependent;
                prog.kernelModeExplicit = true;
            } else {
                std::cerr << "Error at line " << previous().line << ": expected 'independent' or 'dependent' after 'kernel_mode:', got '" << km << "'\n";
                throw std::runtime_error("Invalid kernel_mode");
            }
        } else {
            std::cerr << "Error at line " << peek().line << ": expected 'independent' or 'dependent'\n";
            throw std::runtime_error("Expected kernel_mode value");
        }
        
        if (check(TokenKind::Newline)) advance();
    }

    // =============================================================
    // Optional boot_services: manual — opt-in only. When present, the EFI
    // entry stub does NOT run its automatic GetMemoryMap/ExitBootServices
    // sequence; the program performs EBS itself (after any pre-EBS work
    // such as snapshotting the boot medium's file system). Anything other
    // value than 'manual' is rejected so typos never silently change boot
    // semantics. Absence of the directive = historical behavior.
    // =============================================================
    while (check(TokenKind::Newline)) advance();
    if (check(TokenKind::Ident) && peek().text == "boot_services") {
        advance();
        if (check(TokenKind::Colon)) advance();
        else throw std::runtime_error("Expected ':' after boot_services");
        if (check(TokenKind::Ident)) {
            std::string bs = advance().text;
            if (bs == "manual") {
                prog.bootServicesManual = true;
            } else {
                std::cerr << "Error at line " << previous().line
                          << ": expected 'manual' after 'boot_services:', got '" << bs << "'\n";
                throw std::runtime_error("Invalid boot_services value");
            }
        } else {
            throw std::runtime_error("Expected boot_services value");
        }
        if (check(TokenKind::Newline)) advance();
    }

    // Optional asm_word_size: 64|32|16 — sets the default operand width for
    // 'asm {}' blocks. 'asm_word_size: 16' switches the whole program to a
    // pure 16-bit real-mode boot image (real16).
    while (check(TokenKind::Newline)) advance();
    if (check(TokenKind::Ident) && peek().text == "asm_word_size") {
        advance();
        if (check(TokenKind::Colon)) advance();
        else throw std::runtime_error("Expected ':' after asm_word_size");
        if (check(TokenKind::Number)) {
            int64_t ws = advance().intVal;
            if (ws == 64) { prog.asmWordSize = 64; }
            else if (ws == 32) { prog.asmWordSize = 32; }
            else if (ws == 16) { prog.asmWordSize = 16; prog.real16 = true; }
            else {
                std::cerr << "Error: asm_word_size must be 64, 32 or 16" << std::endl;
                throw std::runtime_error("Invalid asm_word_size");
            }
        } else {
            std::cerr << "Error at line " << peek().line << ": expected 64, 32 or 16 after 'asm_word_size:'" << std::endl;
            throw std::runtime_error("Expected asm_word_size value");
        }
        if (check(TokenKind::Newline)) advance();
    }

    // =============================================================
    // Optional kernel-module (.ko) metadata directives (only emitted when
    // building a driver). Turned into .modinfo entries by codegen_ko.cpp:
    //   module_description: "desc..."   ->  description=desc...
    //   module_author:      "author"    ->  author=author
    //   module_version:     "1.2.3"     ->  version=1.2.3
    // =============================================================
    while (check(TokenKind::Newline)) advance();
    while (check(TokenKind::Ident)) {
        std::string dir = peek().text;
        if (dir != "module_description" && dir != "module_author" && dir != "module_version") break;
        advance();
        if (check(TokenKind::Colon)) advance();
        else throw std::runtime_error("Expected ':' after '" + dir + "'");
        std::string val;
        if (check(TokenKind::StringLit)) {
            val = advance().text;
        } else if (check(TokenKind::Ident)) {
            val = advance().text;
        } else {
            throw std::runtime_error("Expected string value after '" + dir + ":'");
        }
        if (dir == "module_description")       prog.moduleDescription = val;
        else if (dir == "module_author")       prog.moduleAuthor = val;
        else if (dir == "module_version")      prog.moduleVersion = val;
        if (check(TokenKind::Newline)) advance();
    }

    // =============================================================
    // Optional STM32 directives (only meaningful for 'app stm32'):
    //   mcu: stm32f103 | stm32f407   chip family (flash/RAM map, GPIO layout)
    //   led_pin: PC13                on-board LED driven by print()
    //   led_active_low: true         LED turns on with LOW level (Blue Pill PC13)
    //   sysclk: 72000000             HCLK in Hz used to calibrate delay_ms()
    //   systick: 72000000            SysTick clock in Hz (micros/millis/delay_us;
    //                                must be sysclk or sysclk/8; 0 = HCLK)
    //   sram_kb: 8                   SRAM size in KB (QEMU stm32vldiscovery = 8)
    // =============================================================
    while (check(TokenKind::Newline)) advance();
    while (check(TokenKind::Ident)) {
        std::string dir = peek().text;
        if (dir != "mcu" && dir != "led_pin" && dir != "led_active_low" && dir != "sysclk" && dir != "sram_kb" && dir != "systick") break;
        advance();
        if (check(TokenKind::Colon)) advance();
        else throw std::runtime_error("Expected ':' after '" + dir + "'");
        if (dir == "mcu") {
            if (check(TokenKind::Ident)) {
                prog.mcu = advance().text;
            } else {
                throw std::runtime_error("Expected mcu name (e.g. stm32f103)");
            }
        } else if (dir == "led_pin") {
            if (check(TokenKind::Ident)) {
                prog.ledPin = advance().text;
            } else if (check(TokenKind::StringLit)) {
                prog.ledPin = advance().text;
            } else {
                throw std::runtime_error("Expected LED pin (e.g. PC13 or PA5)");
            }
        } else if (dir == "led_active_low") {
            if (check(TokenKind::True)) {
                prog.ledActiveLow = true;
                advance();
            } else if (check(TokenKind::False)) {
                prog.ledActiveLow = false;
                advance();
            } else {
                throw std::runtime_error("Expected true or false after led_active_low:");
            }
        } else if (dir == "sysclk") {
            if (check(TokenKind::Number)) {
                prog.sysclkHz = (uint32_t)advance().intVal;
            } else {
                throw std::runtime_error("Expected sysclk value in Hz");
            }
        } else if (dir == "systick") {
            if (check(TokenKind::Number)) {
                prog.systickHz = (uint32_t)advance().intVal;
            } else {
                throw std::runtime_error("Expected systick value in Hz");
            }
        } else if (dir == "sram_kb") {
            if (check(TokenKind::Number)) {
                prog.sramKb = (uint32_t)advance().intVal;
            } else {
                throw std::runtime_error("Expected sram_kb value in KB");
            }
        }
        if (check(TokenKind::Newline)) advance();
    }

    // =============================================================
    // Optional ARM64 directives (only meaningful for 'app arm64'):
    //   chip: cortex-a53     chip model (informational for QEMU)
    //   clock_hz: 62500000   clock frequency in Hz used by delay_ms()
    // =============================================================
    while (check(TokenKind::Newline)) advance();
    while (check(TokenKind::Ident)) {
        std::string dir = peek().text;
        if (dir != "chip" && dir != "clock_hz") break;
        advance();
        if (check(TokenKind::Colon)) advance();
        else throw std::runtime_error("Expected ':' after '" + dir + "'");
        if (dir == "chip") {
            if (check(TokenKind::Ident) || check(TokenKind::Virt) ||
                check(TokenKind::Phys) || check(TokenKind::Number)) {
                std::string chipName = advance().text;
                while (check(TokenKind::Minus)) {
                    advance();
                    if (!check(TokenKind::Ident) && !check(TokenKind::Virt) &&
                        !check(TokenKind::Phys) && !check(TokenKind::Number))
                        throw std::runtime_error("Expected chip name part after '-' (e.g. cortex-a53)");
                    chipName += "-" + advance().text;
                }
                prog.arm64Chip = chipName;
            } else {
                throw std::runtime_error("Expected chip name (e.g. cortex-a53)");
            }
        } else if (dir == "clock_hz") {
            if (check(TokenKind::Number)) {
                prog.arm64ClockHz = (uint64_t)advance().intVal;
            } else {
                throw std::runtime_error("Expected clock_hz value in Hz");
            }
        }
        if (check(TokenKind::Newline)) advance();
    }

    // If the user didn't specify kernel_mode explicitly, pick a sensible default:
    //   app efi / app bios  -> Dependent  (the firmware services are available)
    //   app bare            -> Independent (the kernel owns the hardware itself)
    if (!prog.kernelModeExplicit) {
        if (prog.appType == AppType::Bare)
            prog.kernelMode = KernelMode::Independent;
        else
            prog.kernelMode = KernelMode::Dependent;
    }
}

// ====================================================================
// Class lowering (basic OOP, console apps only)
//
// After parsing, every `class Foo` is turned into:
//   * a StructDecl (its fields) so codegen lays it out like a struct, and
//   * one FunctionDecl per method, named "Foo::<method>", whose first
//     parameter is `this: ptr<Foo>` (object passed by reference).
// A call `obj.method(a, b)` where `obj` is a class variable is rewritten
// to `Foo::method(&obj, a, b)` (or `Foo::method(obj, ...)` when `obj`
// already is a pointer, e.g. `this`).
// ====================================================================

namespace {

using ClassTypeMap = std::unordered_map<std::string, Type>;

struct LowerCtx {
    Program& prog;
    std::vector<ClassTypeMap> scopes;
    // className -> { methodName -> mangled function name }
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> classMethods;
    // className -> field names (used to rewrite bare field names inside methods)
    std::unordered_map<std::string, std::vector<std::string>> classFields;
    // mangled function name ("Class::method") -> class name
    std::unordered_map<std::string, std::string> fnClass;
    // fields of the method currently being lowered (nullptr for free functions)
    const std::vector<std::string>* currentFields = nullptr;
    // class name of the method currently being lowered ("" for free functions)
    std::string currentClass;
    // class name -> ClassDecl (for inheritance / super resolution)
    std::unordered_map<std::string, ClassDecl*> classByName;
    // class name -> all classes in its inheritance subtree [self..descendants]
    std::unordered_map<std::string, std::vector<std::string>> subtreeOf;
    // interface name -> InterfaceDecl
    std::unordered_map<std::string, InterfaceDecl*> interfaceByName;
    // interface name -> classes implementing it (incl. subclasses of implementors)
    std::unordered_map<std::string, std::vector<std::string>> implementors;
    // mangled names ("Class::method") of abstract methods (no function exists)
    std::unordered_set<std::string> abstractImpls;

    bool isInterface(const std::string& name) const {
        return interfaceByName.count(name) != 0;
    }

    bool isField(const std::string& name) const {
        return currentFields &&
               std::find(currentFields->begin(), currentFields->end(), name) != currentFields->end();
    }

    bool isMethod(const std::string& className, const std::string& name) const {
        auto it = classMethods.find(className);
        return it != classMethods.end() && it->second.count(name) != 0;
    }

    const Type* findVarType(const std::string& name) const {
        for (auto it = scopes.rbegin(); it != scopes.rend(); ++it) {
            auto f = it->find(name);
            if (f != it->end()) return &f->second;
        }
        for (auto& g : prog.globals) {
            if (g->name == name) return &g->type;
        }
        return nullptr;
    }

    // type of a bare field of the method currently being lowered
    // (class fields are not visible to findVarType; the merged layout of the
    // class was pushed into prog.structs during lowering)
    const Type* findFieldType(const std::string& name) const {
        for (auto& s : prog.structs) {
            if (s->name != currentClass) continue;
            for (auto& f : s->fields) {
                if (f.name == name) return &f.type;
            }
        }
        return nullptr;
    }
};

void lowerExpr(LowerCtx& ctx, std::unique_ptr<Expr>& e);
void lowerBlock(LowerCtx& ctx, Block& b);

void resolveVirtualCall(LowerCtx& ctx, CallExpr* call,
                        const std::string& staticClass, const std::string& method,
                        const std::string& mangledImpl, bool isSuper) {
    if (isSuper) {
        call->isVirtual = false;
        call->name = mangledImpl;
        return;
    }
    if (ctx.isInterface(staticClass)) {
        // Interface dispatch: every class that implements the interface is a
        // potential runtime target, so the vtable covers all implementors and
        // the LAST one becomes the fall-through default (its class id simply
        // never gets compared). Abstract impls (no function body) are dropped.
        std::vector<std::pair<int, std::string>> entries;
        auto impIt = ctx.implementors.find(staticClass);
        if (impIt != ctx.implementors.end()) {
            for (auto& X : impIt->second) {
                auto xit = ctx.classMethods.find(X);
                if (xit == ctx.classMethods.end()) continue;
                auto xm = xit->second.find(method);
                if (xm == xit->second.end()) continue;
                if (ctx.abstractImpls.count(xm->second)) continue;
                entries.push_back({ctx.prog.classIDs[X], xm->second});
            }
        }
        if (entries.empty())
            throw std::runtime_error("Interface '" + staticClass + "' method '" + method +
                                     "' has no concrete implementation");
        call->name = entries.back().second;
        if (entries.size() >= 2) {
            call->isVirtual = true;
            call->vtable = std::move(entries);
        }
        return;
    }
    std::unordered_set<std::string> impls;
    std::vector<std::pair<int, std::string>> entries;
    auto stIt = ctx.subtreeOf.find(staticClass);
    if (stIt != ctx.subtreeOf.end()) {
        for (auto& X : stIt->second) {
            auto xit = ctx.classMethods.find(X);
            if (xit == ctx.classMethods.end()) continue;
            auto xm = xit->second.find(method);
            if (xm == xit->second.end()) continue;
            if (ctx.abstractImpls.count(xm->second)) continue;
            entries.push_back({ctx.prog.classIDs[X], xm->second});
            impls.insert(xm->second);
        }
    }
    if (entries.empty())
        throw std::runtime_error("Method '" + method + "' has no concrete implementation in the class hierarchy of '" +
                                 staticClass + "'");
    call->name = mangledImpl;
    if (impls.size() > 1) {
        // move the static-type impl to the end -> becomes the fall-through default
        for (size_t i = 0; i < entries.size(); i++) {
            if (entries[i].second == mangledImpl) {
                std::swap(entries[i], entries[entries.size() - 1]);
                break;
            }
        }
        call->isVirtual = true;
        call->vtable = std::move(entries);
    } else {
        call->name = entries.back().second;
    }
}

void lowerExpr(LowerCtx& ctx, std::unique_ptr<Expr>& e);
void lowerBlock(LowerCtx& ctx, Block& b);

void lowerStmt(LowerCtx& ctx, Stmt* s) {
    if (auto vd = dynamic_cast<VarDecl*>(s)) {
        if (vd->init) lowerExpr(ctx, vd->init);
        if (vd->type.kind == TypeKind::Struct && !vd->type.isPtr) {
            auto abIt = ctx.classByName.find(vd->type.structName);
            if (abIt != ctx.classByName.end() && abIt->second->isAbstract)
                throw std::runtime_error("Cannot instantiate abstract class '" + vd->type.structName +
                                         "' (local variable)");
        }
        if (vd->type.kind == TypeKind::Struct && !vd->type.isPtr && ctx.isInterface(vd->type.structName))
            vd->type.isPtr = true;
        if (!ctx.scopes.empty()) ctx.scopes.back()[vd->name] = vd->type;
        return;
    }
    if (auto ret = dynamic_cast<ReturnStmt*>(s)) {
        if (ret->value) lowerExpr(ctx, ret->value);
        return;
    }
    if (auto ex = dynamic_cast<ExprStmt*>(s)) {
        lowerExpr(ctx, ex->expr);
        return;
    }
    if (auto as = dynamic_cast<AssignStmt*>(s)) {
        // Guard: assigning a value of one class type into another class-typed
        // variable by value would silently overwrite the `__classid` slot and
        // corrupt dispatch. Use ptr<Base> for polymorphic assignment instead.
        if (!as->indexExpr && as->memberPath.empty()) {
            auto tv = ctx.findVarType(as->name);
            if (tv && tv->kind == TypeKind::Struct && !tv->isPtr &&
                ctx.prog.classIDs.count(tv->structName)) {
                if (auto rhsId = dynamic_cast<IdentExpr*>(as->value.get())) {
                    auto sv = ctx.findVarType(rhsId->name);
                    if (sv && sv->kind == TypeKind::Struct && !sv->isPtr &&
                        sv->structName != tv->structName && ctx.prog.classIDs.count(sv->structName)) {
                        throw std::runtime_error(
                            "Cannot assign '" + rhsId->name + "' (" + sv->structName +
                            ") to '" + as->name + "' (" + tv->structName +
                            ") by value; use ptr<" + tv->structName + "> for polymorphic assignment");
                    }
                }
            }
        }
        // Inside a method, `field = v` (and `field.f = v`) where `field` is a
        // member of the current class and not a local variable becomes a
        // member write through `this`.
        if (!as->indexExpr && !as->memberPath.empty() && ctx.isField(as->name) && !ctx.findVarType(as->name)) {
            as->memberPath.insert(as->memberPath.begin(), as->name);
            as->name = "this";
        } else if (!as->indexExpr && as->memberPath.empty() && ctx.isField(as->name) && !ctx.findVarType(as->name)) {
            as->memberPath.push_back(as->name);
            as->name = "this";
        }
        if (as->indexExpr) lowerExpr(ctx, as->indexExpr);
        if (as->value) lowerExpr(ctx, as->value);
        return;
    }
    if (auto pa = dynamic_cast<PtrAssignStmt*>(s)) {
        if (pa->ptr) lowerExpr(ctx, pa->ptr);
        if (pa->value) lowerExpr(ctx, pa->value);
        return;
    }
    if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        lowerExpr(ctx, ifs->condition);
        ctx.scopes.push_back({});
        lowerBlock(ctx, ifs->thenBlock);
        ctx.scopes.pop_back();
        ctx.scopes.push_back({});
        lowerBlock(ctx, ifs->elseBlock);
        ctx.scopes.pop_back();
        return;
    }
    if (auto w = dynamic_cast<WhileStmt*>(s)) {
        lowerExpr(ctx, w->condition);
        ctx.scopes.push_back({});
        lowerBlock(ctx, w->body);
        ctx.scopes.pop_back();
        return;
    }
    if (auto l = dynamic_cast<LoopStmt*>(s)) {
        ctx.scopes.push_back({});
        lowerBlock(ctx, l->body);
        ctx.scopes.pop_back();
        return;
    }
    if (auto f = dynamic_cast<ForStmt*>(s)) {
        if (f->start) lowerExpr(ctx, f->start);
        if (f->end) lowerExpr(ctx, f->end);
        if (f->step) lowerExpr(ctx, f->step);
        ctx.scopes.push_back({});
        ctx.scopes.back()[f->varName] = {TypeKind::Int};
        lowerBlock(ctx, f->body);
        ctx.scopes.pop_back();
        return;
    }
    if (auto sw = dynamic_cast<SwitchStmt*>(s)) {
        if (sw->condition) lowerExpr(ctx, sw->condition);
        for (auto& c : sw->cases) {
            if (c.condition) lowerExpr(ctx, c.condition);
            ctx.scopes.push_back({});
            lowerBlock(ctx, c.body);
            ctx.scopes.pop_back();
        }
        return;
    }
}

void lowerBlock(LowerCtx& ctx, Block& b) {
    for (auto& st : b.stmts) lowerStmt(ctx, st.get());
}

void lowerExpr(LowerCtx& ctx, std::unique_ptr<Expr>& e) {
    if (!e) return;
    if (auto call = dynamic_cast<CallExpr*>(e.get())) {
        if (call->receiver) {
            if (auto memb = dynamic_cast<MemberExpr*>(call->receiver.get())) {
                if (auto objId = dynamic_cast<IdentExpr*>(memb->object.get())) {
                    std::string staticClass;
                    const Type* t = nullptr;
                    const Type* fieldT = nullptr;
                    bool isSuper = (objId->name == "super");
                    if (isSuper) {
                        if (ctx.currentClass.empty())
                            throw std::runtime_error("'super' used outside a class method");
                        auto clsIt = ctx.classByName.find(ctx.currentClass);
                        if (clsIt == ctx.classByName.end() || clsIt->second->base.empty())
                            throw std::runtime_error("'super' used in class '" + ctx.currentClass + "' which has no base class");
                        staticClass = clsIt->second->base;
                    } else {
                        t = ctx.findVarType(objId->name);
                        if (t && t->kind == TypeKind::Struct && !t->structName.empty()) {
                            staticClass = t->structName;
                        } else if (!t && ctx.isField(objId->name)) {
                            // bare class field of `this` (fields are not in findVarType's scopes)
                            fieldT = ctx.findFieldType(objId->name);
                            if (fieldT && fieldT->kind == TypeKind::Struct && !fieldT->structName.empty())
                                staticClass = fieldT->structName;
                        }
                    }
                    if (!staticClass.empty()) {
                        bool isIface = ctx.isInterface(staticClass);
                        std::string impl;
                        bool haveMethod = false;
                        if (isIface) {
                            // an interface reference dispatches on the runtime class
                            auto iit = ctx.interfaceByName.find(staticClass);
                            if (iit != ctx.interfaceByName.end()) {
                                for (auto& mm : iit->second->methods) {
                                    if (mm.name == memb->member) { haveMethod = true; break; }
                                }
                            }
                        } else {
                            auto it = ctx.classMethods.find(staticClass);
                            if (it != ctx.classMethods.end()) {
                                auto mIt = it->second.find(memb->member);
                                if (mIt != it->second.end()) { haveMethod = true; impl = mIt->second; }
                            }
                        }
                        if (haveMethod) {
                            std::unique_ptr<Expr> selfArg;
                            if (isSuper) {
                                auto self = std::make_unique<IdentExpr>();
                                self->name = "this";
                                selfArg = std::move(self);
                            } else if (fieldT) {
                                // `this.<field>`: only pointer-typed fields can be passed
                                // as `this` without taking a member address
                                if (!fieldT->isPtr)
                                    throw std::runtime_error("Cannot call method '" + memb->member +
                                                             "' on by-value field '" + objId->name +
                                                             "'; use ptr<" + staticClass + "> for the field");
                                auto self = std::make_unique<IdentExpr>();
                                self->name = "this";
                                auto m = std::make_unique<MemberExpr>();
                                m->object = std::move(self);
                                m->member = objId->name;
                                selfArg = std::move(m);
                            } else if (t->isPtr) {
                                auto id = std::make_unique<IdentExpr>();
                                id->name = objId->name;
                                selfArg = std::move(id);
                            } else {
                                auto ao = std::make_unique<AddressOfExpr>();
                                ao->name = objId->name;
                                selfArg = std::move(ao);
                            }
                            resolveVirtualCall(ctx, call, staticClass, memb->member, impl, isSuper);
                            call->args.insert(call->args.begin(), std::move(selfArg));
                            call->receiver.reset();
                        }
                    }
                }
            }
        } else if (!ctx.currentClass.empty() && ctx.isMethod(ctx.currentClass, call->name)) {
            // Inside a method, a bare call like `foo()` where `foo` is another
            // method of the same class becomes `this.foo()` (possibly virtual).
            auto memb = std::make_unique<MemberExpr>();
            auto self = std::make_unique<IdentExpr>();
            self->name = "this";
            memb->object = std::move(self);
            memb->member = call->name;
            call->receiver = std::move(memb);
            lowerExpr(ctx, e);
            return;
        }
        for (auto& a : call->args) lowerExpr(ctx, a);
        return;
    }
    if (auto id = dynamic_cast<IdentExpr*>(e.get())) {
        // Inside a method, a bare field name that is not a local variable,
        // parameter or global becomes `this.field`.
        if (id->name == "super") {
            // super.field == this.field (field shadowing across the hierarchy is
            // rejected during lowering, so the merged layout matches).
            id->name = "this";
        } else if (ctx.isField(id->name) && !ctx.findVarType(id->name)) {
            auto self = std::make_unique<IdentExpr>();
            self->name = "this";
            auto m = std::make_unique<MemberExpr>();
            m->object = std::move(self);
            m->member = id->name;
            e = std::move(m);
        }
        return;
    }
    if (auto b = dynamic_cast<BinaryExpr*>(e.get())) {
        lowerExpr(ctx, b->left);
        lowerExpr(ctx, b->right);
        return;
    }
    if (auto u = dynamic_cast<UnaryExpr*>(e.get())) {
        lowerExpr(ctx, u->operand);
        return;
    }
    if (auto m = dynamic_cast<MemberExpr*>(e.get())) {
        lowerExpr(ctx, m->object);
        return;
    }
    if (auto d = dynamic_cast<DerefExpr*>(e.get())) {
        lowerExpr(ctx, d->ptr);
        return;
    }
    if (auto a = dynamic_cast<ArrayAccessExpr*>(e.get())) {
        lowerExpr(ctx, a->array);
        lowerExpr(ctx, a->index);
        return;
    }
}

void lowerFunction(LowerCtx& ctx, FunctionDecl* fn) {
    ctx.currentFields = nullptr;
    ctx.currentClass.clear();
    auto fcIt = ctx.fnClass.find(fn->name);
    if (fcIt != ctx.fnClass.end()) {
        auto fIt = ctx.classFields.find(fcIt->second);
        if (fIt != ctx.classFields.end()) {
            ctx.currentFields = &fIt->second;
            ctx.currentClass = fcIt->second;
        }
    }
    ctx.scopes.push_back({});
    for (auto& p : fn->params) ctx.scopes.back()[p.name] = p.type;
    lowerBlock(ctx, fn->body);
    ctx.scopes.pop_back();
}

void lowerProgramClasses(Program& prog) {
    LowerCtx ctx{prog};

    // ---- inheritance validation & hierarchy info ----
    for (auto& c : prog.classes) ctx.classByName[c->name] = c.get();
    for (auto& i : prog.interfaces) ctx.interfaceByName[i->name] = i.get();

    // interface names must not clash with classes/structs or each other
    for (auto& i : prog.interfaces) {
        if (ctx.classByName.count(i->name))
            throw std::runtime_error("Interface '" + i->name + "' clashes with a class name");
        for (auto& s : prog.structs)
            if (s->name == i->name)
                throw std::runtime_error("Interface '" + i->name + "' clashes with a struct name");
        if (std::count_if(prog.interfaces.begin(), prog.interfaces.end(),
                          [&](const std::unique_ptr<InterfaceDecl>& o) { return o->name == i->name; }) > 1)
            throw std::runtime_error("Duplicate interface '" + i->name + "'");
    }

    for (auto& c : prog.classes) {
        if (c->base.empty()) continue;
        if (!ctx.classByName.count(c->base))
            throw std::runtime_error("Unknown base class '" + c->base + "' for class '" + c->name + "'");
    }
    for (auto& c : prog.classes) {
        for (auto& ii : c->interfaces) {
            if (!ctx.interfaceByName.count(ii))
                throw std::runtime_error("Unknown interface '" + ii + "' for class '" + c->name + "'");
        }
    }
    for (auto& c : prog.classes) {
        std::unordered_set<std::string> seen;
        std::string cur = c->name;
        while (!cur.empty()) {
            if (!seen.insert(cur).second)
                throw std::runtime_error("Circular inheritance involving class '" + c->name + "'");
            cur = ctx.classByName[cur]->base;
        }
    }
    // chainOf[c] = [root, ..., c]; subtreeOf[c] = {c, descendants}
    std::unordered_map<std::string, std::vector<std::string>> chainOf;
    for (auto& c : prog.classes) {
        std::vector<std::string> rev;
        std::string cur = c->name;
        while (!cur.empty()) { rev.push_back(cur); cur = ctx.classByName[cur]->base; }
        std::reverse(rev.begin(), rev.end());
        chainOf[c->name] = std::move(rev);
    }
    for (auto& kv : chainOf) {
        for (auto& anc : kv.second) ctx.subtreeOf[anc].push_back(kv.first);
    }

    // assign runtime class ids (hidden `__classid` slot at offset 0)
    int nextClassID = 1;
    for (auto& c : prog.classes) prog.classIDs[c->name] = nextClassID++;

    // resolved method map per class: method name -> mangled impl of the nearest
    // declaring class (walking up the hierarchy). Own declarations win.
    for (auto& c : prog.classes) {
        auto& mm = ctx.classMethods[c->name];
        for (auto& m : c->methods) {
            if (!mm.emplace(m.name, c->name + "::" + m.name).second) {
                throw std::runtime_error("Duplicate method '" + m.name + "' in class '" + c->name + "'");
            }
        }
    }
    for (auto& c : prog.classes) {
        auto& chain = chainOf[c->name];
        for (int i = (int)chain.size() - 2; i >= 0; i--) {
            auto ancIt = ctx.classMethods.find(chain[i]);
            if (ancIt == ctx.classMethods.end()) continue;
            for (auto& kv : ancIt->second) ctx.classMethods[c->name].emplace(kv.first, kv.second);
        }
    }

    // ---- abstract classes & methods ----
    // abstract methods are recorded by mangled name (they never become functions)
    for (auto& c : prog.classes) {
        for (auto& m : c->methods) {
            if (!m.isAbstract) continue;
            ctx.abstractImpls.insert(c->name + "::" + m.name);
            if (!c->isAbstract)
                throw std::runtime_error("Class '" + c->name + "' has abstract method '" + m.name +
                                         "' but is not declared abstract");
        }
    }
    // a concrete class must resolve every inherited abstract method
    for (auto& c : prog.classes) {
        if (c->isAbstract) continue;
        for (auto& kv : ctx.classMethods[c->name]) {
            if (!ctx.abstractImpls.count(kv.second)) continue;
            auto cls = kv.second.substr(0, kv.second.find("::"));
            throw std::runtime_error("Class '" + c->name + "' must implement abstract method '" +
                                     kv.first + "' from abstract class '" + cls + "'");
        }
    }
    // no abstract class may be instantiated (by-value storage anywhere)
    auto checkAbstractValue = [&](const Type& t, const std::string& what) {
        if (t.kind == TypeKind::Struct && !t.isPtr && !t.structName.empty()) {
            auto abIt = ctx.classByName.find(t.structName);
            if (abIt != ctx.classByName.end() && abIt->second->isAbstract)
                throw std::runtime_error("Cannot instantiate abstract class '" + t.structName +
                                         "' (" + what + ")");
        }
    };
    for (auto& g : prog.globals) checkAbstractValue(g->type, "global variable");
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        for (auto& p : f->params) checkAbstractValue(p.type, "parameter");
        checkAbstractValue(f->returnType, "return type");
    }

    // ---- interface implementors (a class implements an interface when any
    // class in its inheritance chain declares `implements`; subclasses inherit
    // the obligation, so they appear too) ----
    for (auto& iface : prog.interfaces) {
        std::vector<std::string> impls;
        for (auto& c : prog.classes) {
            bool inChain = false;
            for (auto& anc : chainOf[c->name]) {
                for (auto& ii : ctx.classByName[anc]->interfaces)
                    if (ii == iface->name) { inChain = true; break; }
                if (inChain) break;
            }
            if (inChain) impls.push_back(c->name);
        }
        ctx.implementors[iface->name] = std::move(impls);
    }
    // every implementing class must provide every interface method
    for (auto& iface : prog.interfaces) {
        for (auto& X : ctx.implementors[iface->name]) {
            auto& cm = ctx.classMethods[X];
            for (auto& mm : iface->methods) {
                if (!cm.count(mm.name))
                    throw std::runtime_error("Class '" + X + "' implements interface '" + iface->name +
                                             "' but does not implement method '" + mm.name + "'");
            }
        }
    }

    // interface-typed variables/params/fields behave like references (a single
    // qword holding the address of an implementing class object).
    auto fixInterfaceType = [&](Type& t) {
        if (t.kind == TypeKind::Struct && !t.isPtr && ctx.interfaceByName.count(t.structName))
            t.isPtr = true;
    };
    for (auto& g : prog.globals) fixInterfaceType(g->type);
    for (auto& f : prog.functions) {
        if (f->isExtern) continue;
        for (auto& p : f->params) fixInterfaceType(p.type);
    }

    // merged field list: base fields first, then own fields (offsets must match
    // the base layout so base methods work on derived objects).
    std::function<std::vector<StructField>(ClassDecl*)> mergedFields =
        [&](ClassDecl* c) -> std::vector<StructField> {
        std::vector<StructField> result;
        if (!c->base.empty()) result = mergedFields(ctx.classByName[c->base]);
        for (auto& f : c->fields) {
            for (auto& pf : result) {
                if (pf.name == f.name)
                    throw std::runtime_error("Field '" + f.name + "' in class '" + c->name +
                                             "' shadows a field in base class '" + c->base + "'");
            }
            result.push_back(f);
        }
        return result;
    };

    for (auto& c : prog.classes) {
        auto mf = mergedFields(c.get());
        std::vector<std::string> fieldNames;
        for (auto& f : mf) fieldNames.push_back(f.name);
        ctx.classFields[c->name] = std::move(fieldNames);
    }

    // classes become structs with a hidden `__classid` first field
    for (auto& c : prog.classes) {
        for (auto& s : prog.structs) {
            if (s->name == c->name) {
                throw std::runtime_error("Duplicate type '" + c->name + "'");
            }
        }
        auto sd = std::make_unique<StructDecl>();
        sd->name = c->name;
        StructField cid;
        cid.name = "__classid";
        cid.type.kind = TypeKind::Int;
        sd->fields.push_back(cid);
        auto mf = mergedFields(c.get());
        for (auto& f : mf) { fixInterfaceType(f.type); checkAbstractValue(f.type, "field"); sd->fields.push_back(f); }
        prog.structs.push_back(std::move(sd));
    }

    // methods become functions with an implicit `this` first parameter
    for (auto& c : prog.classes) {
        for (auto& m : c->methods) {
            if (m.isAbstract) continue; // abstract methods have no body / no function
            auto fn = std::make_unique<FunctionDecl>();
            fn->name = c->name + "::" + m.name;
            ctx.fnClass[fn->name] = c->name;
            Param self;
            self.name = "this";
            self.type.kind = TypeKind::Struct;
            self.type.structName = c->name;
            self.type.isPtr = true;
            fn->params.push_back(self);
            for (auto& p : m.params) { fixInterfaceType(p.type); checkAbstractValue(p.type, "method parameter"); fn->params.push_back(p); }
            fn->returnType = m.returnType;
            fixInterfaceType(fn->returnType);
            checkAbstractValue(fn->returnType, "method return type");
            fn->body = std::move(m.body);
            prog.functions.push_back(std::move(fn));
        }
    }

    // rewrite obj.method(...) calls to Class::method(&obj, ...) everywhere
    for (auto& f : prog.functions) lowerFunction(ctx, f.get());
}

} // namespace

Program Parser::parse() {
    Program prog;
    appType = AppType::Console;

    // Check for [no_main] directive in source (detected before lexing)
    // The isLibrary flag is set from outside

    // Parse required app directive first
    while (!check(TokenKind::Eof)) {
        if (check(TokenKind::Newline)) { advance(); continue; }
        break;
    }

    if (check(TokenKind::App)) {
        parseAppType(prog);
        appType = prog.appType;
    } else {
        std::cerr << "Error at line " << peek().line << ": missing 'app' directive. Use 'app gui tool', 'app gui game', 'app gui dx tool', 'app console', 'app efi', or 'app bare' at the top of the file.\n";
        throw std::runtime_error("Missing app directive");
    }

    auto trySync = [&]() {
        while (!check(TokenKind::Eof)) {
            if (check(TokenKind::Newline)) { advance(); return true; }
            if (check(TokenKind::End)) return true;
            if (check(TokenKind::Else)) return true;
            if (check(TokenKind::Func)) return true;
            // advance past the keyword so the failing construct is not retried
            if (check(TokenKind::Struct) || check(TokenKind::Class) ||
                check(TokenKind::Interface) || check(TokenKind::Abstract)) {
                advance();
                return true;
            }
            advance();
        }
        return false;
    };

    auto addBuiltinStruct = [&](const std::string& name, const std::vector<std::pair<std::string, TypeKind>>& fields) {
        auto sd = std::make_unique<StructDecl>();
        sd->name = name;
        for (auto& f : fields) {
            StructField sf;
            sf.name = f.first;
            sf.type = {f.second};
            sd->fields.push_back(sf);
        }
        prog.structs.push_back(std::move(sd));
    };

    if (prog.appType == AppType::GUI) {
        addBuiltinStruct("vec2", {{"x", TypeKind::Float}, {"y", TypeKind::Float}});
        addBuiltinStruct("vec3", {{"x", TypeKind::Float}, {"y", TypeKind::Float}, {"z", TypeKind::Float}});
        addBuiltinStruct("color", {{"r", TypeKind::Float}, {"g", TypeKind::Float}, {"b", TypeKind::Float}, {"a", TypeKind::Float}});
    }

    while (!check(TokenKind::Eof)) {
        try {
            if (check(TokenKind::Newline)) { advance(); continue; }

            if (check(TokenKind::At)) {
                advance();
                consume(TokenKind::Import, "Expected 'import' after '@'");
                consume(TokenKind::LParen, "Expected '('");
                Token dll = consume(TokenKind::StringLit, "Expected DLL name string");
                consume(TokenKind::RParen, "Expected ')'");
                if (check(TokenKind::Newline)) advance();
                ImportDecl imp;
                std::string raw = dll.text;
                size_t sep = raw.find("::");
                if (sep != std::string::npos) {
                    imp.dllName = raw.substr(0, sep);
                    imp.module  = raw.substr(sep + 2);
                } else {
                    imp.dllName = raw;
                }
                prog.imports.push_back(imp);
                continue;
            }

            if (check(TokenKind::Extern)) {
                prog.functions.push_back(parseExternFunc());
            } else if (check(TokenKind::Struct)) {
                for (auto& s : prog.structs)
                    if (s->name == peekNext().text)
                        throw std::runtime_error("Duplicate struct '" + peekNext().text + "'");
                prog.structs.push_back(parseStruct());
            } else if (check(TokenKind::Class)) {
                for (auto& c : prog.classes)
                    if (c->name == peekNext().text)
                        throw std::runtime_error("Duplicate class '" + peekNext().text + "'");
                prog.classes.push_back(parseClass());
            } else if (check(TokenKind::Interface)) {
                for (auto& i : prog.interfaces)
                    if (i->name == peekNext().text)
                        throw std::runtime_error("Duplicate interface '" + peekNext().text + "'");
                prog.interfaces.push_back(parseInterface());
            } else if (check(TokenKind::Abstract)) {
                advance();
                if (check(TokenKind::Class)) {
                    for (auto& c : prog.classes)
                        if (c->name == peekNext().text)
                            throw std::runtime_error("Duplicate class '" + peekNext().text + "'");
                    prog.classes.push_back(parseClass(true));
                } else if (check(TokenKind::Interface)) {
                    for (auto& i : prog.interfaces)
                        if (i->name == peekNext().text)
                            throw std::runtime_error("Duplicate interface '" + peekNext().text + "'");
                    prog.interfaces.push_back(parseInterface());
                } else {
                    throw std::runtime_error("Expected 'class' or 'interface' after 'abstract'");
                }
            } else if (check(TokenKind::Func)) {
                auto func = parseFunction();
                for (auto& f : prog.functions) {
                    if (f->name == func->name) {
                        throw std::runtime_error("Duplicate function '" + func->name + "'");
                    }
                }
                prog.functions.push_back(std::move(func));
            } else if (check(TokenKind::Var) || check(TokenKind::Let) || check(TokenKind::Const)) {
                prog.globals.push_back(parseVarDecl());
            } else {
                std::cerr << "Unexpected token '" << peek().text << "' at line " << peek().line << std::endl;
                advance();
            }
        } catch (const std::runtime_error& e) {
            if (fatalError) throw;
            std::cerr << "Error at line " << peek().line << ": " << e.what() << std::endl;
            if (!trySync()) break;
        }
    }
    lowerProgramClasses(prog);
    return prog;
}
