#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include "main.h"

/*
 *  Słowa kluczowe
 */

keyword_t keywords[] = {
    [KW_IF]     = { "if",       TK_IF   },
    [KW_ELSE]   = { "else",     TK_ELSE },
    [KW_AND]    = { "and",      TK_AND  },
    [KW_OR]     = { "or",       TK_OR   },
    [KW_OUT]    = { "out",      TK_CALL },
};

/*
 *  Przejście do kolejnego tokenu
 */

void next_token(lexer_t *lex) {
    lex->token = lex->peek;

    while(*lex->pos && isspace(*lex->pos)) lex->pos++;

    lex->peek.start = lex->pos;
    lex->peek.len = 1;

    if(!*lex->pos) { lex->peek.type = TK_EOF; return; }

    char c = *lex->pos++;

    if(isdigit(c)) {
        lex->peek.type = TK_NUM;
        if(c == '0' && *lex->pos == 'x' && isxdigit(*(lex->pos + 1))){
            lex->peek.num = strtol(lex->peek.start, &lex->pos, 16);
            lex->peek.len = lex->pos - lex->peek.start;
            return;
        }
        lex->peek.num = strtod(lex->peek.start, &lex->pos);
        lex->peek.len = lex->pos - lex->peek.start;
        return;
    }
    if(isalpha(c)) {
        while(isalnum(*lex->pos)) lex->pos++;
        lex->peek.len = lex->pos - lex->peek.start;
        for(size_t i = 0; i < KEYWORDS_NUM; i++) {
            if(!strncmp(keywords[i].name, lex->peek.start, strlen(keywords[i].name))){
                lex->peek.type = keywords[i].token;
                lex->peek.kw = i;
                return;
            }
        }
        lex->peek.type = TK_ID;
        return;
    }
    if(c == '\'') {
        while(*lex->pos && (*lex->pos != '\'' && *(lex->pos - 1) != '\\')) lex->pos++;
        if(!*lex->pos){
            fprintf(stderr, "Syntax error: ' missing [%lld]\n", lex->pos - lex->source);
            lex->error = 1;
            return;
        }
        lex->peek.type = TK_STR; 
        lex->peek.start++;
        lex->peek.len = lex->pos - lex->peek.start;
        lex->pos++;
        return;
    }
    else if(c == '>' && *lex->pos == '='){
        lex->peek.type = TK_GE;
        lex->pos++;
        lex->peek.len = lex->pos - lex->peek.start;
        return;
    }
    else if(c == '<' && *lex->pos == '='){
        lex->peek.type = TK_LE;
        lex->pos++;
        lex->peek.len = lex->pos - lex->peek.start;
        return;
    }
    else if(c == '=' && *lex->pos == '='){
        lex->peek.type = TK_EQEQ;
        lex->pos++;
        lex->peek.len = lex->pos - lex->peek.start;
        return;
    }

    lex->peek.type = c;
}

/*
 *  Tworzenie Lexera
 */

lexer_t lexer(char *str, dbuffer_t *db, ibuffer_t *ib, ibuffer_t *fb, var_t *vb) {
    lexer_t lex;
    lex.source = str;
    lex.pos = lex.source;
    lex.error = 0;
    lex.db = db;
    lex.ib = ib;
    lex.fb = fb;
    lex.vb = vb;
    next_token(&lex);
    return lex;
}

/*
 *  Parametry operatorów: handlery prefix, infix, moc wiązania
 */

node_handler_t node_handler[] = {
    [TK_EOF] =    { NULL,       NULL,           0  },
    [TK_LBRACE] = { node_block, NULL,           0  },
    [TK_RBRACE] = { NULL,       NULL,           0  },
    [TK_DELIM]  = { NULL,       NULL,           0  },
    [TK_NUM]    = { node_val,   NULL,           1  },
    [TK_STR]    = { node_val,   NULL,           1  },
    [TK_ID]     = { node_id,    NULL,           1  },
    [TK_CALL]   = { node_call,  NULL,           1  },
    [TK_LPAREN] = { node_group, NULL,           1  },
    [TK_RPAREN] = { NULL,       NULL,           1  },
    [TK_IF]     = { node_if,    NULL,           6  },
    [TK_ELSE]   = { NULL,       NULL,           6  },
    [TK_EQ]     = { NULL,       node_assign,    7  },
    [TK_AND]    = { NULL,       node_binop,     8  },
    [TK_OR]     = { NULL,       node_binop,     8  },
    [TK_EXC]    = { node_unop,  NULL,           8  },
    [TK_LT]     = { NULL,       node_binop,     9  },
    [TK_GT]     = { NULL,       node_binop,     9  },
    [TK_LE]     = { NULL,       node_binop,     9  },
    [TK_GE]     = { NULL,       node_binop,     9  },
    [TK_EQEQ]   = { NULL,       node_binop,     9  },
    [TK_PLUS]   = { NULL,       node_binop,     10 },
    [TK_MINUS]  = { node_unop,  node_binop,     10 },
    [TK_STAR]   = { NULL,       node_binop,     20 },
    [TK_SLASH]  = { NULL,       node_binop,     20 },
    [TK_BAND]   = { NULL,       node_binop,     30 },
    [TK_BOR]    = { NULL,       node_binop,     30 },
    [TK_BXOR]   = { NULL,       node_binop,     30 },
    [TK_TILDE]  = { node_unop,  NULL,           30 },
};

/*
 *  Funkcja hashująca ukradziona z Lua
 */

uint32_t hash(const char *str, size_t len, uint32_t seed) {
    uint32_t h = seed ^ (uint32_t)(len);
    for(; len > 0; len--)
        h ^= ((h << 5) + (h >> 2) + (uint8_t)(str[len - 1]));
    return h;
}

/*
 *  Alokacja pamięci węzła
 */

node_t* node_alloc(lexer_t *lex, node_type_t type) {
    node_t *node = (node_t*) calloc(1, sizeof(node_t));
    node->type = type;
    node->token_pos = lex->token.start - lex->source;
    node->val.type = type_nil;
    return node;
}

/*
 *  Zwalnianie pamięci drzewa
 */

void node_free(node_t *node) {
    while(node){
        if(node->type == ND_ID && node->id) free(node->id);
        node_t *next = node->next;
        node_free(node->child);
        free(node);
        node = next;
    }
}

/*
 *  Węzeł grupowania
 */

node_t* node_group(lexer_t *lex) {
    node_t *expr = node_expr(lex, node_handler[TK_RPAREN].lbp);
    if(!expr) return NULL;
    next_token(lex);
    if(lex->token.type != TK_RPAREN){
        return node_error(lex, "Syntax error: ) missing");
    }
    return expr;
}

/*
 *  Funkcje pomocnicze do alokacji danych
 */

void alloc_str(void **dst, char *src, size_t count){
    if(*dst) free(*dst);
    *dst = calloc(count + 1, sizeof(char));
    if(!*dst) exit(ENOMEM);
    memcpy(*dst, src, count * sizeof(char));
}

/*
 *  Węzeł z wartością przekazaną wprost
 */

node_t* node_val(lexer_t *lex) {
    node_t *node = node_alloc(lex, ND_VAL);
    switch(lex->token.type){
        case TK_NUM:
            node->val.type = type_num;
            node->val.size = sizeof(double);
            node->val.addr = lex->db->size;
            ib_write(lex->ib, OP_LOAD, lex->db->size);
            db_write(lex->db, &lex->token.num, sizeof(double));
            break;
        case TK_STR:
            node->val.type = type_str;
            node->val.size = lex->token.len + 1;
            node->val.addr = lex->db->size;
            db_write(lex->db, lex->token.start, lex->token.len);
            db_write_u8(lex->db, 0);
            break;
        default:
            return NULL;
    }
    return node;
}

/*
 *  Węzeł identyfikatora
 */

node_t* node_id(lexer_t *lex) {
    node_t *node = node_alloc(lex, ND_ID);
    node->id = (id_node_t*) malloc(sizeof(id_node_t));
    if(!node->id) exit(ENOMEM);
    node->id->name = lex->token.start;
    node->id->len = lex->token.len;

    size_t index = hash(node->id->name, node->id->len, (intptr_t)lex->vb) & (VARS_SIZE - 1);
    size_t start = index;
    while(lex->vb[index].name && strncmp(lex->vb[index].name, node->id->name, node->id->len)){
        index = (index + 1) & (VARS_SIZE - 1);
        if(index == start) {
            return node_error(lex, "Variable table overflow"); 
        }
    }
    node->val.type = type_num; // Na razie tylko liczby jako zmienne'
    node->id->index = index;
    return node; 
}

/*
 *  Ewaluacja węzła do wartości liczbowej
 */

node_t* node_eval(lexer_t *lex, node_t *node){
    if(!node) return NULL;
    if(node->type == ND_ID){
        if(!lex->vb[node->id->index].name){
            return node_error(lex, "Unknown identifier");
        }
        ib_write(lex->ib, OP_VGET, node->id->index);
    }
    else if(!is_num(node->val.type)){
        return node_error(lex, "Not a number");
    }
    return node;
}

/*
 *  Węzeł oparcji binarnej
 */

node_t* node_binop(lexer_t *lex, node_t *left) {
    next_token(lex);
    token_type_t op = lex->token.type;
    if(!node_eval(lex, left)) return NULL;
    node_t *right = node_expr(lex, node_handler[op].lbp);
    if(!node_eval(lex, right)) return NULL;
    node_t *node = node_alloc(lex, ND_BINOP);
    node->op = op;
    node->child = left;
    left->next = right;
    node->val.type = type_num;

    switch(op){
        case TK_PLUS: ib_write(lex->ib, OP_ADD, 0); break;
        case TK_MINUS: ib_write(lex->ib, OP_SUB, 0); break;
        case TK_STAR: ib_write(lex->ib, OP_MULT, 0); break;
        case TK_SLASH: ib_write(lex->ib, OP_DIV, 0); break;
        case TK_BAND: ib_write(lex->ib, OP_BAND, 0); break;
        case TK_BOR: ib_write(lex->ib, OP_BOR, 0); break;
        case TK_BXOR: ib_write(lex->ib, OP_BXOR, 0); break;
        case TK_AND: ib_write(lex->ib, OP_AND, 0); break;
        case TK_OR: ib_write(lex->ib, OP_OR, 0); break;
        case TK_LT: ib_write(lex->ib, OP_LT, 0); break;
        case TK_LE: ib_write(lex->ib, OP_LE, 0); break;
        case TK_GT: ib_write(lex->ib, OP_GT, 0); break;
        case TK_GE: ib_write(lex->ib, OP_GE, 0); break;
        case TK_EQEQ: ib_write(lex->ib, OP_EQ, 0); break;
        default: break;
    }

    return node;
}

/*
 *  Węzeł operacji unarnej
 */

node_t* node_unop(lexer_t *lex) {
    token_type_t op = lex->token.type;
    node_t *expr = node_expr(lex, node_handler[op].lbp);
    if(!expr) return NULL;
    node_t *node = node_alloc(lex, ND_UNOP);
    node->op = op;
    node->child = expr;

    if(!is_num(expr->val.type)){
        return node_error(lex, "Error: invalid operand type");
    }
    node->val.type = type_num;

    switch(node->op){
        case TK_MINUS: ib_write(lex->ib, OP_NEG, 0); break;
        case TK_TILDE: ib_write(lex->ib, OP_BNOT, 0); break;
        case TK_EXC: ib_write(lex->ib, OP_NOT, 0); break;
        default: break;
    }

    return node;
}

/*
 *  Funkcje wbudowane
 */

node_t* builtin_out(lexer_t *lex, node_t *node) {
    if(!node_eval(lex, node->child)) return NULL;
    ib_write(lex->ib, OP_PRINT, 0);
    return node;
}

call_fun_t builtin[] = {
    [KW_OUT] = builtin_out,
};

/*
 *  Węzeł wywołania funkcji
 */

node_t* node_call(lexer_t *lex) {
    token_t token = lex->token;
    next_token(lex);
    if(lex->token.type != TK_LPAREN){
        return node_error(lex, "Syntax error: ( missing");
    }
    node_t *expr = node_group(lex);
    if(!expr) return NULL;
    node_t *node = node_alloc(lex, ND_CALL);
    node->id = (id_node_t*) malloc(sizeof(id_node_t));
    if(!node->id) exit(ENOMEM);
    node->id->name = token.start;
    node->id->len = token.len;
    node->child = expr;
    return builtin[token.kw](lex, node);
}

/*
 *  Węzeł instrukcji warunkowej
 */

node_t* node_if(lexer_t *lex) {
    next_token(lex);
    if(lex->token.type != TK_LPAREN){
        return node_error(lex, "'if' statement syntax error");
    }
    node_t *cond = node_group(lex);
    if(!node_eval(lex, cond)) return NULL;

    uint32_t fjump_idx = lex->ib->count;
    ib_write(lex->ib, OP_FJUMP, 0);

    node_t *node = node_alloc(lex, ND_IF);
    node->child = cond;

    next_token(lex);
    node_t *expr_true = NULL;
    if(lex->token.type != TK_LBRACE){
        node_free(node);
        return node_error(lex, "'if' statement syntax error");
    }
    expr_true = node_block(lex);
    if(!expr_true){
        node_free(node);
        return NULL;
    }
    cond->next = expr_true;

    node_t *expr_false = NULL;
    if(lex->peek.type == TK_ELSE){
        next_token(lex);
        uint32_t jump_idx = lex->ib->count;
        ib_write(lex->ib, OP_JUMP, 0);
        lex->ib->inst[fjump_idx].arg = lex->ib->count;

        next_token(lex);
        if(lex->token.type == TK_LBRACE){
            expr_false = node_block(lex);
        }
        else if(lex->token.type == TK_IF){
            expr_false = node_if(lex);
        }
        else{
            node_free(node);
            return node_error(lex, "'else' statement syntax error");
        }
        if(!expr_false){
            node_free(node);
            return NULL;
        }
        lex->ib->inst[jump_idx].arg = lex->ib->count;
    }
    else{
        lex->ib->inst[fjump_idx].arg = lex->ib->count;
    }
    expr_true->next = expr_false;

    return node;
}

/*
 *  Węzeł przypisania
 */

node_t* node_assign(lexer_t *lex, node_t *left) {
    next_token(lex);
    if(left->type != ND_ID) return node_error(lex, "Assignment error");
    token_type_t op = lex->token.type;
    node_t *right = node_expr(lex, node_handler[op].lbp);
    if(!right || !is_num(right->val.type)) {
        return node_error(lex, "Assignment error"); // Na razie tylko liczby jako zmienne
    }
    node_t *node = node_alloc(lex, ND_ASSIGN);
    node->op = op;
    node->child = left;
    left->next = right;

    if(!lex->vb[left->id->index].name) {
        lex->vb[left->id->index].name = (char*) &lex->db->data[lex->db->size];
        db_write(lex->db, left->id->name, left->id->len);
        db_write_u8(lex->db, 0);
    }
    ib_write(lex->ib, OP_VSET, left->id->index);
    return node;
}

/*
 *  Główna funkcja rekurencyjnego parsowania wyrażenia
 */

node_t* node_expr(lexer_t *lex, uint8_t rbp) {
    next_token(lex);
    prefix_fun_t prefix = node_handler[lex->token.type].prefix;
    node_t *node = prefix ? prefix(lex) : NULL;
    if(!node) return NULL; // node_error(lex, "Syntax error");
    if(node->type == ND_IF) return node;
    while(rbp < node_handler[lex->peek.type].lbp) {
        infix_fun_t infix = node_handler[lex->peek.type].infix;
        node = infix ? infix(lex, node) : node;
    }
    return node;
}

/*
 *  Funkcja parsowania bloku wyrażeń
 */

node_t* node_block(lexer_t *lex) {
    node_t *node = node_alloc(lex, ND_BLOCK);
    if(lex->peek.type == TK_RBRACE || lex->peek.type == TK_EOF){
        next_token(lex);
        return node;
    }

    node_t *expr = node_expr(lex, node_handler[TK_DELIM].lbp);
    node->child = expr;
    while(1){        
        if(!expr) break;
        if(!is_block(expr->type) && !is_inst(expr->type)){
            return node_error(lex, "Invalid expression");
        }
        if(!is_block(expr->type) && lex->peek.type != TK_DELIM){
            return node_error(lex, "Syntax error: ';' missing");
        }
        if(lex->peek.type == TK_DELIM) next_token(lex);
        if(lex->peek.type == TK_RBRACE || lex->peek.type == TK_EOF){
            next_token(lex);
            return node;
        }
        expr->next = node_expr(lex, node_handler[TK_DELIM].lbp);
        expr = expr->next;
    };
    return node;
}

/*
 *  Wydruki błędów parsowania i kompilacji
 */

node_t* node_error(lexer_t *lex, char *msg){
    if(lex->error) return NULL;
    lex->error = 1;
    fprintf(stderr, "%s [%lld]\n", msg, lex->token.start - lex->source);
    return NULL;
}

/*
 *  Wywołanie parsera
 */

node_t* parse(char *expr, dbuffer_t *db, ibuffer_t *ib, ibuffer_t *fb, var_t *vb) {
    lexer_t lex = lexer(expr, db, ib, fb, vb);
    if(lex.peek.type == TK_EOF) return NULL;
    //node_t *root = node_expr(&lex, 0);
    node_t *root = node_block(&lex);
    if(!root || !root->child) return NULL;
    if(lex.peek.type != TK_EOF) {
        next_token(&lex);
        return node_error(&lex, "Syntax error: unexpected expression");
    }
    return root;
}

/*
 *  Wydruk drzewa
 */

void node_print(node_t *node, dbuffer_t *db, int indent) {
    if(!node) return;
    node_t *next;
    for(int i = 0; i < indent; i++) fprintf(stdout, "  ");
    switch(node->type) {
        case ND_VAL:
            switch(node->val.type) {
                case type_num: 
                    fprintf(stdout, "VAL %g\n", *(double*)(db->data + node->val.addr)); 
                    break;
                case type_str:
                    fprintf(stdout, "VAL '%s'\n", (char*)(db->data + node->val.addr)); 
                    break;
                default:
                    break;
            }
            break;
        case ND_ID:
            fprintf(stdout, "ID %.*s\n", (int)node->id->len, node->id->name);
            break;
        case ND_BINOP:
        case ND_ASSIGN:
            fprintf(stdout, "BINOP %d:%c\n", node->op, node->op < 256 ? node->op : '\0');
            node_print(node->child, db, indent + 1);
            node_print(node->child->next, db, indent + 1);
            break;
        case ND_UNOP:
            fprintf(stdout, "UNOP %c\n", node->op);
            node_print(node->child, db, indent + 1);
            break;
        case ND_CALL:
            fprintf(stdout, "CALL %.*s\n", (int)node->id->len, node->id->name);
            node_print(node->child, db, indent + 1);
            next = node->child->next;
            while(next) {
                node_print(next, db, indent + 1);
                next = next->next;
            }
            break;
        case ND_IF:
            fprintf(stdout, "IF\n");
            node_print(node->child, db, indent + 1);
            next = node->child->next;
            while(next) {
                node_print(next, db, indent + 1);
                next = next->next;
            }
            break;
        case ND_BLOCK:
            fprintf(stdout, "BLOCK\n");
            next = node->child;
            while(next) {
                node_print(next, db, indent + 1);
                next = next->next;
            }
            break;
        default:
            break;
    }
}

/*
 *  Bufor instrukcji
 */

void ib_write(ibuffer_t *ib, uint32_t opcode, uint32_t arg){
    if(ib->count >= ib->capacity) {
        ib->capacity = ib->capacity ? ib->capacity * 2 : 256;
        ib->inst = realloc(ib->inst, ib->capacity * sizeof(inst_t));
    }
    ib->inst[ib->count++] = (inst_t){opcode, arg};
}

void ib_free(ibuffer_t *ib){
    if(ib->inst) free(ib->inst);
}

/*
 *  Bufor danych
 */

dbuffer_t db_create() {
    return (dbuffer_t){ .capacity = 4096, .data = malloc(4096) };
}

void db_write(dbuffer_t *db, const void *src, size_t len) {
    if(db->size + len > db->capacity) {
        size_t new_cap = db->capacity;
        while (db->size + len > new_cap) new_cap *= 2;
        db->data = realloc(db->data, new_cap);
        db->capacity = new_cap;
    }
    memcpy(db->data + db->size, src, len);
    db->size += len;
}

void db_free(dbuffer_t *db){
    if(db->data) free(db->data);
}

/*
 *  Maszyna wirtualna wykonująca bytecode
 */

void execute(dbuffer_t *db, ibuffer_t *ib, ibuffer_t *fb, var_t *vb){
    val_t stack[256];
    uint32_t sp = 0;
    uint32_t pc = 0;

    // Musi się zgadzać z opcode_t
    static void *op_table[] = {
        &&op_halt, &&op_load, &&op_add, &&op_sub,
        &&op_mult, &&op_div, &&op_idiv, &&op_mod,
        &&op_neg, &&op_band, &&op_bor, &&op_bxor, 
        &&op_bnot, &&op_not, &&op_call, &&op_print,
        &&op_and, &&op_or, &&op_lt, &&op_le,
        &&op_gt, &&op_ge, &&op_eq, &&op_vset,
        &&op_vget, &&op_jump, &&op_fjump
    };

    #define NEXT() goto *op_table[ib->inst[++pc].opcode]
    #define arg ib->inst[pc].arg

    goto *op_table[ib->inst[0].opcode];

    op_halt:
        return;
    op_load:
        stack[sp++].num = *(double*)(db->data + arg);
        NEXT();
    op_add:
        stack[sp-2].num = stack[sp-2].num + stack[sp-1].num; sp--;
        NEXT();
    op_sub:
        stack[sp-2].num = stack[sp-2].num - stack[sp-1].num; sp--;
        NEXT();
    op_mult:
        stack[sp-2].num = stack[sp-2].num * stack[sp-1].num; sp--;
        NEXT();
    op_div:
        stack[sp-2].num = stack[sp-2].num / stack[sp-1].num; sp--;
        NEXT();
    op_idiv:
        stack[sp-2].num = ((int32_t)stack[sp-2].num) / ((int32_t)stack[sp-1].num); sp--;
        NEXT();
    op_mod:
        stack[sp-2].num = ((int32_t)stack[sp-2].num) % ((int32_t)stack[sp-1].num); sp--;
        NEXT();
    op_neg:
        stack[sp-1].num = -stack[sp-1].num;
        NEXT();
    op_band:
        stack[sp-2].num = ((int32_t)stack[sp-2].num) & ((int32_t)stack[sp-1].num); sp--;
        NEXT();
    op_bor:
        stack[sp-2].num = ((int32_t)stack[sp-2].num) | ((int32_t)stack[sp-1].num); sp--;
        NEXT();
    op_bxor:
        stack[sp-2].num = ((int32_t)stack[sp-2].num) ^ ((int32_t)stack[sp-1].num); sp--;
        NEXT();
    op_bnot:
        stack[sp-1].num = ~((int32_t)stack[sp-1].num);
        NEXT();
    op_not:
        NEXT();
    op_call:
        NEXT();
    op_print:
        fprintf(stdout, "%g\n", stack[--sp].num);
        NEXT();
    op_and:
        stack[sp-2].num = stack[sp-2].num && stack[sp-1].num; sp--;
        NEXT();
    op_or:
        stack[sp-2].num = stack[sp-2].num || stack[sp-1].num; sp--;
        NEXT();
    op_lt:
        stack[sp-2].num = stack[sp-2].num < stack[sp-1].num; sp--;
        NEXT();
    op_le:
        stack[sp-2].num = stack[sp-2].num <= stack[sp-1].num; sp--;
        NEXT();
    op_gt:
        stack[sp-2].num = stack[sp-2].num > stack[sp-1].num; sp--;
        NEXT();
    op_ge:
        stack[sp-2].num = stack[sp-2].num >= stack[sp-1].num; sp--;
        NEXT();
    op_eq:
        stack[sp-2].num = stack[sp-2].num == stack[sp-1].num; sp--;
        NEXT();
    op_vset:
        vb[arg].val = stack[--sp];
        NEXT();
    op_vget:
        stack[sp++].num = vb[arg].val.num;
        NEXT();
    op_jump:
        pc = arg;
        goto *op_table[ib->inst[pc].opcode];
    op_fjump:
        if(!stack[--sp].num){
            pc = arg;
            goto *op_table[ib->inst[pc].opcode];
        }
        NEXT();
}

/*
 *  Main
 */

#define BUFSIZE 256

int main(int argc, char *argv[]) { 
    char line[BUFSIZE];
    FILE *file = stdin;

    if(argc > 1) {
        file = fopen(argv[1], "rb");
        if(!file) {
            fprintf(stderr, "Unable to open file \"%s\"\n", argv[1]);
            exit(EIO);
        }
        fseek(file, 0, SEEK_END);
        size_t f_size = ftell(file);
        fseek(file, 0, SEEK_SET);
        char *code = (char*) calloc(1, f_size + 1);
        if(!code) exit(ENOMEM);
        if(fread(code, f_size, 1, file) != 1){
            fclose(file);
            free(code);
            exit(EIO);
        }
        fclose(file);

        var_t vars[VARS_SIZE] = {0};
        dbuffer_t data_buf = db_create();
        ibuffer_t inst_buf = {0};
        ibuffer_t fun_buf = {0};
        node_t *root = parse(code, &data_buf, &inst_buf, &fun_buf, vars);
        if(root){
            node_print(root, &data_buf, 0);
            ib_write(&inst_buf, OP_HALT, 0);
            execute(&data_buf, &inst_buf, &fun_buf, vars);
            node_free(root); 
        }
        ib_free(&inst_buf);
        ib_free(&fun_buf);
        db_free(&data_buf);
        return 0;
    }

    var_t vars[VARS_SIZE] = {0};
    dbuffer_t data_buf = db_create();

    if(file == stdin) fprintf(stdout, ">> ");
    while(fgets(line, BUFSIZE, file) != NULL){
        if(strncmp(line, "exit", 4) == 0) break;
        ibuffer_t inst_buf = {0};
        ibuffer_t fun_buf = {0};
        node_t *root = parse(line, &data_buf, &inst_buf, &fun_buf, vars);
        if(root){
            node_print(root, &data_buf, 0);
            ib_write(&inst_buf, OP_HALT, 0);
            execute(&data_buf, &inst_buf, &fun_buf, vars);
            node_free(root); 
        }
        
        ib_free(&inst_buf);
        ib_free(&fun_buf);
        if(file == stdin) fprintf(stdout, ">> ");
    }
    db_free(&data_buf);
    if(file != stdin) fclose(file);

    return 0;

}
