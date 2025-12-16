#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include "main.h"

/*
*   Przejście do kolejnego tokenu
*/

void next_token(lexer_t *lex) {
    lex->token = lex->peek;

    while(*lex->pos && isspace(*lex->pos)) lex->pos++;

    lex->peek.start = lex->pos;
    lex->peek.len = 1;

    if(!*lex->pos) { lex->peek.type = TK_EOF; return; }

    char c = *lex->pos++;

    if(isdigit(c)) {
        if(c == '0' && *lex->pos == 'x' && isxdigit(*(lex->pos + 1))){
            lex->peek.type = TK_INT;
            lex->peek.inum = strtol(lex->peek.start, &lex->pos, 16);
            lex->peek.len = lex->pos - lex->peek.start;
            return;
        }
        while(isdigit(*lex->pos)) lex->pos++;
        if(*lex->pos != '.') {
            lex->peek.type = TK_INT;
            lex->peek.inum = strtol(lex->peek.start, NULL, 10);
        }
        else {
            lex->peek.type = TK_FLT;
            lex->peek.fnum = strtod(lex->peek.start, &lex->pos);
        }
        lex->peek.len = lex->pos - lex->peek.start;
        return;
    }
    if(isalpha(c)) {
        while(isalpha(*lex->pos)) lex->pos++;
        lex->peek.type = TK_ID;
        lex->peek.len = lex->pos - lex->peek.start;
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

    lex->peek.type = c;
}

/*
*   Tworzenie Lexera
*/

lexer_t lexer(char *str) {
    lexer_t lex;
    lex.source = str;
    lex.pos = lex.source;
    lex.error = 0;
    next_token(&lex);
    return lex;
}

/*
*   Parametry operatorów: handlery prefix, infix, moc wiązania
*/

node_handler_t node_handler[] = {
    [TK_FLT]    = { node_val,   NULL,           0  },
    [TK_INT]    = { node_val,   NULL,           0  },
    [TK_STR]    = { node_val,   NULL,           0  },
    [TK_ID]     = { node_id,    NULL,           0  },
    [TK_LPAREN] = { node_group, NULL,           0  },
    [TK_RPAREN] = { NULL,       NULL,           0  },
    [TK_EQ]     = { NULL,       node_assign,    1  },
    [TK_QUEST]  = { NULL,       node_binop,     2  },
    [TK_COL]    = { NULL,       node_binop,     3  },
    [TK_PLUS]   = { NULL,       node_binop,     10 },
    [TK_MINUS]  = { node_unop,  node_binop,     10 },
    [TK_STAR]   = { NULL,       node_binop,     20 },
    [TK_SLASH]  = { NULL,       node_binop,     20 },
    [TK_AND]    = { NULL,       node_binop,     30 },
    [TK_OR]     = { NULL,       node_binop,     30 },
    [TK_XOR]    = { NULL,       node_binop,     30 },
    [TK_NEG]    = { node_unop,  NULL,           30 },
};

/*
*   Słowa kluczowe i funkcje
*/

keyword_t keywords[] = {
    [KW_SIN]    = { "sin",      sin_eval },
    [KW_COS]    = { "cos",      cos_eval },
};

/*
*   Tablica zmiennych globalnych
*/

#define VARTAB_SIZE (1 << 8) 
static var_tab_t var_tab[VARTAB_SIZE] = {0};

/*
*   Alokacja pamięci węzła
*/

node_t* node_alloc(lexer_t *lex, node_type_t type) {
    node_t *node = (node_t*) calloc(1, sizeof(node_t));
    node->type = type;
    node->token_pos = lex->token.start - lex->source;
    node->val.type = type_nil;
    return node;
}

/*
*   Zwalnianie pamięci drzewa
*/

void node_free(node_t *node) {
    while(node){
        if(node->type == ND_VAL && is_arr(node->val.type)) free(node->val.arr.ptr);
        if(node->type == ND_ID && node->id) free(node->id);
        node_t *next = node->next;
        node_free(node->child);
        free(node);
        node = next;
    }
}

/*
*   Węzeł grupowania
*/

node_t* node_group(lexer_t *lex) {
    node_t *expr = node_expr(lex, 0);
    if(!expr) return NULL;
    next_token(lex);
    if(lex->token.type != TK_RPAREN){
        return node_error(lex, "Syntax error: ) missing");
    }
    return expr;
}

/*
*   Funkcje pomocnicze do alokacji danych
*/

void alloc_str(void **dst, char *src, size_t count){
    if(*dst) free(*dst);
    *dst = calloc(count + 1, sizeof(char));
    if(!*dst) exit(ENOMEM);
    memcpy(*dst, src, count * sizeof(char));
}

/*
*   Węzeł z wartością przekazaną wprost
*/

node_t* node_val(lexer_t *lex) {
    node_t *node = node_alloc(lex, ND_VAL);
    switch(lex->token.type){
        case TK_INT:
            node->val.type = type_int;
            node->val.inum = lex->token.inum;
            break;
        case TK_FLT:
            node->val.type = type_flt;
            node->val.fnum = lex->token.fnum;
            break;
        case TK_STR:
            node->val.type = type_str;
            node->val.arr.count = lex->token.len;
            alloc_str(&node->val.arr.ptr, lex->token.start, lex->token.len);
            break;
        default:
            return NULL;
    }
    return node;
}

/*
*   Węzeł identyfikatora
*/

node_t* node_id(lexer_t *lex) {
    for(size_t i = 0; i < KEYWORDS_NUM; i++) {
        if(!strncmp(keywords[i].name, lex->token.start, strlen(keywords[i].name))){
            if(keywords[i].fun) return node_call(lex, i);
        }
    }
    node_t *node = node_alloc(lex, ND_ID);
    node->id = (id_node_t*) malloc(sizeof(id_node_t));
    if(!node->id) exit(ENOMEM);
    node->id->name = lex->token.start;
    node->id->len = lex->token.len;
    return node; 
}

/*
*   Węzeł oparcji binarnej
*/

node_t* node_binop(lexer_t *lex, node_t *left) {
    next_token(lex);
    token_type_t op = lex->token.type;
    node_t *right = node_expr(lex, node_handler[op].lbp);
    if(!right) return NULL;
    node_t *node = node_alloc(lex, ND_BINOP);
    node->op = op;
    node->child = left;
    left->next = right;
    return node;
}

/*
*   Węzeł operacji unarnej
*/

node_t* node_unop(lexer_t *lex) {
    token_type_t op = lex->token.type;
    node_t *expr = node_expr(lex, node_handler[op].lbp);
    if(!expr) return NULL;
    node_t *node = node_alloc(lex, ND_UNOP);
    node->op = op;
    node->child = expr;
    return node;
}

/*
*   Węzeł wywołania funkcji
*/

node_t* node_call(lexer_t *lex, uint8_t kw) {
    next_token(lex);
    if(lex->token.type != TK_LPAREN){
        return node_error(lex, "Syntax error: ( missing");
    }
    node_t *expr = node_group(lex);
    if(!expr) return NULL;
    node_t *node = node_alloc(lex, ND_CALL);
    node->op = kw;
    node->child = expr;
    return node;
}

/*
*   Węzeł przypisania
*/

node_t* node_assign(lexer_t *lex, node_t *left) {
    next_token(lex);
    if(left->type != ND_ID) return node_error(lex, "Assignment error");
    token_type_t op = lex->token.type;
    node_t *right = node_expr(lex, node_handler[op].lbp);
    if(!right) return NULL;
    node_t *node = node_alloc(lex, ND_ASSIGN);
    node->op = op;
    node->child = left;
    left->next = right;
    return node;
}

/*
*   Główna funkcja rekurencyjnego parsowania wyrażenia
*/

node_t* node_expr(lexer_t *lex, uint8_t rbp) {
    next_token(lex);
    prefix_fun_t prefix = node_handler[lex->token.type].prefix;
    node_t *node = prefix ? prefix(lex) : NULL;
    if(!node) return node_error(lex, "Syntax error");
    while(rbp < node_handler[lex->peek.type].lbp) {
        infix_fun_t infix = node_handler[lex->peek.type].infix;
        node = infix ? infix(lex, node) : node;
    }
    return node;
}

/*
*   Wydruki błędów parsowania
*/

node_t* node_error(lexer_t *lex, char *msg){
    if(lex->error) return NULL;
    lex->error = 1;
    fprintf(stderr, "%s [%lld]\n", msg, lex->token.start - lex->source);
    return NULL;
}

/*
*   Wywołanie parsera
*/

node_t* parse(char *expr) {
    lexer_t lex = lexer(expr);
    if(lex.peek.type == TK_EOF) return NULL;
    node_t *root = node_expr(&lex, 0);
    if(lex.peek.type != TK_EOF){
        next_token(&lex);
        return node_error(&lex, "Syntax error: unexpected expression");
    }
    return root;
}

/*
*   Wydruk drzewa
*/

void node_print(node_t *node, int indent) {
    if(!node) return;
    for(int i = 0; i < indent; i++) fprintf(stdout, "  ");
    switch(node->type) {
        case ND_VAL:
            switch(node->val.type){
                case type_flt: 
                    fprintf(stdout, "VAL %.2f\n", node->val.fnum); 
                    break;
                case type_int: 
                    fprintf(stdout, "VAL %lld\n", node->val.inum); 
                    break;
                case type_str: 
                    fprintf(stdout, "VAL '%s'\n", (char*)node->val.arr.ptr); 
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
            fprintf(stdout, "BINOP %c\n", node->op);
            node_print(node->child, indent + 1);
            node_print(node->child->next, indent + 1);
            break;
        case ND_UNOP:
            fprintf(stdout, "UNOP %c\n", node->op);
            node_print(node->child, indent + 1);
            break;
        case ND_CALL:
            fprintf(stdout, "CALL %s\n", keywords[node->op].name);
            node_print(node->child, indent + 1);
            node_t *next = node->child->next;
            while(next){
                node_print(next, indent + 1);
                next = next->next;
            }
            break;
        default:
            break;
    }
}

/*
*   Ewaluacja operacji arytmetycznych
*/

void binop_arithmetic(node_t *node) {
    node_t *lhs = node->child;
    node_t *rhs = node->child->next;

    if(!is_num(lhs->val.type) || !is_num(rhs->val.type)){
        eval_error(node, "Eval error: invalid operand type");
        return;
    }
    node->val.type = (is_flt(lhs->val.type) || is_flt(rhs->val.type)) ? type_flt : type_int;

    switch(node->val.type){
        case type_flt: {
            node->val.fnum = is_flt(lhs->val.type) ? lhs->val.fnum : lhs->val.inum;
            double rhs_val = is_flt(rhs->val.type) ? rhs->val.fnum : rhs->val.inum;
            switch(node->op) {
                case TK_PLUS: node->val.fnum += rhs_val; break;
                case TK_MINUS: node->val.fnum -= rhs_val; break;
                case TK_STAR: node->val.fnum *= rhs_val; break;
                case TK_SLASH: node->val.fnum /= rhs_val; break;
                default: break;
            }
            return;
        }
        case type_int: {
            node->val.inum = lhs->val.inum;
            switch(node->op) {
                case TK_PLUS: node->val.inum += rhs->val.inum; break;
                case TK_MINUS: node->val.inum -= rhs->val.inum; break;
                case TK_STAR: node->val.inum *= rhs->val.inum; break;
                case TK_SLASH: node->val.inum /= rhs->val.inum; break;
                default: break;
            }
            return;
        }
        default:
            return;
    }
}

void unop_negative(node_t *node){
    switch(node->child->val.type){
        case type_flt:
            node->val.fnum = -node->child->val.fnum;
            break;
        case type_int:
            node->val.inum = -node->child->val.inum;
            break;
        default: return;
    }
    node->val.type = node->child->val.type;
}

/*
*   Ewaluacja operacji binarnych
*/

void binop_bianry(node_t *node) {
    node_t *lhs = node->child;
    node_t *rhs = node->child->next;

    if(!is_int(lhs->val.type) || !is_int(rhs->val.type)) {
        eval_error(node, "Eval error: invalid operand type");
        return;
    }
    
    node->val.type = type_int;
    node->val.inum = lhs->val.inum;
    switch(node->op) {
        case TK_OR: node->val.inum  |= rhs->val.inum; return;
        case TK_AND: node->val.inum  &= rhs->val.inum; return;
        case TK_XOR: node->val.inum  ^= rhs->val.inum; return;
        default: return;
    }
}

void unop_negate(node_t *node){
    if(!is_int(node->child->val.type)) {
        eval_error(node, "Eval error: invalid operand type");
        return;
    }
    node->val.type = type_int;
    node->val.inum = ~node->child->val.inum;
}

/*
*   Ewaluacja instrukcji warunkowej ternary
*/

void binop_tern_col(node_t *node) {
    node_t *lhs = node->child;
    node_t *rhs = node->child->next;
    if(is_nil(lhs->val.type) || is_nil(rhs->val.type)) {
        eval_error(node, "Eval error: incorrect argument");
        return;
    }
}

void binop_tern_quest(node_t *node) {
    node_t *cond = node->child;
    node_t *alts = node->child->next;
    if(!is_num(cond->val.type)) {
        eval_error(node, "Eval error: incorrect condition");
        return;
    }
    if(alts->type != ND_BINOP || alts->op != TK_COL) {
        eval_error(node, "Eval error: incorrect alternatives");
        return;
    }
    if(cond->val.inum || cond->val.fnum){
        node->val = alts->child->val;
        if(is_arr(alts->child->val.type)){
            alts->child->val.arr.ptr = NULL;
        }
    }
    else{
        node->val = alts->child->next->val;
        if(is_arr(alts->child->next->val.type)){
            alts->child->next->val.arr.ptr = NULL;
        }
    }
}

/*
*   Ewaluacja funkcji wbudowanych
*/

void sin_eval(node_t *node){
    val_t *val = &node->child->val;
    if(!is_num(val->type)){
        eval_error(node, "Eval error: invalid argument type");
        return;
    }
    node->val.type = type_flt;
    node->val.fnum = sin(is_flt(val->type) ? val->fnum : val->inum);
}

void cos_eval(node_t *node){
    val_t *val = &node->child->val;
    if(!is_num(val->type)){
        eval_error(node, "Eval error: invalid argument type");
        return;
    }
    node->val.type = type_flt;
    node->val.fnum = cos(is_flt(val->type) ? val->fnum : val->inum);
}


/*
*   Tablice funkcji ewaluacji operatorów
*/

op_fun_t binop_eval[] = {
    [TK_PLUS] = binop_arithmetic,
    [TK_MINUS] = binop_arithmetic,
    [TK_STAR] = binop_arithmetic,
    [TK_SLASH] = binop_arithmetic,
    [TK_OR] = binop_bianry,
    [TK_AND] = binop_bianry,
    [TK_XOR] = binop_bianry,
    [TK_COL] = binop_tern_col,
    [TK_QUEST] = binop_tern_quest,
};

op_fun_t unop_eval[] = {
    [TK_MINUS] = unop_negative,
    [TK_NEG] = unop_negate,
};

/*
*   Wydruki błędów ewaluacji
*/

void eval_error(node_t *node, char *msg){
    if(node->type == ND_ID){
        fprintf(stderr, "%s %.*s [%llu]\n", msg, (int)node->id->len, node->id->name, node->token_pos);
        return;
    }
    fprintf(stderr, "%s [%llu]\n", msg, node->token_pos);
}

/*
*   Funkcja hashująca ukradziona z Lua
*/

uint32_t hash(const char *str, size_t len, uint32_t seed) {
    uint32_t h = seed ^ (uint32_t)(len);
    for(; len > 0; len--)
        h ^= ((h << 5) + (h >> 2) + (uint8_t)(str[len - 1]));
    return h;
}

/*
*   Globalne zmienne liczbowe
*/

void set_var(node_t *node, var_tab_t *vars) {
    node_t *left = node->child;
    node_t *right = node->child->next;
    size_t index = hash(left->id->name, left->id->len, (intptr_t)vars) & (VARTAB_SIZE - 1);
    size_t start = index;
    while(vars[index].name && strncmp(vars[index].name, left->id->name, left->id->len)){
        index = (index + 1) & (VARTAB_SIZE - 1);
        if(index == start) {
            eval_error(node, "Assignment error: variable table overflow");
            return;
        }
    }
    node_eval(right);
    if(is_nil(right->val.type)) return;

    if(!vars[index].name) {
        vars[index].name = (char*) calloc(left->id->len + 1, sizeof(char));
        memcpy(vars[index].name, left->id->name, left->id->len);
    }

    if(is_str(right->val.type)){
        alloc_str(&vars[index].val.arr.ptr, right->val.arr.ptr, right->val.arr.count);
        return;
    }

    vars[index].val = right->val;
}

void get_var(node_t *node, var_tab_t *vars){
    size_t index = hash(node->id->name, node->id->len, (intptr_t)vars) & (VARTAB_SIZE - 1);
    size_t start = index;
    uint8_t overflow = 0;
    while(vars[index].name && strncmp(vars[index].name, node->id->name, node->id->len)){
        index = (index + 1) & (VARTAB_SIZE - 1);
        if(index == start){
            overflow = 1;
            break;
        }
    }
    if(!vars[index].name || overflow){
        eval_error(node, "Unknown identifier:");
        return;
    }
    node->val = vars[index].val;
}

/*
*   Ewaluacja drzewa
*/

void node_eval(node_t *node){
    if(!node) return;
    switch(node->type) {
        case ND_VAL:
            return;
        case ND_ID:
            get_var(node, var_tab);
            return;
        case ND_BINOP:
            node_eval(node->child);
            node_eval(node->child->next);
            binop_eval[node->op](node);
            return;
        case ND_UNOP:
            node_eval(node->child);
            unop_eval[node->op](node);
            return;
        case ND_ASSIGN:
            set_var(node, var_tab);
            return;
        case ND_CALL:
            node_eval(node->child);
            keywords[node->op].fun(node);
            return;
        default:
            return;
    }
}

void node_echo(node_t *node){
    switch(node->val.type){
        case type_nil:
            return;
        case type_flt:
            fprintf(stdout, "%g\n", node->val.fnum);
            return;
        case type_int:
            fprintf(stdout, "%lld\n", node->val.inum);
            return;
        case type_str:
            fprintf(stdout, "'%s'\n", (char*)node->val.arr.ptr);
            return;
        default:
            return;
    }
}

/**
 ** Kompilator
 **/

typedef struct {
    size_t size;
    size_t capacity;
    uint8_t *data;
} dbuffer_t;

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

#define db_write_u32(db, val) do { uint32_t _v = (val); db_write(db, &_v, 4); } while(0)
#define db_write_u16(db, val) do { uint16_t _v = (val); db_write(db, &_v, 2); } while(0)
#define db_write_u8 (db, val) do { uint8_t  _v = (val); db_write(db, &_v, 1); } while(0)

/*
typedef enum {
    OP_LOAD,
    OP_PUSH,
    OP_POP,
    OP_ADD,
    OP_SUB,
    OP_MULT,
    OP_DIV,
    //OP_MOVE,
    //OP_LOAD,
    //OP_ADD,
    //OP_SUB,
    //OP_MULT,
    //OP_DIV,
    //OP_MOD,
    //OP_NEG,
    //OP_BAND,
    //OP_BOR,
    //OP_BXOR,
    //OP_BNOT,
    //OP_LSH,
    //OP_RSH,
    //OP_NOT,
    //OP_JMP,
    //OP_LT,
    //OP_LE, 
    //OP_TEST,
} opcodes_t;

void node_val_compile(node_t *node, dbuffer_t *data_buf, dbuffer_t *code_buf){
    size_t data_pos = data_buf->size;
    db_write(data_buf, node->val.type, sizeof(uint32_t));
    size_t len = type_size(node->val.type);
    switch(node->val.type){
        case type_int:
            db_write(data_buf, &node->val.inum, len);
            break;
        case type_flt:
            db_write(data_buf, &node->val.fnum, len);
            break;
        case type_arr:
            db_write(data_buf, node->val.arr.ptr, len);
            break;
    }
    uint32_t cmd;
}

void node_compile(node_t *node, dbuffer_t *data_buf, dbuffer_t *code_buf){
    if(!node) return;
    switch(node->type) {
        case ND_VAL:
            return;
        case ND_ID:
            get_var(node, var_tab);
            return;
        case ND_BINOP:
            node_eval(node->child);
            node_eval(node->child->next);
            binop_eval[node->op](node);
            return;
        case ND_UNOP:
            node_eval(node->child);
            unop_eval[node->op](node);
            return;
        case ND_ASSIGN:
            set_var(node, var_tab);
            return;
        case ND_CALL:
            node_eval(node->child);
            keywords[node->op].fun(node);
            return;
        default:
            return;
    }
}

void compile(node_t *node){
    dbuffer_t data_buf = db_create();
    dbuffer_t code_buf = db_create();

    node_compile(node, &data_buf, &code_buf);

    db_free(&data_buf);
    db_free(&code_buf);
}

*/


/*
*   Main
*/

#define BUFSIZE 256

int main(int argc, char *argv[]) { 
    char buffer[BUFSIZE];
    FILE *file = stdin;

    if(argc > 1) {
        file = fopen(argv[1], "r");
        if(!file) {
            fprintf(stderr, "Unable to open file \"%s\"\n", argv[1]);
            exit(EIO);
        }
    }


    
    if(file == stdin) fprintf(stdout, ">> ");
    while(fgets(buffer, BUFSIZE, file) != NULL){
        if(strncmp(buffer, "exit", 4) == 0) break;
        node_t *root = parse(buffer);
        if(root){
            node_print(root, 0);
            node_eval(root);
            node_echo(root);
            node_free(root);
        }
        if(file == stdin) fprintf(stdout, ">> ");
    }
    if(file != stdin) fclose(file);

    return 0;
}
