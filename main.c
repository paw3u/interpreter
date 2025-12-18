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

lexer_t lexer(char *str, dbuffer_t *data) {
    lexer_t lex;
    lex.source = str;
    lex.pos = lex.source;
    lex.error = 0;
    lex.data = data;
    next_token(&lex);
    return lex;
}

/*
*   Parametry operatorów: handlery prefix, infix, moc wiązania
*/

node_handler_t node_handler[] = {
    [TK_NUM]    = { node_val,   NULL,           0  },
    [TK_STR]    = { node_val,   NULL,           0  },
    [TK_ID]     = { node_id,    NULL,           0  },
    [TK_LPAREN] = { node_group, NULL,           0  },
    [TK_RPAREN] = { NULL,       NULL,           0  },
    [TK_IF]     = { NULL,       NULL,           8  },
    [TK_THEN]   = { NULL,       NULL,           8  },
    [TK_ELSE]   = { NULL,       NULL,           8  },
    [TK_ELIF]   = { NULL,       NULL,           8  },
    [TK_END]    = { NULL,       NULL,           8  },
    [TK_EQ]     = { NULL,       node_assign,    9  },
    [TK_PLUS]   = { NULL,       node_binop,     10 },
    [TK_MINUS]  = { node_unop,  node_binop,     10 },
    [TK_STAR]   = { NULL,       node_binop,     20 },
    [TK_SLASH]  = { NULL,       node_binop,     20 },
    [TK_AND]    = { NULL,       node_binop,     30 },
    [TK_OR]     = { NULL,       node_binop,     30 },
    [TK_XOR]    = { NULL,       node_binop,     30 },
    [TK_TILDE]  = { node_unop,  NULL,           30 },
};

/*
*   Słowa kluczowe i funkcje
*/

keyword_t keywords[] = {
    //[KW_SIN]    = { "sin",      0,          sin_eval },
    //[KW_COS]    = { "cos",      0,          cos_eval },
    [KW_IF]     = { "if",       TK_IF,      NULL },
    [KW_THEN]   = { "then",     TK_THEN,    NULL },
    [KW_ELSE]   = { "else",     TK_ELSE,    NULL },
    [KW_ELIF]   = { "elseif",   TK_ELIF,    NULL },
    [KW_END]    = { "end",      TK_END,     NULL },
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
        case TK_NUM:
            node->val.type = type_num;
            node->val.size = sizeof(double);
            node->val.addr = lex->data->size;
            db_write(lex->data, &lex->token.num, sizeof(double));
            break;
        case TK_STR:
            node->val.type = type_str;
            node->val.size = lex->token.len + 1;
            node->val.addr = lex->data->size;
            db_write(lex->data, lex->token.start, lex->token.len);
            db_write_u8(lex->data, 0);
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
            switch(i) {
                case KW_IF:
                case KW_ELSE:
                case KW_ELIF:
                case KW_END:
                    return node_if(lex, keywords[i].token);
            }
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
*   Węzeł instrukcji warunkowej
*/

node_t* node_if(lexer_t *lex, token_type_t op) {
    if(op != KW_IF) {
        return node_error(lex, "'if' statement syntax error");
    }

    next_token(lex);
    node_t *cond = node_expr(lex, node_handler[op].lbp);
    if(!cond) return NULL;

    next_token(lex);
    if(lex->token.type != TK_THEN){
        return node_error(lex, "'if' statement syntax error: 'then' missing");
    }
    next_token(lex);
    node_t *expr_true = node_expr(lex, node_handler[op].lbp);
    if(!expr_true) return NULL;

    next_token(lex);
    node_t *expr_false = node_expr(lex, node_handler[op].lbp);
    if(!expr_false) return NULL;

    return cond;
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

node_t* parse(char *expr, dbuffer_t *data) {
    lexer_t lex = lexer(expr, data);
    if(lex.peek.type == TK_EOF) return NULL;
    node_t *root = node_expr(&lex, 0);
    if(lex.peek.type != TK_EOF) {
        next_token(&lex);
        return node_error(&lex, "Syntax error: unexpected expression");
    }
    return root;
}

/*
*   Wydruk drzewa
*/

void node_print(node_t *node, dbuffer_t *db, int indent) {
    if(!node) return;
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
            fprintf(stdout, "BINOP %c\n", node->op);
            node_print(node->child, db, indent + 1);
            node_print(node->child->next, db, indent + 1);
            break;
        case ND_UNOP:
            fprintf(stdout, "UNOP %c\n", node->op);
            node_print(node->child, db, indent + 1);
            break;
        case ND_CALL:
            fprintf(stdout, "CALL %s\n", keywords[node->op].name);
            node_print(node->child, db, indent + 1);
            node_t *next = node->child->next;
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
*   Wydruki błędów kompilacji
*/

void comp_error(node_t *node, char *msg){
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
            comp_error(node, "Assignment error: variable table overflow");
            return;
        }
    }
    //node_eval(right);
    if(is_nil(right->val.type)) return;

    if(!vars[index].name) {
        vars[index].name = (char*) calloc(left->id->len + 1, sizeof(char));
        memcpy(vars[index].name, left->id->name, left->id->len);
    }

    if(is_str(right->val.type)){
        //alloc_str(&vars[index].val.addr, right->val.addr, right->val.arr.count);
        return;
    }
    vars[index].type = right->val.type;
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
        comp_error(node, "Unknown identifier:");
        return;
    }
    node->val.type = vars[index].type;
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
 *  Tablica funkcji kompilacji
 */

comp_fun_t comp_binop[] = {
    [TK_PLUS] = comp_num_binop,
    [TK_MINUS] = comp_num_binop,
    [TK_STAR] = comp_num_binop,
    [TK_SLASH] = comp_num_binop,
    [TK_OR] = comp_num_binop,
    [TK_AND] = comp_num_binop,
    [TK_XOR] = comp_num_binop,
    //[TK_COL] = comp_binop_col,
    //[TK_QUEST] = comp_binop_quest,
};

comp_fun_t comp_unop[] = {
    [TK_MINUS] = comp_num_unop,
    [TK_TILDE] = comp_num_unop,
};

/*
*   Kompilacja węzła z wartością stałą
*/

void comp_node_val(node_t *node, ibuffer_t *ib){
    switch(node->val.type){
        case type_num:
            ib_write(ib, OP_LOAD, node->val.addr);
            break;
        case type_arr:
            return;
    }
}

void comp_node_call(node_t *node, ibuffer_t *ib){

}

/*
*   Kompilacja węzła operacji binarnych na danych liczbowych
*/

void comp_num_binop(node_t *node, ibuffer_t *ib){
    node_t *lhs = node->child;
    node_t *rhs = node->child->next;

    if(!is_num(lhs->val.type) || !is_num(rhs->val.type)){
        comp_error(node, "Error: invalid operand type");
        return;
    }
    node->val.type = type_num;

    switch(node->op){
        case TK_PLUS: ib_write(ib, OP_ADD, 0); return;
        case TK_MINUS: ib_write(ib, OP_SUB, 0); return;
        case TK_STAR: ib_write(ib, OP_MULT, 0); return;
        case TK_SLASH: ib_write(ib, OP_DIV, 0); return;
        case TK_AND: ib_write(ib, OP_BAND, 0); return;
        case TK_OR: ib_write(ib, OP_BOR, 0); return;
        case TK_XOR: ib_write(ib, OP_BXOR, 0); return;
        default: return;
    }
}

/*
*   Kompilacja węzła operacji unarnych na danych liczbowych
*/

void comp_num_unop(node_t *node, ibuffer_t *ib){
    node_t *arg = node->child;

    if(!is_num(arg->val.type)){
        comp_error(node, "Error: invalid operand type");
        return;
    }
    node->val.type = type_num;

    switch(node->op){
        case TK_MINUS: ib_write(ib, OP_NEG, 0); return;
        case TK_TILDE: ib_write(ib, OP_BNOT, 0); return;
        default: return;
    }
}

/*
*   Kompilacja węzła
*/

void comp_node(node_t *node, ibuffer_t *ib){
    if(!node) return;
    switch(node->type) {
        case ND_VAL:
            comp_node_val(node, ib);
            return;
        case ND_ID:
            return;
        case ND_BINOP:
            comp_node(node->child, ib);
            comp_node(node->child->next, ib);
            comp_binop[node->op](node, ib);
            return;
        case ND_UNOP:
            comp_node(node->child, ib);
            comp_unop[node->op](node, ib);
            return;
        case ND_ASSIGN:
            //set_var(node, var_tab);
            return;
        case ND_CALL:
            comp_node(node->child, ib);
            comp_node_call(node, ib);
            return;
        default:
            return;
    }
}

/*
*   Maszyna wirtualna wykonująca bytecode
*/

void execute(dbuffer_t *db, ibuffer_t *ib){
    val_t stack[256];
    uint32_t sp = 0;
    uint32_t pc = 0;

    // Musi się zgadzać z opcode_t
    static void *op_table[] = {
        &&op_halt, &&op_load, &&op_add, &&op_sub,
        &&op_mult, &&op_div, &&op_idiv, &&op_mod,
        &&op_neg, &&op_band, &&op_bor, &&op_bxor, 
        &&op_bnot, &&op_call, &&op_print
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
}

/*
*   Main
*/

#define BUFSIZE 256

int main(int argc, char *argv[]) { 
    char line[BUFSIZE];
    FILE *file = stdin;

    if(argc > 1) {
        file = fopen(argv[1], "r");
        if(!file) {
            fprintf(stderr, "Unable to open file \"%s\"\n", argv[1]);
            exit(EIO);
        }
    }

    if(file == stdin) fprintf(stdout, ">> ");
    while(fgets(line, BUFSIZE, file) != NULL){
        if(strncmp(line, "exit", 4) == 0) break;
        dbuffer_t data_buf = db_create();
        node_t *root = parse(line, &data_buf);
        if(root){
            node_print(root, &data_buf, 0);
            ibuffer_t code_buf = {0};
            comp_node(root, &code_buf);
            ib_write(&code_buf, OP_PRINT, 0);
            ib_write(&code_buf, OP_HALT, 0);
            execute(&data_buf, &code_buf);
            ib_free(&code_buf);
            node_free(root); 
        }
        db_free(&data_buf);
        if(file == stdin) fprintf(stdout, ">> ");
    }
    if(file != stdin) fclose(file);

    return 0;
}
