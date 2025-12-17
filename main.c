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
            node->val.size = sizeof(uint64_t);
            node->val.addr = lex->data->size;
            db_write(lex->data, &lex->token.inum, sizeof(uint64_t));
            node->nval.inum = lex->token.inum;
            break;
        case TK_FLT:
            node->val.type = type_flt;
            node->val.size = sizeof(double);
            node->val.addr = lex->data->size;
            db_write(lex->data, &lex->token.fnum, sizeof(double));
            node->nval.fnum = lex->token.fnum;
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
                case type_flt: 
                    fprintf(stdout, "VAL %.2f\n", *(double*)(db->data + node->val.addr)); 
                    break;
                case type_int: 
                    fprintf(stdout, "VAL %lld\n", *(int64_t*)(db->data + node->val.addr)); 
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
            node->nval.fnum = is_flt(lhs->val.type) ? lhs->nval.fnum : lhs->nval.inum;
            double rhs_val = is_flt(rhs->val.type) ? rhs->nval.fnum : rhs->nval.inum;
            switch(node->op) {
                case TK_PLUS: node->nval.fnum += rhs_val; break;
                case TK_MINUS: node->nval.fnum -= rhs_val; break;
                case TK_STAR: node->nval.fnum *= rhs_val; break;
                case TK_SLASH: node->nval.fnum /= rhs_val; break;
                default: break;
            }
            return;
        }
        case type_int: {
            node->nval.inum = lhs->nval.inum;
            switch(node->op) {
                case TK_PLUS: node->nval.inum += rhs->nval.inum; break;
                case TK_MINUS: node->nval.inum -= rhs->nval.inum; break;
                case TK_STAR: node->nval.inum *= rhs->nval.inum; break;
                case TK_SLASH: node->nval.inum /= rhs->nval.inum; break;
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
            node->nval.fnum = -node->child->nval.fnum;
            break;
        case type_int:
            node->nval.inum = -node->child->nval.inum;
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
    node->nval.inum = lhs->nval.inum;
    switch(node->op) {
        case TK_OR: node->nval.inum  |= rhs->nval.inum; return;
        case TK_AND: node->nval.inum  &= rhs->nval.inum; return;
        case TK_XOR: node->nval.inum  ^= rhs->nval.inum; return;
        default: return;
    }
}

void unop_negate(node_t *node){
    if(!is_int(node->child->val.type)) {
        eval_error(node, "Eval error: invalid operand type");
        return;
    }
    node->val.type = type_int;
    node->nval.inum = ~node->child->nval.inum;
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
    if(cond->nval.inum || cond->nval.fnum) {
        node->val = alts->child->val;
    }
    else {
        node->val = alts->child->next->val;
    }
}

/*
*   Ewaluacja funkcji wbudowanych
*/

void sin_eval(node_t *node) {
    val_info_t *val = &node->child->val;
    val_t *nval = &node->child->nval;
    if(!is_num(val->type)) {
        eval_error(node, "Eval error: invalid argument type");
        return;
    }
    node->val.type = type_flt;
    node->nval.fnum = sin(is_flt(val->type) ? nval->fnum : nval->inum);
}

void cos_eval(node_t *node) {
    val_info_t *val = &node->child->val;
    val_t *nval = &node->child->nval;
    if(!is_num(val->type)) {
        eval_error(node, "Eval error: invalid argument type");
        return;
    }
    node->val.type = type_flt;
    node->nval.fnum = cos(is_flt(val->type) ? nval->fnum : nval->inum);
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
        //alloc_str(&vars[index].val.addr, right->val.addr, right->val.arr.count);
        return;
    }
    vars[index].type = right->val.type;
    vars[index].val = right->nval;
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
    node->val.type = vars[index].type;
    node->nval = vars[index].val;
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
            fprintf(stdout, "%g\n", node->nval.fnum);
            return;
        case type_int:
            fprintf(stdout, "%lld\n", node->nval.inum);
            return;
        case type_str:
            //char *ptr = (char*)&db->data[node->val.addr];
            //fprintf(stdout, "'%s'\n", ptr);
            return;
        default:
            return;
    }
}

/**
 ** Kompilator
 **/

ibuffer_t ib_create(){
    return (ibuffer_t){ .capacity = 1024, .inst = malloc(1024 * sizeof(instruct_t)) };
}
void ib_write(ibuffer_t *ib, instruct_t inst){
    if(ib->size + sizeof(instruct_t) > ib->capacity) {
        size_t new_cap = ib->capacity * 2;
        ib->inst = realloc(ib->inst, new_cap);
        ib->capacity = new_cap;
    }
    memcpy(ib->inst + ib->size, &inst, sizeof(instruct_t));
    ib->size += sizeof(instruct_t);
}
void ib_free(ibuffer_t *ib){
    if(ib->inst) free(ib->inst);
}

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



comp_fun_t comp_binop[] = {
    [TK_PLUS] = comp_binop_arithmetic,
    [TK_MINUS] = comp_binop_arithmetic,
    [TK_STAR] = comp_binop_arithmetic,
    [TK_SLASH] = comp_binop_arithmetic,
    //[TK_OR] = comp_binop_binary,
    //[TK_AND] = comp_binop_binary,
    //[TK_XOR] = comp_binop_binary,
    //[TK_COL] = comp_binop_col,
    //[TK_QUEST] = comp_binop_quest,
};

//comp_fun_t unop_eval[] = {
//    [TK_MINUS] = unop_negative,
//    [TK_NEG] = unop_negate,
//};

void node_val_compile(node_t *node, ibuffer_t *ib){
    instruct_t inst;
    inst.arg = node->val.addr;
    switch(node->val.type){
        case type_int:
            inst.opcode = OP_LOAD_INT; 
            break;
        case type_flt:
            inst.opcode = OP_LOAD_FLT;
            break;
        case type_arr:
            return;
    }
    ib_write(ib, inst);
}

void comp_binop_arithmetic(node_t *node, ibuffer_t *ib){
    node_t *lhs = node->child;
    node_t *rhs = node->child->next;
    instruct_t inst = {0};

    if(!is_num(lhs->val.type) || !is_num(rhs->val.type)){
        eval_error(node, "Error: invalid operand type");
        return;
    }

    node->val.type = (is_flt(lhs->val.type) || is_flt(rhs->val.type)) ? type_flt : type_int;
    int types = ((lhs->val.type & type_flt) >> (VT_FLT - 1)) | ((rhs->val.type & type_flt) >> VT_FLT);
    switch(node->op){
        case TK_PLUS: {
            switch(types) {
                case 0: inst.opcode = OP_ADD_II; break;
                case 1: inst.opcode = OP_ADD_IF; break;
                case 2: inst.opcode = OP_ADD_FI; break;
                case 3: inst.opcode = OP_ADD_FF; break;
            }
            break;
        }
        case TK_MINUS:
            switch(types) {
                case 0: inst.opcode = OP_SUB_II; break;
                case 1: inst.opcode = OP_SUB_IF; break;
                case 2: inst.opcode = OP_SUB_FI; break;
                case 3: inst.opcode = OP_SUB_FF; break;
            }
            break;
    }
    ib_write(ib, inst);
}

void node_compile(node_t *node, ibuffer_t *ib){
    if(!node) return;
    switch(node->type) {
        case ND_VAL:
            node_val_compile(node, ib);
            return;
        case ND_ID:
            return;
        case ND_BINOP:
            node_compile(node->child, ib);
            node_compile(node->child->next, ib);
            comp_binop[node->op](node, ib);
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


void execute(dbuffer_t *db, ibuffer_t *ib){
    val_t stack[256];
    uint32_t sp = 0;
    uint32_t pc = 0;
    uint8_t run = 1;
    val_t rhs, lhs;
    while(run) {
        instruct_t inst = ib->inst[pc];
        switch(inst.opcode){
            case OP_HALT:
                run = 0;
                break;
            case OP_LOAD_INT:
                stack[sp].size = sizeof(uint64_t);
                stack[sp].inum = *(uint64_t*)(db->data + inst.arg);
                sp++; pc++;
                break;
            case OP_LOAD_FLT:
                stack[sp].size = sizeof(double);
                stack[sp].inum = *(double*)(db->data + inst.arg);
                sp++; pc++;
                break;
            case OP_ADD_II:
                rhs = stack[--sp];
                lhs = stack[--sp];
                stack[sp].type = type_int;
                stack[sp].inum = lhs.inum + rhs.inum;
                sp++; pc++;
                break;
            case OP_ADD_IF:
                rhs = stack[--sp];
                lhs = stack[--sp];
                stack[sp].type = type_int;
                stack[sp].inum = lhs.inum + rhs.inum;
                sp++; pc++;
                break;
            case OP_ADD_FI:
                rhs = stack[--sp];
                lhs = stack[--sp];
                stack[sp].type = type_int;
                stack[sp].inum = lhs.inum + rhs.inum;
                sp++; pc++;
                break;
            case OP_ADD_FF:
                rhs = stack[--sp];
                lhs = stack[--sp];
                stack[sp].type = type_int;
                stack[sp].inum = lhs.inum + rhs.inum;
                sp++; pc++;
                break;
        }
    }
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
            node_eval(root);
            ibuffer_t code_buf = ib_create();
            node_compile(root, &code_buf);
            instruct_t inst = {.opcode = OP_HALT};
            ib_write(&code_buf, inst);
            execute(&data_buf, &code_buf);
            ib_free(&code_buf);
            node_echo(root);
            node_free(root);
        }
        db_free(&data_buf);
        if(file == stdin) fprintf(stdout, ">> ");
    }
    if(file != stdin) fclose(file);

    return 0;
}
