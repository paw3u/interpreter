#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
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
            lex->peek.num_int = strtol(lex->peek.start, &lex->pos, 16);
            lex->peek.len = lex->pos - lex->peek.start;
            return;
        }
        while(isdigit(*lex->pos)) lex->pos++;
        if(*lex->pos != '.') {
            lex->peek.type = TK_INT;
            lex->peek.num_int = strtol(lex->peek.start, NULL, 10);
        }
        else {
            lex->peek.type = TK_FLT;
            lex->peek.num_flt = strtod(lex->peek.start, &lex->pos);
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
    return node;
}

/*
*   Zwalnianie pamięci drzewa
*/

void node_free(node_t *node) {
    while(node){
        if(node->val.ptr) free(node->val.ptr);
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

void new_flt(void **dst, double *src, size_t count){
    if(*dst) free(*dst);
    *dst = malloc(count * sizeof(double));
    if(!*dst) exit(ENOMEM);
    memcpy(*dst, src, count * sizeof(double));
}

void new_int(void **dst, int *src, size_t count){
    if(*dst) free(*dst);
    *dst = malloc(count * sizeof(int));
    if(!*dst) exit(ENOMEM);
    memcpy(*dst, src, count * sizeof(int));
}

void new_str(void **dst, char *src, size_t count){
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
            node->val.type = TYPE_INT;
            node->val.count = 1;
            new_int(&node->val.ptr, &lex->token.num_int, 1);
            break;
        case TK_FLT:
            node->val.type = TYPE_FLT;
            node->val.count = 1;
            new_flt(&node->val.ptr, &lex->token.num_flt, 1);
            break;
        case TK_STR:
            node->val.type = TYPE_STR;
            node->val.count = lex->token.len;
            new_str(&node->val.ptr, lex->token.start, node->val.count);
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

node_t* node_call(lexer_t *lex, int kw) {
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

node_t* node_expr(lexer_t *lex, int rbp) {
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
                case TYPE_FLT: 
                    fprintf(stdout, "VAL %.2f\n", *(double*)node->val.ptr); 
                    break;
                case TYPE_INT: 
                    fprintf(stdout, "VAL %d\n", *(int*)node->val.ptr); 
                    break;
                case TYPE_STR: 
                    fprintf(stdout, "VAL '%s'\n", (char*)node->val.ptr); 
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

    if((lhs->val.type != TYPE_FLT && lhs->val.type != TYPE_INT)
    || (rhs->val.type != TYPE_FLT && rhs->val.type != TYPE_INT)) 
        node->val.type = TYPE_NONE;
    else
        node->val.type = (lhs->val.type == TYPE_FLT || rhs->val.type == TYPE_FLT) ? TYPE_FLT : TYPE_INT;

    node->val.count = 1;

    switch(node->val.type){
        case TYPE_NONE: return;
        case TYPE_FLT: {
            double result = (lhs->val.type == TYPE_FLT) ? *(double*)lhs->val.ptr : *(int*)lhs->val.ptr;
            double operand = (rhs->val.type == TYPE_FLT) ? *(double*)rhs->val.ptr : *(int*)rhs->val.ptr;
            switch(node->op) {
                case TK_PLUS: result += operand; break;
                case TK_MINUS: result -= operand; break;
                case TK_STAR: result *= operand; break;
                case TK_SLASH: result /= operand; break;
                default: break;
            }
            new_flt(&node->val.ptr, &result, 1);
            return;
        }
        case TYPE_INT: {
            int result = *(int*)lhs->val.ptr;
            int operand = *(int*)rhs->val.ptr;
            switch(node->op) {
                case TK_PLUS: result += operand; break;
                case TK_MINUS: result -= operand; break;
                case TK_STAR: result *= operand; break;
                case TK_SLASH: result /= operand; break;
                default: break;
            }
            new_int(&node->val.ptr, &result, 1);
            return;
        }
        default:
            return;
    }
}

void unop_negative(node_t *node){
    node_val_t *val = &node->child->val;
    switch(val->type){
        case TYPE_FLT: {
            double neg = -(*(double*)val->ptr);
            new_flt(&node->val.ptr, &neg, val->count);
            break;
        }
        case TYPE_INT: {
            int neg = -(*(int*)val->ptr);
            new_int(&node->val.ptr, &neg, val->count);
            break;
        }
        default:
            return;
    }
    node->val.type = val->type;
    node->val.count = 1;
}

/*
*   Ewaluacja operacji binarnych
*/

void binop_bianry(node_t *node) {
    node_t *lhs = node->child;
    node_t *rhs = node->child->next;

    if(lhs->val.type != TYPE_INT || rhs->val.type != TYPE_INT) {
        eval_error(node, "Eval error: invalid operand type");
        return;
    }
    
    node->val.type = TYPE_INT;
    node->val.count = 1;
    int result = *(int*)lhs->val.ptr;
    int operand = *(int*)rhs->val.ptr;
    switch(node->op) {
        case TK_OR: result |= operand; break;
        case TK_AND: result &= operand; break;
        case TK_XOR: result ^= operand; break;
        default: break;
    }
    new_int(&node->val.ptr, &result, 1);
}

void unop_negate(node_t *node){
    node_val_t *val = &node->child->val;
    if(val->type != TYPE_INT) {
        eval_error(node, "Eval error: invalid operand type");
        return;
    }
    node->val.type = TYPE_INT;
    node->val.count = 1;
    int neg = ~(*(int*)val->ptr);
    new_int(&node->val.ptr, &neg, val->count);
}

/*
*   Ewaluacja funkcji wbudowanych
*/

void sin_eval(node_t *node){
    node_val_t *val = &node->child->val;
    switch(val->type){
        case TYPE_FLT: {
            double arg = sin(*(double*)val->ptr);
            new_flt(&node->val.ptr, &arg, val->count);
            break;
        }
        case TYPE_INT: {
            double arg = sin(*(int*)val->ptr);
            new_flt(&node->val.ptr, &arg, val->count);
            break;
        }
        default:
            eval_error(node, "Eval error: invalid argument type");
            return;
    }
    node->val.type = TYPE_FLT;
    node->val.count = 1;
}

void cos_eval(node_t *node){
    node_val_t *val = &node->child->val;
    switch(val->type){
        case TYPE_FLT: {
            double arg = cos(*(double*)val->ptr);
            new_flt(&node->val.ptr, &arg, val->count);
            break;
        }
        case TYPE_INT: {
            double arg = cos(*(int*)val->ptr);
            new_flt(&node->val.ptr, &arg, val->count);
            break;
        }
        default:
            eval_error(node, "Eval error: incorrect argument type");
            return;
    }
    node->val.type = TYPE_FLT;
    node->val.count = 1;
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
        fprintf(stderr, "%s %.*s [%d]\n", msg, (int)node->id->len, node->id->name, node->token_pos);
        return;
    }
    fprintf(stderr, "%s [%d]\n", msg, node->token_pos);
}

/*
*   Funkcja hashująca ukradziona z Lua
*/

unsigned int hash(const char *str, size_t len, unsigned int seed) {
    unsigned int h = seed ^ (unsigned int)(len);
    for(; len > 0; len--)
        h ^= ((h << 5) + (h >> 2) + (unsigned char)(str[len - 1]));
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
    if(right->val.type == TYPE_NONE) return;
    switch(right->val.type){
        case TYPE_FLT:
            new_flt(&vars[index].value.ptr, right->val.ptr, right->val.count);
            break;
        case TYPE_INT: 
            new_int(&vars[index].value.ptr, right->val.ptr, right->val.count);
            break;
        case TYPE_STR:
            new_str(&vars[index].value.ptr, right->val.ptr, right->val.count);
            break;
        default:
            eval_error(node, "Unsupported variable type");
            return;
    }
    vars[index].value.count = right->val.count;
    vars[index].value.type = right->val.type;
    if(!vars[index].name) {
        vars[index].name = (char*) calloc(left->id->len + 1, sizeof(char));
        memcpy(vars[index].name, left->id->name, left->id->len);
    }
}

void get_var(node_t *node, var_tab_t *vars){
    size_t index = hash(node->id->name, node->id->len, (intptr_t)vars) & (VARTAB_SIZE - 1);
    size_t start = index;
    int overflow = 0;
    while(vars[index].name && strncmp(vars[index].name, node->id->name, node->id->len)){
        index = (index + 1) & (VARTAB_SIZE - 1);
        if(index == start){
            overflow = 1;
            break;
        }
    }
    if(!vars[index].name || overflow){
        eval_error(node, "Unknown identifier:");
        node->val.type = TYPE_NONE;
        return;
    }
    node->val.count = vars[index].value.count;
    node->val.type = vars[index].value.type;
    switch(node->val.type){
        case TYPE_FLT:
            new_flt(&node->val.ptr, vars[index].value.ptr, node->val.count);
            break;
        case TYPE_INT:
            new_int(&node->val.ptr, vars[index].value.ptr, node->val.count);
            break;
        case TYPE_STR:
            new_str(&node->val.ptr, vars[index].value.ptr, node->val.count);
            break;
        default:
            eval_error(node, "Unsupported variable type");
            return;
    }
}

/*
*   Ewaluacja drzewa
*/

void node_eval(node_t *node){
    if(!node || node->val.ptr) return;
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

/*
*   Main
*/

#define BUFSIZE 256

int main(int argc, char *argv[]) { 
    
    char buffer[BUFSIZE];

    fprintf(stdout, ">> ");
    while(fgets(buffer, BUFSIZE, stdin) != NULL){
        if(strncmp(buffer, "exit", 4) == 0) break;
        node_t *root = parse(buffer);
        if(root){
            //node_print(root, 0);
            node_eval(root);
            switch(root->val.type){
                case TYPE_NONE:
                    break;
                case TYPE_FLT:
                    fprintf(stdout, "%g\n", *(double*)root->val.ptr);
                    break;
                case TYPE_INT:
                    fprintf(stdout, "%d\n", *(int*)root->val.ptr);
                    break;
                case TYPE_STR:
                    fprintf(stdout, "'%s'\n", (char*)root->val.ptr);
                    break;
                default:
                    break;
            }
            node_free(root);
        }
        fprintf(stdout, ">> ");
    }

    return 0;
}
