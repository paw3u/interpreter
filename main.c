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
    lex->peek.length = 1;

    if(!*lex->pos) { lex->peek.type = TK_EOF; return; }

    char c = *lex->pos++;

    if(isdigit(c)) {
        lex->peek.number = strtod(lex->peek.start, &lex->pos);
        lex->peek.type = TK_NUM;
        lex->peek.length = lex->pos - lex->peek.start;
        return;
    }
    if(isalpha(c)) {
        while(isalpha(*lex->pos)) lex->pos++;
        lex->peek.type = TK_ID;
        lex->peek.length = lex->pos - lex->peek.start;
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
*   Parametry operatorów: handlery prefix, infix, moc wiązania, ewaluacja
*/

node_handler_t node_handler[] = {
    [TK_NUM]    = { node_num,   NULL,           0  },
    [TK_ID]     = { node_id,    NULL,           0  },
    [TK_LPAREN] = { node_group, NULL,           0  },
    [TK_EQ]     = { NULL,       node_assign,    1  },
    [TK_PLUS]   = { NULL,       node_binop,     10 },
    [TK_MINUS]  = { node_unop,  node_binop,     10 },
    [TK_STAR]   = { NULL,       node_binop,     20 },
    [TK_SLASH]  = { NULL,       node_binop,     20 },
    [TK_B_AND]  = { NULL,       node_binop,     30 },
    [TK_B_OR]   = { NULL,       node_binop,     30 },
    [TK_B_XOR]  = { NULL,       node_binop,     30 },
    [TK_B_NEG]  = { node_unop,  NULL,           30 },
};

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
        node_error(lex, ERR_RPAREN);
    }
    return expr;
}

/*
*   Węzeł liczbowy
*/

node_t* node_num(lexer_t *lex) {
    node_t *node = node_alloc(lex, ND_NUM);
    node->number = lex->token.number;
    return node;
}

/*
*   Węzeł identyfikatora
*/

node_t* node_id(lexer_t *lex) {
    node_t *node = node_alloc(lex, ND_ID);
    node->id.name = lex->token.start;
    node->id.len = lex->token.length;
    node->id.type = ID_NUM; // Na razie tylko zmienne liczbowe
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

node_t* node_call(lexer_t *lex) {
    node_t *node = node_alloc(lex, ND_CALL);
    return node;
}

/*
*   Węzeł przypisania
*/

node_t* node_assign(lexer_t *lex, node_t *left) {
    next_token(lex);
    if(left->type != ND_ID) return node_error(lex, ERR_ASSIGN);
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
    if(!node) return node_error(lex, ERR_EXPR);
    while(rbp < node_handler[lex->peek.type].lbp) {
        infix_fun_t infix = node_handler[lex->peek.type].infix;
        node = infix ? infix(lex, node) : node;
    }
    return node;
}

/*
*   Wydruki błędów parsowania
*/

node_t* node_error(lexer_t *lex, err_t type){
    if(lex->error) return NULL;
    lex->error = type;
    switch(type) {
        case ERR_EXPR:
            fprintf(stderr, "Syntax error: %d\n", lex->token.start - lex->source);
            break;
        case ERR_RPAREN:
            fprintf(stderr, "')' missing: %d\n", lex->token.start - lex->source);
            break;
        case ERR_ASSIGN:
            fprintf(stderr, "Assignment error: %d\n", lex->token.start - lex->source);
            break;
        default:
            break;
    }
    return NULL;
}

/*
*   Wywołanie parsera
*/

node_t* parse(char *expr) {
    err_t error = 0;
    lexer_t lex = lexer(expr);
    if(lex.peek.type == TK_EOF) return NULL;
    return node_expr(&lex, 0);
}

/*
*   Wydruk drzewa
*/

void node_print(node_t *node, int indent) {
    if(!node) return;
    for(int i = 0; i < indent; i++) printf("  ");
    switch(node->type) {
        case ND_NUM: 
            printf("NUM %.2f\n", node->number); 
            break;
        case ND_ID:
            printf("ID %.*s\n", node->id.len, node->id.name);
            break;
        case ND_BINOP:
        case ND_ASSIGN:
            printf("BINOP %c\n", node->op);
            node_print(node->child, indent + 1);
            node_print(node->child->next, indent + 1);
            break;
        case ND_UNOP:
            printf("UNOP %c\n", node->op);
            node_print(node->child, indent + 1);
            break;
    }
}

/*
*   Ewaluacja funkcji arytmetycznych
*/

static double eval_mult(double lhs, double rhs) {
    return lhs * rhs;
}

static double eval_div(double lhs, double rhs) {
    return lhs / rhs;
}

static double eval_sub(double lhs, double rhs) {
    return lhs - rhs;
}

static double eval_add(double lhs, double rhs) {
    return lhs + rhs;
}

binop_fun_t binop_eval[] = {
    [TK_PLUS] = eval_add,
    [TK_MINUS] = eval_sub,
    [TK_STAR] = eval_mult,
    [TK_SLASH] = eval_div,
};

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

#define VARTAB_SIZE (1 << 8) // Max 256 różnych identyfikatorów

static var_tab_t var_tab[VARTAB_SIZE] = {0};

void set_var(node_t *node, var_tab_t *vars) {
    node_t *left = node->child;
    node_t *right = node->child->next;
    size_t index = hash(left->id.name, left->id.len, (intptr_t)vars) & (VARTAB_SIZE - 1);
    int val_return = 1;
    switch(node->id.type){
        case ID_NUM:{
            // Przesuwamy się dopóki nazwa się nie zgadza lub mamy wolny indeks
            size_t start = index;
            while(vars[index].name && strncmp(vars[index].name, left->id.name, left->id.len)){
                index = (index + 1) & (VARTAB_SIZE - 1);
                if(index == start){ // Brak miejsca
                    fprintf(stderr, "Assignment error: variable table overflow\n");
                    return;
                }
            }
            double value = node_eval(right, &val_return);
            if(!val_return) return;
            vars[index].value = value;
            if(!vars[index].name){
                vars[index].name = (char*) malloc(left->id.len + 1);
                memcpy(vars[index].name, left->id.name, left->id.len);
                vars[index].name[left->id.len] = 0;
            }
            break;
        }
    }
}

double get_var(node_t *node, var_tab_t *vars, int *val_return){
    size_t index = hash(node->id.name, node->id.len, (intptr_t)vars) & (VARTAB_SIZE - 1);
    // Przesuwamy się dopóki nazwa się nie zgadza
    size_t start = index;
    int overflow = 0;
    while(vars[index].name && strncmp(vars[index].name, node->id.name, node->id.len)){
        index = (index + 1) & (VARTAB_SIZE - 1);
        if(index == start){ // Wróciliśmy do początku
            overflow = 1;
            break;
        }
    }
    if(!vars[index].name || overflow){
        fprintf(stderr, "Undefined identifier: %.*s\n", node->id.len, node->id.name);
        *val_return = 0;
        return 0;
    }
    return vars[index].value;
}

/*
*   Ewaluacja drzewa
*/

double node_eval(node_t *node, int *val_return){
    if(!node) return 0;
    switch(node->type) {
        case ND_NUM:
            return node->number;
        case ND_ID:
            return get_var(node, var_tab, val_return);
        case ND_BINOP:
            return binop_eval[node->op](
                node_eval(node->child, val_return),
                node_eval(node->child->next, val_return));
            return 0;
        case ND_UNOP:                
            return 0;
        case ND_ASSIGN:
            set_var(node, var_tab);
            *val_return = 0;
            return 0;
    }
    return 0;
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
            int val_return = 1;
            double value = node_eval(root, &val_return);
            if(val_return) fprintf(stdout, "%g\n", value);
            node_free(root);
        }
        fprintf(stdout, ">> ");
    }

    return 0;
}
