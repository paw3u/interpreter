#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "main.h"

// ================ Lexer ================ //

void next_token(lexer_t *lex) {
    while(*lex->pos && isspace(*lex->pos)) lex->pos++;

    lex->token.start = lex->pos;
    lex->token.length = 1;

    if(!*lex->pos) { lex->token.type = TK_EOF; return; }

    char c = *lex->pos++;

    if(isdigit(c)) {
        lex->token.number = strtod(lex->token.start, &lex->pos);
        lex->token.type = TK_NUM;
        lex->token.length = lex->pos - lex->token.start;
        return;
    }
    if(isalpha(c)) {
        while(isalpha(*lex->pos)) lex->pos++;
        lex->token.type = TK_ID;
        lex->token.length = lex->pos - lex->token.start;
        return;
    }

    lex->token.type = c;
}

lexer_t lexer(char *str) {
    lexer_t lex;
    lex.source = str;
    lex.pos = lex.source;
    //next_token(&lex);
    return lex;
}

// ================ Parser ================ //

node_handler_t node_handler[] = {
    [TK_NUM]    = {node_num,    NULL,       0},
    [TK_ID]     = {node_id,     NULL,       0},
    [TK_LPAREN] = {node_group,  NULL,       0},
    [TK_RPAREN] = {node_group,  NULL,       0},
    [TK_PLUS]   = {NULL,        node_binop, 10},
    [TK_MINUS]  = {NULL,        node_binop, 10},
    [TK_MULT]   = {NULL,        node_binop, 20},
    [TK_DIV]    = {NULL,        node_binop, 20},
    [TK_POW]    = {NULL,        node_binop, 30},
};

node_t* node_alloc(lexer_t *lex, node_type_t type) {
    node_t *node = (node_t*) calloc(1, sizeof(node_t));
    node->type = type;
    node->token_pos = lex->token.start - lex->source;
    return node;
}

void node_free(node_t *node) {
    while(node){
        node_t *next = node->next;
        node_free(node->child);
        if(node->type == ND_ID) free(node->id);
        free(node);
        node = next;
    }
}

node_t* node_group(lexer_t *lex) {
    node_t *expr = node_expr(lex, 0);
    if(!expr) return NULL;
    if(lex->token.type != TK_RPAREN){
        node_error(ERR_RPAREN, lex->token.start - lex->source);
    }
    return expr;
}

node_t* node_num(lexer_t *lex) {
    node_t *node = node_alloc(lex, ND_NUM);
    node->number = lex->token.number;
    return node;
}

node_t* node_id(lexer_t *lex) {
    node_t *node = node_alloc(lex, ND_ID);
    char *name = (char*) malloc(lex->token.length + 1);
    memcpy(name, lex->token.start, lex->token.length);
    name[lex->token.length] = '\0';
    return node;
}

node_t* node_binop(lexer_t *lex, node_t *left) {
    token_type_t op = lex->token.type;
    node_t *right = node_expr(lex, node_handler[op].lbp);
    if(!right) return NULL;
    node_t *node = node_alloc(lex, ND_BINOP);
    node->op = op;
    node->child = left;
    left->next = right;
    return node;
}

node_t* node_unop(lexer_t *lex) {
    node_t *node = node_alloc(lex, ND_UNOP);
    return node;
}

node_t* node_call(lexer_t *lex) {
    node_t *node = node_alloc(lex, ND_CALL);
    return node;
}

node_t* node_expr(lexer_t *lex, int rbp) {
    next_token(lex);
    prefix_fun_t prefix = node_handler[lex->token.type].prefix;
    node_t *node = prefix ? prefix(lex) : NULL;
    if(!node){
        return node_error(ERR_BAD_TK, lex->token.start - lex->source);
    }
    next_token(lex);
    while(rbp < node_handler[lex->token.type].lbp) {
        infix_fun_t infix = node_handler[lex->token.type].infix;
        node = infix ? infix(lex, node) : node;
        if(!node) return NULL;
    }
    return node;
}

static parse_err_t error = {0};

node_t* node_error(err_t type, int pos){
    if(type == error.type && pos == error.pos) return NULL;
    error.type = type;
    error.pos = pos;
    switch (type) {
        case ERR_BAD_TK:
            fprintf(stderr, "Wrong token at: %d\n", pos);
            break;
        case ERR_RPAREN:
            fprintf(stderr, "')' missing at: %d\n", pos);
            break;
        default:
            break;
    }
    return NULL;
}

node_t* parse(char *expr) {
    lexer_t lex = lexer(expr);
    return node_expr(&lex, 0);
}

void node_print(node_t *node, int indent) {
    if (!node) return;
    for (int i = 0; i < indent; i++) printf("  ");
    switch(node->type) {
        case ND_NUM: printf("NUM %.2f\n", node->number); break;
        case ND_ID:  printf("ID %s\n", node->id); break;
        case ND_BINOP:
            printf("BINOP %c\n", node->op);
            node_print(node->child, indent + 1);
            node_print(node->child->next, indent + 1);
            break;
    }
}

 

// --------------------- main ----------------------

#define BUFSIZE 256

int main(int argc, char *argv[]) { 
    
    char buffer[BUFSIZE];

    fprintf(stdout, ">> ");
    while(fgets(buffer, BUFSIZE, stdin) != NULL){
        if(strncmp(buffer, "exit", 4) == 0) break;
        node_t *root = parse(buffer);
        node_print(root, 0);
        fprintf(stdout, ">> ");
    }

    return 0;
}
