#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "main.h"

// ================ Lexer ================ //

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

lexer_t lexer(char *str) {
    lexer_t lex;
    lex.source = str;
    lex.pos = lex.source;
    lex.error = 0;
    next_token(&lex);
    return lex;
}

// ================ Parser ================ //

node_handler_t node_handler[] = {
    [TK_NUM]    = {node_num,    NULL,       0},
    [TK_ID]     = {node_id,     NULL,       0},
    [TK_LPAREN] = {node_group,  NULL,       0},
    [TK_PLUS]   = {NULL,        node_binop, 10},
    [TK_MINUS]  = {node_unop,   node_binop, 10},
    [TK_MULT]   = {NULL,        node_binop, 20},
    [TK_DIV]    = {NULL,        node_binop, 20},
    [TK_B_AND]  = {NULL,        node_binop, 30},
    [TK_B_OR]   = {NULL,        node_binop, 30},
    [TK_B_XOR]  = {NULL,        node_binop, 30},
    [TK_B_NEG]  = {node_unop,   NULL,       30},
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
    next_token(lex);
    if(lex->token.type != TK_RPAREN){
        node_error(lex, ERR_RPAREN);
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
    node->id = (char*) malloc(lex->token.length + 1);
    memcpy(node->id, lex->token.start, lex->token.length);
    node->id[lex->token.length] = '\0';
    return node;
}

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

node_t* node_unop(lexer_t *lex) {
    token_type_t op = lex->token.type;
    node_t *expr = node_expr(lex, node_handler[op].lbp);
    if(!expr) return NULL;
    node_t *node = node_alloc(lex, ND_UNOP);
    node->op = op;
    node->child = expr;
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
    if(!node) return node_error(lex, ERR_EXPR);
    while(rbp < node_handler[lex->peek.type].lbp) {
        infix_fun_t infix = node_handler[lex->peek.type].infix;
        node = infix ? infix(lex, node) : node;
    }
    return node;
}

node_t* node_error(lexer_t *lex, err_t type){
    if(lex->error) return NULL;
    lex->error = type;
    switch (type) {
        case ERR_EXPR:
            fprintf(stderr, "Syntax error: %d\n", lex->token.start - lex->source);
            break;
        case ERR_RPAREN:
            fprintf(stderr, "')' missing at: %d\n", lex->token.start - lex->source);
            break;
        default:
            break;
    }
    return NULL;
}

node_t* parse(char *expr) {
    err_t error = 0;
    lexer_t lex = lexer(expr);
    if(lex.peek.type == TK_EOF) return NULL;
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
        case ND_UNOP:
            printf("UNOP %c\n", node->op);
            node_print(node->child, indent + 1);
    }
}

double node_eval(node_t *node){

    return 0;
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
        node_free(root);
        fprintf(stdout, ">> ");
    }

    return 0;
}
