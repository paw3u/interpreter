#ifndef MAIN_H
#define MAIN_H

// ================ Lexer ================ //

typedef enum {
    TK_EOF = 0,
    TK_NUM,
    TK_ID,
    TK_PLUS = '+',
    TK_MINUS = '-',
    TK_MULT = '*',
    TK_DIV = '/',
    TK_POW = '^',
    TK_LPAREN = '(',
    TK_RPAREN = ')',
} token_type_t;

typedef struct {
    token_type_t type;
    char *start;
    size_t length;
    double number;
} token_t;

typedef struct {
    char *source;
    char *pos;
    token_t token;
} lexer_t;


void next_token(lexer_t *lex);
lexer_t lexer(char *str);

// ================ Parser ================ //

typedef enum {
    ND_BINOP,
    ND_UNOP,
    ND_NUM,
    ND_ID,
    ND_CALL,
} node_type_t;

typedef struct node_t node_t;

struct node_t {
    node_type_t type;
    int token_pos;
    node_t *child;
    node_t *next;
    union{
        token_type_t op;
        double number;
        char *id;
    };
};

typedef node_t* (*prefix_fun_t)(lexer_t *lex);
typedef node_t* (*infix_fun_t)(lexer_t *lex, node_t *node);

typedef struct {
    prefix_fun_t prefix;
    infix_fun_t infix;
    int lbp;
} node_handler_t;

typedef enum {
    ERR_BAD_TK = 1,
    ERR_RPAREN,
} err_t;

typedef struct {
    int type;
    int pos;
} parse_err_t;

node_t* node_alloc(lexer_t *lex, node_type_t type);
void node_free(node_t *node) ;
node_t* node_group(lexer_t *lex);
node_t* node_num(lexer_t *lex);
node_t* node_id(lexer_t *lex);
node_t* node_binop(lexer_t *lex, node_t *left);
node_t* node_unop(lexer_t *lex);
node_t* node_call(lexer_t *lex);
node_t* node_expr(lexer_t *lex, int rbp);
node_t* node_error(err_t type, int pos);
node_t* parse(char *expr);

#endif