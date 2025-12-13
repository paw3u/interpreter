#ifndef MAIN_H
#define MAIN_H

typedef enum {
    TK_EOF = 0,
    TK_NUM,
    TK_ID,
    TK_PLUS     = '+',
    TK_MINUS    = '-',
    TK_STAR     = '*',
    TK_SLASH    = '/',
    TK_B_AND    = '&',
    TK_B_OR     = '|',
    TK_B_XOR    = '^',
    TK_B_NEG    = '~',
    TK_LPAREN   = '(',
    TK_RPAREN   = ')',
    TK_EQ       = '=',
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
    token_t peek;
    int error;
} lexer_t;

void next_token(lexer_t *lex);
lexer_t lexer(char *str);

typedef enum {
    ND_BINOP,
    ND_UNOP,
    ND_NUM,
    ND_ID,
    ND_CALL,
    ND_ASSIGN,
} node_type_t;

typedef enum {
    ID_NUM,
    ID_ARR,
    ID_FUN,
} id_type_t;

typedef struct {
    char *name;
    size_t len;
    id_type_t type;
} id_node_t;

typedef struct node_t node_t;
struct node_t {
    node_type_t type;
    int token_pos;
    node_t *child;
    node_t *next;
    union{
        token_type_t op;
        double number;
        id_node_t id;
    };
};

typedef node_t* (*prefix_fun_t)(lexer_t *lex);
typedef node_t* (*infix_fun_t)(lexer_t *lex, node_t *node);
typedef double  (*binop_fun_t)(double lhs, double rhs);

typedef struct {
    prefix_fun_t prefix;
    infix_fun_t infix;
    int lbp;
} node_handler_t;

typedef enum {
    ERR_EXPR = 1,
    ERR_BINOP,
    ERR_RPAREN,
    ERR_ASSIGN,
} err_t;

typedef struct {
    char *name;
    double value;
} var_tab_t;

node_t* node_alloc(lexer_t *lex, node_type_t type);
void node_free(node_t *node) ;

node_t* node_group(lexer_t *lex);
node_t* node_num(lexer_t *lex);
node_t* node_id(lexer_t *lex);
node_t* node_binop(lexer_t *lex, node_t *left);
node_t* node_unop(lexer_t *lex);
node_t* node_call(lexer_t *lex);
node_t* node_assign(lexer_t *lex, node_t *left);
node_t* node_expr(lexer_t *lex, int rbp);
node_t* node_error(lexer_t *lex, err_t type);

static double eval_mult(double lhs, double rhs);
static double eval_div(double lhs, double rhs);
static double eval_sub(double lhs, double rhs);
static double eval_add(double lhs, double rhs);

void set_var(node_t *node, var_tab_t *vars);
double get_var(node_t *node, var_tab_t *vars, int *val_return);
double node_eval(node_t *node, int *val_return);

node_t* parse(char *expr);

#endif