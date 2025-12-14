#ifndef MAIN_H
#define MAIN_H

typedef enum {
    TK_EOF = 0,
    TK_FLT,
    TK_INT,
    TK_STR,
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
    size_t len;
    union {
        double num_flt;
        int num_int;
    };
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
    ND_VAL,
    ND_ID,
    ND_CALL,
    ND_ASSIGN,
} node_type_t;

typedef enum {
    TYPE_NONE,
    TYPE_FLT,
    TYPE_INT,
    TYPE_STR,
    TYPE_FUN,
} val_type_t;

typedef struct {
    val_type_t type;
    size_t count;
    void *ptr;
} node_val_t;

typedef struct {
    char *name;
    size_t len;
} id_node_t;

typedef struct node_t node_t;
struct node_t {
    node_type_t type;
    node_val_t val;
    int token_pos;
    node_t *child;
    node_t *next;
    union {
        token_type_t op;
        id_node_t *id;
    };
};

typedef node_t* (*prefix_fun_t)(lexer_t *lex);
typedef node_t* (*infix_fun_t)(lexer_t *lex, node_t *node);
typedef void (*op_fun_t)(node_t *node);

typedef struct {
    char *name;
    op_fun_t fun;
} keyword_t;

typedef enum {
    KW_SIN,
    KW_COS,
    KEYWORDS_NUM,
} keyword_type_t;

typedef struct {
    prefix_fun_t prefix;
    infix_fun_t infix;
    int lbp;
} node_handler_t;

typedef struct {
    char *name;
    node_val_t value;
} var_tab_t;

node_t* node_alloc(lexer_t *lex, node_type_t type);
void node_free(node_t *node) ;

void new_flt(void **dst, double *src, size_t count);
void new_int(void **dst, int *src, size_t count);
void new_str(void **dst, char *src, size_t count);

node_t* node_group(lexer_t *lex);
node_t* node_val(lexer_t *lex);
node_t* node_id(lexer_t *lex);
node_t* node_binop(lexer_t *lex, node_t *left);
node_t* node_unop(lexer_t *lex);
node_t* node_call(lexer_t *lex, int kw);
node_t* node_assign(lexer_t *lex, node_t *left);
node_t* node_expr(lexer_t *lex, int rbp);
node_t* node_error(lexer_t *lex, char *msg);

void binop_arithmetic(node_t *node);
void unop_negative(node_t *node);

void sin_eval(node_t *node);
void cos_eval(node_t *node);

void set_var(node_t *node, var_tab_t *vars);
void get_var(node_t *node, var_tab_t *vars);
void node_eval(node_t *node);

void eval_error(node_t *node, char *msg);

node_t* parse(char *expr);

#endif