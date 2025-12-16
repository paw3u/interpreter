#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>

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
    TK_AND      = '&',
    TK_OR       = '|',
    TK_XOR      = '^',
    TK_NEG      = '~',
    TK_LPAREN   = '(',
    TK_RPAREN   = ')',
    TK_EQ       = '=',
    TK_QUEST    = '?',
    TK_COL      = ':',
} token_type_t;

typedef struct {
    token_type_t type;
    char *start;
    size_t len;
    union {
        double fnum;
        int64_t inum;
    };
} token_t;

typedef struct {
    char *source;
    char *pos;
    token_t token;
    token_t peek;
    uint8_t error;
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
    VT_NIL,
    VT_FLT,
    VT_INT,
    VT_CHR,
    VT_ARR,
} val_type_t;

#define type_nil (1 << VT_NIL)
#define type_flt (1 << VT_FLT)
#define type_int (1 << VT_INT)
#define type_chr (1 << VT_CHR)
#define type_arr (1 << VT_ARR)
#define type_str (type_chr | type_arr)

#define type_size(t) (is_num(t) ? 8 : is_char(t) ? 1 : 0)

#define is_nil(t) (t & type_nil)
#define is_flt(t) (t & type_flt)
#define is_int(t) (t & type_int)
#define is_chr(t) (t & type_chr)
#define is_arr(t) (t & type_arr)
#define is_str(t) ((t & type_arr) && (t & type_chr))
#define is_num(t) ((t & type_flt) || (t & type_int))

typedef struct {
    size_t count;
    void *ptr;
} arr_t;

typedef struct {
    uint32_t type;
    union {
        int64_t inum;
        double fnum;
        arr_t arr;
    };
} val_t;

typedef struct {
    char *name;
    size_t len;
} id_node_t;

typedef struct node_t node_t;
struct node_t {
    node_type_t type;
    val_t val;
    size_t token_pos;
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
    const char *name;
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
    uint8_t lbp;
} node_handler_t;

typedef struct {
    char *name;
    val_t val;
} var_tab_t;

node_t* node_alloc(lexer_t *lex, node_type_t type);
void node_free(node_t *node) ;
void alloc_str(void **dst, char *src, size_t count);

node_t* node_group(lexer_t *lex);
node_t* node_val(lexer_t *lex);
node_t* node_id(lexer_t *lex);
node_t* node_binop(lexer_t *lex, node_t *left);
node_t* node_unop(lexer_t *lex);
node_t* node_call(lexer_t *lex, uint8_t kw);
node_t* node_assign(lexer_t *lex, node_t *left);
node_t* node_expr(lexer_t *lex, uint8_t rbp);
node_t* node_error(lexer_t *lex, char *msg);
uint32_t hash(const char *str, size_t len, uint32_t seed);

void binop_arithmetic(node_t *node);
void unop_negative(node_t *node);
void binop_tern_col(node_t *node);
void binop_tern_quest(node_t *node);
void sin_eval(node_t *node);
void cos_eval(node_t *node);

void set_var(node_t *node, var_tab_t *vars);
void get_var(node_t *node, var_tab_t *vars);
void node_eval(node_t *node);

void eval_error(node_t *node, char *msg);

node_t* parse(char *expr);

#endif