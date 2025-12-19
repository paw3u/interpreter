#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>

typedef enum {
    OP_HALT,
    OP_LOAD,
    OP_ADD,
    OP_SUB,
    OP_MULT,
    OP_DIV,
    OP_IDIV,
    OP_MOD,
    OP_NEG,
    OP_BAND,
    OP_BOR,
    OP_BXOR,
    OP_BNOT,
    OP_CALL,
    OP_PRINT,
} opcode_t;

typedef struct {
    uint32_t opcode;
    uint32_t arg;
} inst_t;

typedef struct {
    size_t count;
    size_t capacity;
    inst_t *inst;
} ibuffer_t;

void ib_write(ibuffer_t *ib, uint32_t opcode, uint32_t arg);
void ib_free(ibuffer_t *db);

typedef struct {
    size_t size;
    size_t capacity;
    uint8_t *data;
} dbuffer_t;

dbuffer_t db_create();
void db_write(dbuffer_t *db, const void *src, size_t len);
void db_free(dbuffer_t *db);

#define db_write_u32(db, val) do { uint32_t _v = (val); db_write(db, &_v, 4); } while(0)
#define db_write_u16(db, val) do { uint16_t _v = (val); db_write(db, &_v, 2); } while(0)
#define db_write_u8(db, val) do { uint8_t  _v = (val); db_write(db, &_v, 1); } while(0)

typedef enum {
    TK_EOF = 0,
    TK_PLUS     = '+',
    TK_MINUS    = '-',
    TK_STAR     = '*',
    TK_SLASH    = '/',
    TK_AND      = '&',
    TK_OR       = '|',
    TK_XOR      = '^',
    TK_TILDE    = '~',
    TK_LPAREN   = '(',
    TK_RPAREN   = ')',
    TK_EQ       = '=',
    TK_QUEST    = '?',
    TK_COL      = ':',
    TK_NUM      = 256,
    TK_STR,
    TK_ID,
    TK_IF,
    TK_THEN,
    TK_ELSE,
    TK_ELIF,
    TK_END,
} token_type_t;

typedef struct {
    token_type_t type;
    char *start;
    size_t len;
    double num;
} token_t;

typedef struct {
    char *source;
    char *pos;
    token_t token;
    token_t peek;
    uint8_t error;
    dbuffer_t *data;
} lexer_t;

void next_token(lexer_t *lex);
lexer_t lexer(char *str, dbuffer_t *data);

typedef enum {
    ND_BINOP,
    ND_UNOP,
    ND_VAL,
    ND_ID,
    ND_CALL,
    ND_IF,
    ND_ASSIGN,
} node_type_t;

typedef enum {
    VT_NIL,
    VT_NUM,
    VT_CHR,
    VT_ARR,
} val_type_t;

#define type_nil (1 << VT_NIL)
#define type_num (1 << VT_NUM)
#define type_chr (1 << VT_CHR)
#define type_arr (1 << VT_ARR)
#define type_str (type_chr | type_arr)

#define is_nil(t) (t & type_nil)
#define is_num(t) (t & type_num)
#define is_chr(t) (t & type_chr)
#define is_arr(t) (t & type_arr)
#define is_str(t) ((t & type_arr) && (t & type_chr))

#define type_size(t) (is_num(t) ? 8 : is_chr(t) ? 1 : 0)

/*
 *  W trakcie parsowania stałych w drzewie zapisywane są typ
 *  i adres w buforze danych, natomiast do bufora zapisywana
 *  jest wartość pod odpowiednim adresem.
 *  W OP_LOAD podawany jest adres z węzła i przy wykonywaniu
 *  kodu pobierana jest wartość z bufora.
 *  Do ustalenia jak to ma działać dla danych tablicowych...
 */

// Typ przechowywany na stosie - do wykonywania kodu
typedef struct {
    uint32_t type;
    uint32_t size;
    union {
        double num;
        void *addr;
    };
} val_t;

// Typ przechowywany w węźle
typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t addr;
} val_info_t;

typedef struct {
    char *name;
    size_t len;
} id_node_t;

typedef struct node_t node_t;
struct node_t {
    node_type_t type;
    val_info_t val;
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
typedef void (*comp_fun_t)(node_t *node, ibuffer_t *ib);

typedef struct {
    const char *name;
    token_type_t token;
    op_fun_t fun;
} keyword_t;

typedef enum {
    //KW_SIN,
    //KW_COS,
    KW_IF,
    KW_THEN,
    KW_ELSE,
    KW_ELIF,
    KW_END,
    KEYWORDS_NUM,
} keyword_type_t;

typedef struct {
    prefix_fun_t prefix;
    infix_fun_t infix;
    uint8_t lbp;
} node_handler_t;

typedef struct {
    char *name;
    uint32_t type;
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
node_t* node_if(lexer_t *lex);
node_t* node_assign(lexer_t *lex, node_t *left);
node_t* node_expr(lexer_t *lex, uint8_t rbp);
node_t* node_error(lexer_t *lex, char *msg);
uint32_t hash(const char *str, size_t len, uint32_t seed);
void node_print(node_t *node, dbuffer_t *db, int indent);

void comp_node_val(node_t *node, ibuffer_t *ib);
void comp_num_binop(node_t *node, ibuffer_t *ib);
void comp_num_unop(node_t *node, ibuffer_t *ib);
void comp_node(node_t *node, ibuffer_t *ib);
void comp_error(node_t *node, char *msg);

void set_var(node_t *node, var_tab_t *vars);
void get_var(node_t *node, var_tab_t *vars);

node_t* parse(char *expr, dbuffer_t *data);

#endif