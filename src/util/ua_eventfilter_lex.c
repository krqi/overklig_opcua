

#include <opcua/util.h>
#include "ua_eventfilter_parser.h"



#undef YYPEEK
#undef YYSKIP
#undef YYBACKUP
#undef YYRESTORE
#undef YYSHIFT
#undef YYSTAGP
#undef YYSTAGN
#undef YYSHIFTSTAG
#undef YYRESTORETAG
#define YYPEEK() (pos < end) ? *pos: 0
#define YYSKIP() ++pos;
#define YYBACKUP() m = pos;
#define YYRESTORE() pos = m;
#define YYSHIFT(shift) pos += shift
#define YYSTAGP(t) t = pos
#define YYSTAGN(t) t = NULL
#define YYSHIFTSTAG(t, shift) t += shift
#define YYRESTORETAG(t) pos = t;



UA_StatusCode
UA_EventFilter_skip(const UA_ByteString content, size_t *offset,
                    EFParseContext *ctx) {
    const char *pos = (const char*)&content.data[*offset];
    const char *end = (const char*)&content.data[content.length];

  begin:
    *offset = (uintptr_t)(pos - (const char*)content.data);
    size_t initial = *offset;

    
{
	char yych;
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy3;
		case '/': goto yy5;
		default: goto yy1;
	}
yy1:
	YYSKIP();
yy2:
	{ return UA_STATUSCODE_GOOD; }
yy3:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy3;
		default: goto yy4;
	}
yy4:
	{ goto begin; }
yy5:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '*': goto yy6;
		case '/': goto yy7;
		default: goto yy2;
	}
yy6:
	YYSKIP();
	{ for(; pos < end - 1; pos++)
           { if(pos[0] == '*' && pos[1] == '/') { pos += 2; goto begin; } }
           unsigned c = 0, l = 0;
           pos2lines(content, initial, &l, &c);
           UA_LOG_ERROR(ctx->logger, UA_LOGCATEGORY_USERLAND,
                        "The comment starting at line %u, column %u "
                        "never terminates", l, c);
           return UA_STATUSCODE_BADINTERNALERROR;
         }
yy7:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n':
		case '\r': goto yy8;
		default: goto yy7;
	}
yy8:
	{ goto begin; }
}

}

int
UA_EventFilter_lex(const UA_ByteString content, size_t *offset,
                   EFParseContext *ctx, Operand **token) {
    const char *pos = (const char*)&content.data[*offset];
    const char *end = (const char*)&content.data[content.length];
    const char *m, *b; 
    const char *yyt1;
    const UA_DataType *lt; 
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    UA_ByteString match;
    UA_FilterOperator f;

    int tokenId = 0;
    while(true) {
        
        b = pos;

        
{
	char yych;
	unsigned int yyaccept = 0;
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '.': goto yy10;
		case '!': goto yy13;
		case '"': goto yy15;
		case '#':
		case '/': goto yy16;
		case '$': goto yy19;
		case '&': goto yy20;
		case '\'': goto yy22;
		case '(': goto yy23;
		case ')': goto yy24;
		case ',': goto yy25;
		case '-': goto yy26;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy27;
		case ':': goto yy29;
		case '<': goto yy30;
		case '=': goto yy32;
		case '>': goto yy33;
		case 'A':
		case 'a': goto yy35;
		case 'B': goto yy36;
		case 'C':
		case 'c': goto yy37;
		case 'D':
		case 'd': goto yy38;
		case 'E':
		case 'e': goto yy39;
		case 'F':
		case 'f': goto yy40;
		case 'G': goto yy41;
		case 'I': goto yy42;
		case 'L':
		case 'l': goto yy43;
		case 'N': goto yy44;
		case 'O':
		case 'o': goto yy45;
		case 'Q':
		case 'q': goto yy46;
		case 'S': goto yy47;
		case 'T':
		case 't': goto yy48;
		case 'U':
		case 'u': goto yy49;
		case 'W':
		case 'w': goto yy50;
		case '[': goto yy51;
		case ']': goto yy52;
		case 'b': goto yy53;
		case 'g': goto yy54;
		case 'i': goto yy55;
		case 'n': goto yy56;
		case 's': goto yy57;
		case '{': goto yy58;
		case '|': goto yy60;
		default: goto yy12;
	}
yy10:
	YYSKIP();
yy11:
	{ goto finish; }
yy12:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		default: goto yy63;
	}
yy13:
	YYSKIP();
yy14:
	{ f = UA_FILTEROPERATOR_NOT;     tokenId = EF_TOK_NOT;     goto make_op; }
yy15:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	if (yych <= 0x00) goto yy11;
	goto yy67;
yy16:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
yy17:
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy18;
		case '&': goto yy75;
		case '[': goto yy76;
		default: goto yy16;
	}
yy18:
	{ goto sao; }
yy19:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case '_':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy77;
		default: goto yy63;
	}
yy20:
	yyaccept = 2;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy21;
		case '&': goto yy79;
		default: goto yy62;
	}
yy21:
	{ f = UA_FILTEROPERATOR_BITWISEAND;                        goto binary_op; }
yy22:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	if (yych <= 0x00) goto yy11;
	goto yy82;
yy23:
	YYSKIP();
	{ tokenId = EF_TOK_LPAREN;     goto finish; }
yy24:
	YYSKIP();
	{ tokenId = EF_TOK_RPAREN;     goto finish; }
yy25:
	YYSKIP();
	{ tokenId = EF_TOK_COMMA;      goto finish; }
yy26:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '[':
		case ']': goto yy11;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy27;
		case '>': goto yy90;
		default: goto yy63;
	}
yy27:
	yyaccept = 3;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy28;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy27;
		default: goto yy62;
	}
yy28:
	{ lt = &UA_TYPES[UA_TYPES_INT32]; goto lit; }
yy29:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '=': goto yy92;
		default: goto yy11;
	}
yy30:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '=': goto yy93;
		default: goto yy31;
	}
yy31:
	{ f = UA_FILTEROPERATOR_LESSTHAN;                          goto binary_op; }
yy32:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case '=': goto yy95;
		default: goto yy63;
	}
yy33:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '=': goto yy97;
		default: goto yy34;
	}
yy34:
	{ f = UA_FILTEROPERATOR_GREATERTHAN;                       goto binary_op; }
yy35:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'N':
		case 'n': goto yy99;
		default: goto yy63;
	}
yy36:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'E':
		case 'e': goto yy100;
		case 'I':
		case 'i': goto yy101;
		case 'O':
		case 'o': goto yy102;
		case 'Y':
		case 'y': goto yy103;
		default: goto yy63;
	}
yy37:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'A':
		case 'a': goto yy104;
		default: goto yy63;
	}
yy38:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'A':
		case 'a': goto yy105;
		case 'O':
		case 'o': goto yy106;
		default: goto yy63;
	}
yy39:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'Q':
		case 'q': goto yy107;
		case 'X':
		case 'x': goto yy108;
		default: goto yy63;
	}
yy40:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'A':
		case 'a': goto yy109;
		case 'L':
		case 'l': goto yy110;
		case 'O':
		case 'o': goto yy111;
		default: goto yy63;
	}
yy41:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'R':
		case 'r': goto yy112;
		case 'U':
		case 'u': goto yy113;
		default: goto yy63;
	}
yy42:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'N':
		case 'n': goto yy114;
		case 'S':
		case 's': goto yy115;
		default: goto yy63;
	}
yy43:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'E':
		case 'e': goto yy116;
		case 'I':
		case 'i': goto yy117;
		case 'O':
		case 'o': goto yy118;
		default: goto yy63;
	}
yy44:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'O':
		case 'o': goto yy119;
		default: goto yy63;
	}
yy45:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'F':
		case 'f': goto yy120;
		case 'R':
		case 'r': goto yy121;
		default: goto yy63;
	}
yy46:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'U':
		case 'u': goto yy123;
		default: goto yy63;
	}
yy47:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'B':
		case 'b': goto yy124;
		case 'E':
		case 'e': goto yy125;
		case 'T':
		case 't': goto yy126;
		default: goto yy63;
	}
yy48:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'R':
		case 'r': goto yy127;
		default: goto yy63;
	}
yy49:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'I':
		case 'i': goto yy128;
		default: goto yy63;
	}
yy50:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'H':
		case 'h': goto yy129;
		default: goto yy63;
	}
yy51:
	YYSKIP();
	{ tokenId = EF_TOK_LBRACKET;   goto finish; }
yy52:
	YYSKIP();
	{ tokenId = EF_TOK_RBRACKET;   goto finish; }
yy53:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case '=': goto yy130;
		case 'E':
		case 'e': goto yy100;
		case 'I':
		case 'i': goto yy101;
		case 'O':
		case 'o': goto yy102;
		case 'Y':
		case 'y': goto yy103;
		default: goto yy63;
	}
yy54:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case '=': goto yy130;
		case 'R':
		case 'r': goto yy112;
		case 'U':
		case 'u': goto yy113;
		default: goto yy63;
	}
yy55:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case '=': goto yy130;
		case 'N':
		case 'n': goto yy114;
		case 'S':
		case 's': goto yy115;
		default: goto yy63;
	}
yy56:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case 'O':
		case 'o': goto yy119;
		case 's': goto yy131;
		default: goto yy63;
	}
yy57:
	yyaccept = 0;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy11;
		case '=': goto yy130;
		case 'B':
		case 'b': goto yy124;
		case 'E':
		case 'e': goto yy125;
		case 'T':
		case 't': goto yy126;
		default: goto yy63;
	}
yy58:
	yyaccept = 4;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy59;
		default: goto yy63;
	}
yy59:
	{ goto json; }
yy60:
	yyaccept = 5;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy61;
		case '|': goto yy121;
		default: goto yy63;
	}
yy61:
	{ f = UA_FILTEROPERATOR_BITWISEOR;                         goto binary_op; }
yy62:
	YYSKIP();
	yych = YYPEEK();
yy63:
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		default: goto yy62;
	}
yy64:
	YYRESTORE();
	switch (yyaccept) {
		case 0: goto yy11;
		case 1: goto yy18;
		case 2: goto yy21;
		case 3: goto yy28;
		case 4: goto yy59;
		case 5: goto yy61;
		case 6: goto yy71;
		case 7: goto yy78;
		case 8: goto yy80;
		case 9: goto yy88;
		case 10: goto yy96;
		case 11: goto yy122;
		case 12: goto yy14;
		case 13: goto yy179;
		case 14: goto yy91;
		case 15: goto yy198;
		case 16: goto yy210;
		case 17: goto yy220;
		case 18: goto yy263;
		case 19: goto yy273;
		case 20: goto yy276;
		case 21: goto yy284;
		case 22: goto yy289;
		case 23: goto yy300;
		case 24: goto yy306;
		case 25: goto yy315;
		case 26: goto yy320;
		case 27: goto yy325;
		case 28: goto yy330;
		case 29:
			YYSTAGP(yyt1);
			goto yy336;
		case 30: goto yy341;
		case 31: goto yy345;
		case 32: goto yy364;
		case 33: goto yy31;
		case 34: goto yy336;
		case 35: goto yy383;
		case 36: goto yy386;
		case 37: goto yy389;
		case 38: goto yy407;
		case 39: goto yy414;
		case 40: goto yy427;
		case 41: goto yy34;
		case 42: goto yy465;
		case 43: goto yy468;
		case 44: goto yy476;
		case 45:
			YYSTAGP(yyt1);
			goto yy491;
		case 46:
			YYSTAGP(yyt1);
			goto yy494;
		case 47: goto yy94;
		case 48: goto yy501;
		case 49: goto yy491;
		case 50: goto yy494;
		default: goto yy98;
	}
yy65:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy62;
	}
yy66:
	YYSKIP();
	yych = YYPEEK();
yy67:
	switch (yych) {
		case 0x00: goto yy64;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy68;
		case '"': goto yy70;
		case '#':
		case '/': goto yy72;
		case '&': goto yy73;
		case '\\': goto yy74;
		default: goto yy66;
	}
yy68:
	YYSKIP();
	yych = YYPEEK();
yy69:
	switch (yych) {
		case 0x00: goto yy64;
		case '"': goto yy132;
		case '\\': goto yy133;
		default: goto yy68;
	}
yy70:
	yyaccept = 6;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy71;
		default: goto yy63;
	}
yy71:
	{ lt = &UA_TYPES[UA_TYPES_STRING]; goto lit; }
yy72:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy18;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy68;
		case '"': goto yy16;
		case '&': goto yy134;
		case '[': goto yy135;
		case '\\': goto yy136;
		default: goto yy72;
	}
yy73:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\n': goto yy68;
		case '"': goto yy70;
		case '\\': goto yy74;
		default: goto yy66;
	}
yy74:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy68;
		case '"': goto yy137;
		case '#':
		case '/': goto yy72;
		case '&': goto yy73;
		case '\\': goto yy74;
		default: goto yy66;
	}
yy75:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy16;
	}
yy76:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case ']': goto yy64;
		default: goto yy139;
	}
yy77:
	yyaccept = 7;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy78;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case '_':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy77;
		default: goto yy62;
	}
yy78:
	{ goto namedoperand; }
yy79:
	yyaccept = 8;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy80;
		default: goto yy63;
	}
yy80:
	{ f = UA_FILTEROPERATOR_AND;     tokenId = EF_TOK_AND;     goto make_op; }
yy81:
	YYSKIP();
	yych = YYPEEK();
yy82:
	switch (yych) {
		case 0x00: goto yy64;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy83;
		case '#':
		case '/': goto yy85;
		case '&': goto yy86;
		case '\'': goto yy87;
		case '\\': goto yy89;
		default: goto yy81;
	}
yy83:
	YYSKIP();
	yych = YYPEEK();
yy84:
	switch (yych) {
		case 0x00: goto yy64;
		case '\'': goto yy140;
		case '\\': goto yy141;
		default: goto yy83;
	}
yy85:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy18;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy83;
		case '&': goto yy142;
		case '\'': goto yy16;
		case '[': goto yy143;
		case '\\': goto yy144;
		default: goto yy85;
	}
yy86:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\n': goto yy83;
		case '\'': goto yy87;
		case '\\': goto yy89;
		default: goto yy81;
	}
yy87:
	yyaccept = 9;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy88;
		default: goto yy63;
	}
yy88:
	{ lt = &UA_TYPES[UA_TYPES_STRING]; goto lit; }
yy89:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy83;
		case '#':
		case '/': goto yy85;
		case '&': goto yy86;
		case '\'': goto yy145;
		case '\\': goto yy89;
		default: goto yy81;
	}
yy90:
	YYSKIP();
yy91:
	{ f = UA_FILTEROPERATOR_CAST;                              goto binary_op; }
yy92:
	YYSKIP();
	{ tokenId = EF_TOK_COLONEQUAL; goto finish; }
yy93:
	YYSKIP();
yy94:
	{ f = UA_FILTEROPERATOR_LESSTHANOREQUAL;                   goto binary_op; }
yy95:
	yyaccept = 10;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy96;
		default: goto yy63;
	}
yy96:
	{ f = UA_FILTEROPERATOR_EQUALS;                            goto binary_op; }
yy97:
	YYSKIP();
yy98:
	{ f = UA_FILTEROPERATOR_GREATERTHANOREQUAL;                goto binary_op; }
yy99:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy79;
		default: goto yy63;
	}
yy100:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy146;
		default: goto yy63;
	}
yy101:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy147;
		default: goto yy63;
	}
yy102:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'O':
		case 'o': goto yy148;
		default: goto yy63;
	}
yy103:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy149;
		default: goto yy63;
	}
yy104:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'S':
		case 's': goto yy150;
		default: goto yy63;
	}
yy105:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy151;
		default: goto yy63;
	}
yy106:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'U':
		case 'u': goto yy152;
		default: goto yy63;
	}
yy107:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'U':
		case 'u': goto yy153;
		default: goto yy63;
	}
yy108:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'P':
		case 'p': goto yy154;
		default: goto yy63;
	}
yy109:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy155;
		default: goto yy63;
	}
yy110:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'O':
		case 'o': goto yy156;
		default: goto yy63;
	}
yy111:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'R':
		case 'r': goto yy157;
		default: goto yy63;
	}
yy112:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy158;
		default: goto yy63;
	}
yy113:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'I':
		case 'i': goto yy159;
		default: goto yy63;
	}
yy114:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy160;
		case 'T':
		case 't': goto yy161;
		default: goto yy63;
	}
yy115:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy162;
		default: goto yy63;
	}
yy116:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'S':
		case 's': goto yy163;
		default: goto yy63;
	}
yy117:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'K':
		case 'k': goto yy164;
		default: goto yy63;
	}
yy118:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'C':
		case 'c': goto yy165;
		default: goto yy63;
	}
yy119:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy166;
		case 'T':
		case 't': goto yy167;
		default: goto yy63;
	}
yy120:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy168;
		default: goto yy63;
	}
yy121:
	yyaccept = 11;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy122;
		default: goto yy63;
	}
yy122:
	{ f = UA_FILTEROPERATOR_OR;      tokenId = EF_TOK_OR;      goto make_op; }
yy123:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy169;
		default: goto yy63;
	}
yy124:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'Y':
		case 'y': goto yy170;
		default: goto yy63;
	}
yy125:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy171;
		default: goto yy63;
	}
yy126:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy172;
		case 'R':
		case 'r': goto yy173;
		default: goto yy63;
	}
yy127:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'U':
		case 'u': goto yy174;
		default: goto yy63;
	}
yy128:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy175;
		default: goto yy63;
	}
yy129:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy176;
		default: goto yy63;
	}
yy130:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		default: goto yy178;
	}
yy131:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '=': goto yy181;
		default: goto yy63;
	}
yy132:
	YYSKIP();
	goto yy71;
yy133:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '"': goto yy182;
		case '\\': goto yy133;
		default: goto yy68;
	}
yy134:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\n': goto yy68;
		case '"': goto yy16;
		case '\\': goto yy136;
		default: goto yy72;
	}
yy135:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case ',':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case ':': goto yy183;
		default: goto yy69;
	}
yy136:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy18;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy68;
		case '&': goto yy134;
		case '[': goto yy135;
		case '\\': goto yy136;
		default: goto yy72;
	}
yy137:
	yyaccept = 6;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy71;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy68;
		case '"': goto yy70;
		case '#':
		case '/': goto yy72;
		case '&': goto yy73;
		case '\\': goto yy74;
		default: goto yy66;
	}
yy138:
	YYSKIP();
	yych = YYPEEK();
yy139:
	switch (yych) {
		case ',':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case ':': goto yy138;
		case ']': goto yy184;
		default: goto yy64;
	}
yy140:
	YYSKIP();
	goto yy88;
yy141:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\'': goto yy185;
		case '\\': goto yy141;
		default: goto yy83;
	}
yy142:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\n': goto yy83;
		case '\'': goto yy16;
		case '\\': goto yy144;
		default: goto yy85;
	}
yy143:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case ',':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case ':': goto yy186;
		default: goto yy84;
	}
yy144:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy18;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy83;
		case '&': goto yy142;
		case '[': goto yy143;
		case '\\': goto yy144;
		default: goto yy85;
	}
yy145:
	yyaccept = 9;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy88;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy83;
		case '#':
		case '/': goto yy85;
		case '&': goto yy86;
		case '\'': goto yy87;
		case '\\': goto yy89;
		default: goto yy81;
	}
yy146:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'W':
		case 'w': goto yy187;
		default: goto yy63;
	}
yy147:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'W':
		case 'w': goto yy188;
		default: goto yy63;
	}
yy148:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy189;
		default: goto yy63;
	}
yy149:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy190;
		default: goto yy63;
	}
yy150:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy191;
		default: goto yy63;
	}
yy151:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy192;
		default: goto yy63;
	}
yy152:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'B':
		case 'b': goto yy193;
		default: goto yy63;
	}
yy153:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy194;
		default: goto yy63;
	}
yy154:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy195;
		default: goto yy63;
	}
yy155:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'S':
		case 's': goto yy174;
		default: goto yy63;
	}
yy156:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy196;
		default: goto yy63;
	}
yy157:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
			YYSTAGP(yyt1);
			goto yy197;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ':
			YYSTAGP(yyt1);
			goto yy199;
		case '?':
			YYSTAGP(yyt1);
			goto yy200;
		default: goto yy63;
	}
yy158:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy201;
		default: goto yy63;
	}
yy159:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy202;
		default: goto yy63;
	}
yy160:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'I':
		case 'i': goto yy203;
		default: goto yy63;
	}
yy161:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '1': goto yy204;
		case '3': goto yy205;
		case '6': goto yy206;
		default: goto yy63;
	}
yy162:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'U':
		case 'u': goto yy207;
		default: goto yy63;
	}
yy163:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'S':
		case 's': goto yy208;
		default: goto yy63;
	}
yy164:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy209;
		default: goto yy63;
	}
yy165:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy211;
		default: goto yy63;
	}
yy166:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy212;
		default: goto yy63;
	}
yy167:
	yyaccept = 12;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy14;
		default: goto yy63;
	}
yy168:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'Y':
		case 'y': goto yy213;
		default: goto yy63;
	}
yy169:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy214;
		default: goto yy63;
	}
yy170:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy215;
		default: goto yy63;
	}
yy171:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy216;
		default: goto yy63;
	}
yy172:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy217;
		default: goto yy63;
	}
yy173:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'I':
		case 'i': goto yy218;
		default: goto yy63;
	}
yy174:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy219;
		default: goto yy63;
	}
yy175:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy221;
		default: goto yy63;
	}
yy176:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'R':
		case 'r': goto yy222;
		default: goto yy63;
	}
yy177:
	yyaccept = 13;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
yy178:
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy179;
		case '#':
		case '/': goto yy16;
		case '&': goto yy180;
		default: goto yy177;
	}
yy179:
	{ lt = &UA_TYPES[UA_TYPES_NODEID]; goto lit; }
yy180:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy177;
	}
yy181:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy223;
		default: goto yy63;
	}
yy182:
	yyaccept = 6;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy71;
		case '"': goto yy132;
		case '\\': goto yy133;
		default: goto yy68;
	}
yy183:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '"': goto yy132;
		case ',':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case ':': goto yy183;
		case '\\': goto yy133;
		case ']': goto yy224;
		default: goto yy68;
	}
yy184:
	YYSKIP();
	goto yy18;
yy185:
	yyaccept = 9;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy88;
		case '\'': goto yy140;
		case '\\': goto yy141;
		default: goto yy83;
	}
yy186:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\'': goto yy140;
		case ',':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case ':': goto yy186;
		case '\\': goto yy141;
		case ']': goto yy225;
		default: goto yy83;
	}
yy187:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy226;
		default: goto yy63;
	}
yy188:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'I':
		case 'i': goto yy227;
		default: goto yy63;
	}
yy189:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy228;
		default: goto yy63;
	}
yy190:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy229;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy230;
		case 'S':
		case 's': goto yy231;
		default: goto yy63;
	}
yy191:
	yyaccept = 14;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy91;
		default: goto yy63;
	}
yy192:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy232;
		default: goto yy63;
	}
yy193:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy233;
		default: goto yy63;
	}
yy194:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy234;
		default: goto yy63;
	}
yy195:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy235;
		default: goto yy63;
	}
yy196:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy236;
		default: goto yy63;
	}
yy197:
	yyaccept = 15;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy198;
		case 0x08: goto yy197;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy199;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		default: goto yy62;
	}
yy198:
	YYRESTORETAG(yyt1);
	{ tokenId = EF_TOK_FOR;    goto finish; }
yy199:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy199;
		default: goto yy198;
	}
yy200:
	yyaccept = 15;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy198;
		default: goto yy63;
	}
yy201:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy237;
		default: goto yy63;
	}
yy202:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy238;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy239;
		default: goto yy63;
	}
yy203:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'S':
		case 's': goto yy240;
		default: goto yy63;
	}
yy204:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '6': goto yy241;
		default: goto yy63;
	}
yy205:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '2': goto yy242;
		default: goto yy63;
	}
yy206:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '4': goto yy243;
		default: goto yy63;
	}
yy207:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy244;
		default: goto yy63;
	}
yy208:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy245;
		default: goto yy63;
	}
yy209:
	yyaccept = 16;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy210;
		default: goto yy63;
	}
yy210:
	{ f = UA_FILTEROPERATOR_LIKE;                              goto binary_op; }
yy211:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy246;
		default: goto yy63;
	}
yy212:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'I':
		case 'i': goto yy247;
		default: goto yy63;
	}
yy213:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'P':
		case 'p': goto yy248;
		default: goto yy63;
	}
yy214:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'I':
		case 'i': goto yy249;
		default: goto yy63;
	}
yy215:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy250;
		default: goto yy63;
	}
yy216:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'C':
		case 'c': goto yy251;
		default: goto yy63;
	}
yy217:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'U':
		case 'u': goto yy252;
		default: goto yy63;
	}
yy218:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy253;
		default: goto yy63;
	}
yy219:
	yyaccept = 17;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy220;
		default: goto yy63;
	}
yy220:
	{ lt = &UA_TYPES[UA_TYPES_BOOLEAN]; goto lit; }
yy221:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '1': goto yy254;
		case '3': goto yy255;
		case '6': goto yy256;
		default: goto yy63;
	}
yy222:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy257;
		default: goto yy63;
	}
yy223:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy223;
		case ';': goto yy258;
		default: goto yy62;
	}
yy224:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	if (yych <= 0x00) goto yy18;
	goto yy69;
yy225:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	if (yych <= 0x00) goto yy18;
	goto yy84;
yy226:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy259;
		default: goto yy63;
	}
yy227:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'S':
		case 's': goto yy260;
		default: goto yy63;
	}
yy228:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy261;
		default: goto yy63;
	}
yy229:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy229;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy230;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy262;
		default: goto yy62;
	}
yy230:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy230;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy264;
		default: goto yy64;
	}
yy231:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy265;
		default: goto yy63;
	}
yy232:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'I':
		case 'i': goto yy266;
		default: goto yy63;
	}
yy233:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy267;
		default: goto yy63;
	}
yy234:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'S':
		case 's': goto yy95;
		default: goto yy63;
	}
yy235:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy268;
		default: goto yy63;
	}
yy236:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy269;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy270;
		default: goto yy63;
	}
yy237:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy271;
		default: goto yy63;
	}
yy238:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy238;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy239;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '-':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy272;
		default: goto yy62;
	}
yy239:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy239;
		case '-':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy274;
		default: goto yy64;
	}
yy240:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy275;
		default: goto yy63;
	}
yy241:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy277;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy278;
		default: goto yy63;
	}
yy242:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy279;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy280;
		default: goto yy63;
	}
yy243:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy281;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy282;
		default: goto yy63;
	}
yy244:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy283;
		default: goto yy63;
	}
yy245:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'H':
		case 'h': goto yy285;
		default: goto yy63;
	}
yy246:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'I':
		case 'i': goto yy286;
		default: goto yy63;
	}
yy247:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy287;
		default: goto yy63;
	}
yy248:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy288;
		default: goto yy63;
	}
yy249:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'F':
		case 'f': goto yy290;
		default: goto yy63;
	}
yy250:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy291;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy292;
		default: goto yy63;
	}
yy251:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy293;
		default: goto yy63;
	}
yy252:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'S':
		case 's': goto yy294;
		default: goto yy63;
	}
yy253:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'G':
		case 'g': goto yy295;
		default: goto yy63;
	}
yy254:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '6': goto yy296;
		default: goto yy63;
	}
yy255:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '2': goto yy297;
		default: goto yy63;
	}
yy256:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '4': goto yy298;
		default: goto yy63;
	}
yy257:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
			YYSTAGP(yyt1);
			goto yy299;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ':
			YYSTAGP(yyt1);
			goto yy301;
		case '(':
			YYSTAGP(yyt1);
			goto yy302;
		case '?':
			YYSTAGP(yyt1);
			goto yy303;
		default: goto yy63;
	}
yy258:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'b':
		case 'g':
		case 'i':
		case 's': goto yy304;
		default: goto yy63;
	}
yy259:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy305;
		default: goto yy63;
	}
yy260:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy307;
		default: goto yy63;
	}
yy261:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy308;
		default: goto yy63;
	}
yy262:
	yyaccept = 18;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy263;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy262;
		default: goto yy62;
	}
yy263:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_BYTE];           goto lit; }
yy264:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy264;
		default: goto yy263;
	}
yy265:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'R':
		case 'r': goto yy309;
		default: goto yy63;
	}
yy266:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'M':
		case 'm': goto yy310;
		default: goto yy63;
	}
yy267:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy311;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy312;
		default: goto yy63;
	}
yy268:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy313;
		default: goto yy63;
	}
yy269:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy269;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy270;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '+':
		case '-':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'E':
		case 'e':
			YYSTAGP(yyt1);
			goto yy314;
		case '.':
			YYSTAGP(yyt1);
			goto yy316;
		default: goto yy62;
	}
yy270:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy270;
		case '+':
		case '-':
		case '.':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'E':
		case 'e':
			YYSTAGP(yyt1);
			goto yy316;
		default: goto yy64;
	}
yy271:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'R':
		case 'r': goto yy317;
		default: goto yy63;
	}
yy272:
	yyaccept = 19;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy273;
		default: goto yy63;
	}
yy273:
	YYSTAGP(b);
	YYSHIFTSTAG(b, -1);
	{ lt = &UA_TYPES[UA_TYPES_GUID];           goto lit; }
yy274:
	YYSKIP();
	goto yy273;
yy275:
	yyaccept = 20;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy276;
		default: goto yy63;
	}
yy276:
	{ f = UA_FILTEROPERATOR_INLIST;  tokenId = EF_TOK_INLIST;  goto make_op; }
yy277:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy277;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy278;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '-':
			YYSTAGP(yyt1);
			goto yy318;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy319;
		default: goto yy62;
	}
yy278:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy278;
		case '-':
			YYSTAGP(yyt1);
			goto yy321;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy322;
		default: goto yy64;
	}
yy279:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy279;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy280;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '-':
			YYSTAGP(yyt1);
			goto yy323;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy324;
		default: goto yy62;
	}
yy280:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy280;
		case '-':
			YYSTAGP(yyt1);
			goto yy326;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy327;
		default: goto yy64;
	}
yy281:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy281;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy282;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '-':
			YYSTAGP(yyt1);
			goto yy328;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy329;
		default: goto yy62;
	}
yy282:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy282;
		case '-':
			YYSTAGP(yyt1);
			goto yy331;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy332;
		default: goto yy64;
	}
yy283:
	yyaccept = 21;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy284;
		default: goto yy63;
	}
yy284:
	{ f = UA_FILTEROPERATOR_ISNULL;                            goto unary_op; }
yy285:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy333;
		default: goto yy63;
	}
yy286:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'Z':
		case 'z': goto yy334;
		default: goto yy63;
	}
yy287:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy335;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy337;
		default: goto yy63;
	}
yy288:
	yyaccept = 22;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy289;
		default: goto yy63;
	}
yy289:
	{ f = UA_FILTEROPERATOR_OFTYPE;                            goto unary_op; }
yy290:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'I':
		case 'i': goto yy338;
		default: goto yy63;
	}
yy291:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy291;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy292;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '-':
			YYSTAGP(yyt1);
			goto yy339;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy340;
		default: goto yy62;
	}
yy292:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy292;
		case '-':
			YYSTAGP(yyt1);
			goto yy342;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy343;
		default: goto yy64;
	}
yy293:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
			YYSTAGP(yyt1);
			goto yy344;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ':
			YYSTAGP(yyt1);
			goto yy346;
		case '?':
			YYSTAGP(yyt1);
			goto yy347;
		default: goto yy63;
	}
yy294:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'C':
		case 'c': goto yy348;
		default: goto yy63;
	}
yy295:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy349;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy350;
		default: goto yy63;
	}
yy296:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy351;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy352;
		default: goto yy63;
	}
yy297:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy353;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy354;
		default: goto yy63;
	}
yy298:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy355;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy356;
		default: goto yy63;
	}
yy299:
	yyaccept = 23;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy300;
		case 0x08: goto yy299;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy301;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		default: goto yy62;
	}
yy300:
	YYRESTORETAG(yyt1);
	{ tokenId = EF_TOK_WHERE;  goto finish; }
yy301:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy301;
		default: goto yy300;
	}
yy302:
	YYSKIP();
	goto yy300;
yy303:
	yyaccept = 23;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy300;
		default: goto yy63;
	}
yy304:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '=': goto yy130;
		default: goto yy63;
	}
yy305:
	yyaccept = 24;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy306;
		default: goto yy63;
	}
yy306:
	{ f = UA_FILTEROPERATOR_BETWEEN; tokenId = EF_TOK_BETWEEN; goto make_op; }
yy307:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy357;
		case 'O':
		case 'o': goto yy358;
		default: goto yy63;
	}
yy308:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy359;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy360;
		default: goto yy63;
	}
yy309:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'I':
		case 'i': goto yy361;
		default: goto yy63;
	}
yy310:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy362;
		default: goto yy63;
	}
yy311:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy311;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy312;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '+':
		case '-':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'E':
		case 'e':
			YYSTAGP(yyt1);
			goto yy363;
		case '.':
			YYSTAGP(yyt1);
			goto yy365;
		default: goto yy62;
	}
yy312:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy312;
		case '+':
		case '-':
		case '.':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'E':
		case 'e':
			YYSTAGP(yyt1);
			goto yy365;
		default: goto yy64;
	}
yy313:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy366;
		default: goto yy63;
	}
yy314:
	yyaccept = 25;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy315;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '+':
		case '-':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'E':
		case 'e': goto yy314;
		case '.': goto yy316;
		default: goto yy62;
	}
yy315:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_FLOAT];          goto lit; }
yy316:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '+':
		case '-':
		case '.':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'E':
		case 'e': goto yy316;
		default: goto yy315;
	}
yy317:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy367;
		default: goto yy63;
	}
yy318:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy319;
		default: goto yy63;
	}
yy319:
	yyaccept = 26;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy320;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy319;
		default: goto yy62;
	}
yy320:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_INT16];          goto lit; }
yy321:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy322;
		default: goto yy64;
	}
yy322:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy322;
		default: goto yy320;
	}
yy323:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy324;
		default: goto yy63;
	}
yy324:
	yyaccept = 27;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy325;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy324;
		default: goto yy62;
	}
yy325:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_INT32];          goto lit; }
yy326:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy327;
		default: goto yy64;
	}
yy327:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy327;
		default: goto yy325;
	}
yy328:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy329;
		default: goto yy63;
	}
yy329:
	yyaccept = 28;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy330;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy329;
		default: goto yy62;
	}
yy330:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_INT64];          goto lit; }
yy331:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy332;
		default: goto yy64;
	}
yy332:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy332;
		default: goto yy330;
	}
yy333:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy368;
		default: goto yy63;
	}
yy334:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy369;
		default: goto yy63;
	}
yy335:
	yyaccept = 29;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']':
			YYSTAGP(yyt1);
			goto yy336;
		case 0x08: goto yy335;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy337;
		case '#':
		case '/': goto yy16;
		case '&':
			YYSTAGP(yyt1);
			goto yy371;
		default:
			YYSTAGP(yyt1);
			goto yy370;
	}
yy336:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_NODEID];         goto lit; }
yy337:
	yyaccept = 29;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '#':
		case '(':
		case ')':
		case ',':
		case '.':
		case '/':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']':
			YYSTAGP(yyt1);
			goto yy336;
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy337;
		case '&':
			YYSTAGP(yyt1);
			goto yy373;
		default:
			YYSTAGP(yyt1);
			goto yy372;
	}
yy338:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy374;
		default: goto yy63;
	}
yy339:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy340;
		default: goto yy63;
	}
yy340:
	yyaccept = 30;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy341;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy340;
		default: goto yy62;
	}
yy341:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_SBYTE];          goto lit; }
yy342:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy343;
		default: goto yy64;
	}
yy343:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy343;
		default: goto yy341;
	}
yy344:
	yyaccept = 31;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy345;
		case 0x08: goto yy344;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy346;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		default: goto yy62;
	}
yy345:
	YYRESTORETAG(yyt1);
	{ tokenId = EF_TOK_SELECT; goto finish; }
yy346:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy346;
		default: goto yy345;
	}
yy347:
	yyaccept = 31;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy345;
		default: goto yy63;
	}
yy348:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'O':
		case 'o': goto yy375;
		default: goto yy63;
	}
yy349:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy349;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy350;
		case '"':
			YYSTAGP(yyt1);
			goto yy376;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '\'':
			YYSTAGP(yyt1);
			goto yy377;
		default: goto yy62;
	}
yy350:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy350;
		case '"':
			YYSTAGP(yyt1);
			goto yy378;
		case '\'':
			YYSTAGP(yyt1);
			goto yy380;
		default: goto yy64;
	}
yy351:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy351;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy352;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy382;
		default: goto yy62;
	}
yy352:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy352;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy384;
		default: goto yy64;
	}
yy353:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy353;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy354;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy385;
		default: goto yy62;
	}
yy354:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy354;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy387;
		default: goto yy64;
	}
yy355:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy355;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy356;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy388;
		default: goto yy62;
	}
yy356:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy356;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy390;
		default: goto yy64;
	}
yy357:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy391;
		default: goto yy63;
	}
yy358:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'R':
		case 'r': goto yy392;
		default: goto yy63;
	}
yy359:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy359;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy360;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case 'F':
		case 'f':
			YYSTAGP(yyt1);
			goto yy393;
		case 'T':
		case 't':
			YYSTAGP(yyt1);
			goto yy394;
		default: goto yy62;
	}
yy360:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy360;
		case 'F':
		case 'f':
			YYSTAGP(yyt1);
			goto yy395;
		case 'T':
		case 't':
			YYSTAGP(yyt1);
			goto yy396;
		default: goto yy64;
	}
yy361:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy397;
		default: goto yy63;
	}
yy362:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy398;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy399;
		default: goto yy63;
	}
yy363:
	yyaccept = 32;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy364;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '+':
		case '-':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'E':
		case 'e': goto yy363;
		case '.': goto yy365;
		default: goto yy62;
	}
yy364:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_DOUBLE];         goto lit; }
yy365:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '+':
		case '-':
		case '.':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'E':
		case 'e': goto yy365;
		default: goto yy364;
	}
yy366:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy400;
		default: goto yy63;
	}
yy367:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'H':
		case 'h': goto yy401;
		default: goto yy63;
	}
yy368:
	yyaccept = 33;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy31;
		case 'O':
		case 'o': goto yy402;
		default: goto yy63;
	}
yy369:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy403;
		default: goto yy63;
	}
yy370:
	yyaccept = 34;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy336;
		case '#':
		case '/': goto yy16;
		case '&': goto yy371;
		default: goto yy370;
	}
yy371:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy370;
	}
yy372:
	yyaccept = 34;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '#':
		case '(':
		case ')':
		case ',':
		case '.':
		case '/':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy336;
		case '&': goto yy373;
		default: goto yy372;
	}
yy373:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy372;
	}
yy374:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy404;
		default: goto yy63;
	}
yy375:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy405;
		default: goto yy63;
	}
yy376:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy378;
		case '"': goto yy406;
		case '#':
		case '/': goto yy408;
		case '&': goto yy409;
		case '\\': goto yy410;
		default: goto yy376;
	}
yy377:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy380;
		case '#':
		case '/': goto yy411;
		case '&': goto yy412;
		case '\'': goto yy413;
		case '\\': goto yy415;
		default: goto yy377;
	}
yy378:
	YYSKIP();
	yych = YYPEEK();
yy379:
	switch (yych) {
		case 0x00: goto yy64;
		case '"': goto yy416;
		case '\\': goto yy417;
		default: goto yy378;
	}
yy380:
	YYSKIP();
	yych = YYPEEK();
yy381:
	switch (yych) {
		case 0x00: goto yy64;
		case '\'': goto yy418;
		case '\\': goto yy419;
		default: goto yy380;
	}
yy382:
	yyaccept = 35;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy383;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy382;
		default: goto yy62;
	}
yy383:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_UINT16];         goto lit; }
yy384:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy384;
		default: goto yy383;
	}
yy385:
	yyaccept = 36;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy386;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy385;
		default: goto yy62;
	}
yy386:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_UINT32];         goto lit; }
yy387:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy387;
		default: goto yy386;
	}
yy388:
	yyaccept = 37;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy389;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy388;
		default: goto yy62;
	}
yy389:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_UINT64];         goto lit; }
yy390:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy390;
		default: goto yy389;
	}
yy391:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy420;
		default: goto yy63;
	}
yy392:
	yyaccept = 5;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy61;
		default: goto yy63;
	}
yy393:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy421;
		default: goto yy63;
	}
yy394:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'R':
		case 'r': goto yy422;
		default: goto yy63;
	}
yy395:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy423;
		default: goto yy64;
	}
yy396:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'R':
		case 'r': goto yy424;
		default: goto yy64;
	}
yy397:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'G':
		case 'g': goto yy425;
		default: goto yy63;
	}
yy398:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy398;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy399;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '-':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':
			YYSTAGP(yyt1);
			goto yy426;
		case ':':
			YYSTAGP(yyt1);
			goto yy428;
		default: goto yy62;
	}
yy399:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy399;
		case '-':
		case ':':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':
			YYSTAGP(yyt1);
			goto yy428;
		default: goto yy64;
	}
yy400:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'O':
		case 'o': goto yy429;
		default: goto yy63;
	}
yy401:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy430;
		default: goto yy63;
	}
yy402:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'R':
		case 'r': goto yy431;
		default: goto yy63;
	}
yy403:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy432;
		default: goto yy63;
	}
yy404:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy433;
		default: goto yy63;
	}
yy405:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy434;
		default: goto yy63;
	}
yy406:
	yyaccept = 38;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy407;
		default: goto yy63;
	}
yy407:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_STRING];         goto lit; }
yy408:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy18;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy378;
		case '"': goto yy435;
		case '&': goto yy436;
		case '[': goto yy437;
		case '\\': goto yy438;
		default: goto yy408;
	}
yy409:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\n': goto yy378;
		case '"': goto yy406;
		case '\\': goto yy410;
		default: goto yy376;
	}
yy410:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy378;
		case '"': goto yy439;
		case '#':
		case '/': goto yy408;
		case '&': goto yy409;
		case '\\': goto yy410;
		default: goto yy376;
	}
yy411:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy18;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy380;
		case '&': goto yy440;
		case '\'': goto yy441;
		case '[': goto yy442;
		case '\\': goto yy443;
		default: goto yy411;
	}
yy412:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\n': goto yy380;
		case '\'': goto yy413;
		case '\\': goto yy415;
		default: goto yy377;
	}
yy413:
	yyaccept = 39;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy414;
		default: goto yy63;
	}
yy414:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_STRING];         goto lit; }
yy415:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy380;
		case '#':
		case '/': goto yy411;
		case '&': goto yy412;
		case '\'': goto yy444;
		case '\\': goto yy415;
		default: goto yy377;
	}
yy416:
	YYSKIP();
	goto yy407;
yy417:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '"': goto yy445;
		case '\\': goto yy417;
		default: goto yy378;
	}
yy418:
	YYSKIP();
	goto yy414;
yy419:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\'': goto yy446;
		case '\\': goto yy419;
		default: goto yy380;
	}
yy420:
	yyaccept = 2;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy21;
		default: goto yy63;
	}
yy421:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy447;
		default: goto yy63;
	}
yy422:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'U':
		case 'u': goto yy448;
		default: goto yy63;
	}
yy423:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy449;
		default: goto yy64;
	}
yy424:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'U':
		case 'u': goto yy450;
		default: goto yy64;
	}
yy425:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy451;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy452;
		default: goto yy63;
	}
yy426:
	yyaccept = 40;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case '[':
		case ']': goto yy427;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '-':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy426;
		case ':': goto yy428;
		default: goto yy62;
	}
yy427:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_DATETIME];       goto lit; }
yy428:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '-':
		case ':':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy428;
		default: goto yy427;
	}
yy429:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy453;
		default: goto yy63;
	}
yy430:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'N':
		case 'n': goto yy454;
		default: goto yy63;
	}
yy431:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy455;
		default: goto yy63;
	}
yy432:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy456;
		default: goto yy63;
	}
yy433:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy457;
		default: goto yy63;
	}
yy434:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy458;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy459;
		default: goto yy63;
	}
yy435:
	yyaccept = 38;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy407;
		default: goto yy17;
	}
yy436:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\n': goto yy378;
		case '"': goto yy435;
		case '\\': goto yy438;
		default: goto yy408;
	}
yy437:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case ',':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case ':': goto yy460;
		default: goto yy379;
	}
yy438:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy18;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy378;
		case '"': goto yy461;
		case '&': goto yy436;
		case '[': goto yy437;
		case '\\': goto yy438;
		default: goto yy408;
	}
yy439:
	yyaccept = 38;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy407;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy378;
		case '"': goto yy406;
		case '#':
		case '/': goto yy408;
		case '&': goto yy409;
		case '\\': goto yy410;
		default: goto yy376;
	}
yy440:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\n': goto yy380;
		case '\'': goto yy441;
		case '\\': goto yy443;
		default: goto yy411;
	}
yy441:
	yyaccept = 39;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy414;
		default: goto yy17;
	}
yy442:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case ',':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case ':': goto yy462;
		default: goto yy381;
	}
yy443:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy18;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy380;
		case '&': goto yy440;
		case '\'': goto yy463;
		case '[': goto yy442;
		case '\\': goto yy443;
		default: goto yy411;
	}
yy444:
	yyaccept = 39;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy414;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy380;
		case '#':
		case '/': goto yy411;
		case '&': goto yy412;
		case '\'': goto yy413;
		case '\\': goto yy415;
		default: goto yy377;
	}
yy445:
	yyaccept = 38;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy407;
		case '"': goto yy416;
		case '\\': goto yy417;
		default: goto yy378;
	}
yy446:
	yyaccept = 39;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy414;
		case '\'': goto yy418;
		case '\\': goto yy419;
		default: goto yy380;
	}
yy447:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'S':
		case 's': goto yy448;
		default: goto yy63;
	}
yy448:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy464;
		default: goto yy63;
	}
yy449:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'S':
		case 's': goto yy450;
		default: goto yy64;
	}
yy450:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy466;
		default: goto yy64;
	}
yy451:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy451;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy452;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '=':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':
			YYSTAGP(yyt1);
			goto yy467;
		default: goto yy62;
	}
yy452:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy452;
		case '=':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':
			YYSTAGP(yyt1);
			goto yy469;
		default: goto yy64;
	}
yy453:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy470;
		default: goto yy63;
	}
yy454:
	yyaccept = 41;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy34;
		case 'O':
		case 'o': goto yy471;
		default: goto yy63;
	}
yy455:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'Q':
		case 'q': goto yy472;
		default: goto yy63;
	}
yy456:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'X':
		case 'x': goto yy473;
		default: goto yy63;
	}
yy457:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'M':
		case 'm': goto yy474;
		default: goto yy63;
	}
yy458:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy458;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy459;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':
			YYSTAGP(yyt1);
			goto yy475;
		default: goto yy62;
	}
yy459:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy459;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':
			YYSTAGP(yyt1);
			goto yy477;
		default: goto yy64;
	}
yy460:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '"': goto yy416;
		case ',':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case ':': goto yy460;
		case '\\': goto yy417;
		case ']': goto yy478;
		default: goto yy378;
	}
yy461:
	yyaccept = 38;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy407;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy378;
		case '"': goto yy435;
		case '&': goto yy436;
		case '[': goto yy437;
		case '\\': goto yy438;
		default: goto yy408;
	}
yy462:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy64;
		case '\'': goto yy418;
		case ',':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case ':': goto yy462;
		case '\\': goto yy419;
		case ']': goto yy479;
		default: goto yy380;
	}
yy463:
	yyaccept = 39;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00: goto yy414;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case ']': goto yy380;
		case '&': goto yy440;
		case '\'': goto yy441;
		case '[': goto yy442;
		case '\\': goto yy443;
		default: goto yy411;
	}
yy464:
	yyaccept = 42;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy465;
		default: goto yy63;
	}
yy465:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_BOOLEAN];        goto lit; }
yy466:
	YYSKIP();
	goto yy465;
yy467:
	yyaccept = 43;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy468;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '=':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy467;
		default: goto yy62;
	}
yy468:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_BYTESTRING];     goto lit; }
yy469:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '=':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy469;
		default: goto yy468;
	}
yy470:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'I':
		case 'i': goto yy480;
		default: goto yy63;
	}
yy471:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'R':
		case 'r': goto yy481;
		default: goto yy63;
	}
yy472:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'U':
		case 'u': goto yy482;
		default: goto yy63;
	}
yy473:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'T':
		case 't': goto yy483;
		default: goto yy63;
	}
yy474:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy484;
		default: goto yy63;
	}
yy475:
	yyaccept = 44;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy476;
		case '#':
		case '/': goto yy16;
		case '&': goto yy65;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy475;
		default: goto yy62;
	}
yy476:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_STATUSCODE];     goto lit; }
yy477:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy477;
		default: goto yy476;
	}
yy478:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	if (yych <= 0x00) goto yy18;
	goto yy379;
yy479:
	yyaccept = 1;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	if (yych <= 0x00) goto yy18;
	goto yy381;
yy480:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'D':
		case 'd': goto yy485;
		default: goto yy63;
	}
yy481:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'E':
		case 'e': goto yy486;
		default: goto yy63;
	}
yy482:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy487;
		default: goto yy63;
	}
yy483:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy488;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy489;
		default: goto yy63;
	}
yy484:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy490;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy492;
		default: goto yy63;
	}
yy485:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x08: goto yy493;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy495;
		default: goto yy63;
	}
yy486:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'Q':
		case 'q': goto yy496;
		default: goto yy63;
	}
yy487:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy497;
		default: goto yy63;
	}
yy488:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08: goto yy488;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy489;
		case '#':
		case '/': goto yy16;
		case '&':
			YYSTAGP(yyt1);
			goto yy499;
		case ':':
			YYSTAGP(yyt1);
			goto yy500;
		default:
			YYSTAGP(yyt1);
			goto yy498;
	}
yy489:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '#':
		case '(':
		case ')':
		case ',':
		case '.':
		case '/':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy489;
		case '&':
			YYSTAGP(yyt1);
			goto yy503;
		case ':':
			YYSTAGP(yyt1);
			goto yy500;
		default:
			YYSTAGP(yyt1);
			goto yy502;
	}
yy490:
	yyaccept = 45;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']':
			YYSTAGP(yyt1);
			goto yy491;
		case 0x08: goto yy490;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy492;
		case '#':
		case '/': goto yy16;
		case '&':
			YYSTAGP(yyt1);
			goto yy505;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy506;
		default:
			YYSTAGP(yyt1);
			goto yy504;
	}
yy491:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_QUALIFIEDNAME];  goto lit; }
yy492:
	yyaccept = 45;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '#':
		case '(':
		case ')':
		case ',':
		case '.':
		case '/':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']':
			YYSTAGP(yyt1);
			goto yy491;
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy492;
		case '&':
			YYSTAGP(yyt1);
			goto yy508;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			YYSTAGP(yyt1);
			goto yy509;
		default:
			YYSTAGP(yyt1);
			goto yy507;
	}
yy493:
	yyaccept = 46;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']':
			YYSTAGP(yyt1);
			goto yy494;
		case 0x08: goto yy493;
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy495;
		case '#':
		case '/': goto yy16;
		case '&':
			YYSTAGP(yyt1);
			goto yy511;
		default:
			YYSTAGP(yyt1);
			goto yy510;
	}
yy494:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_EXPANDEDNODEID]; goto lit; }
yy495:
	yyaccept = 46;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\f':
		case '!':
		case '#':
		case '(':
		case ')':
		case ',':
		case '.':
		case '/':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']':
			YYSTAGP(yyt1);
			goto yy494;
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\r':
		case ' ': goto yy495;
		case '&':
			YYSTAGP(yyt1);
			goto yy513;
		default:
			YYSTAGP(yyt1);
			goto yy512;
	}
yy496:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'U':
		case 'u': goto yy514;
		default: goto yy63;
	}
yy497:
	yyaccept = 47;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy94;
		default: goto yy63;
	}
yy498:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case '#':
		case '/': goto yy16;
		case '&': goto yy499;
		case ':': goto yy500;
		default: goto yy498;
	}
yy499:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy498;
	}
yy500:
	yyaccept = 48;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '#':
		case '(':
		case ')':
		case ',':
		case '.':
		case '/':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy501;
		case '&': goto yy515;
		default: goto yy500;
	}
yy501:
	b = yyt1;
	{ lt = &UA_TYPES[UA_TYPES_LOCALIZEDTEXT];  goto lit; }
yy502:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '#':
		case '(':
		case ')':
		case ',':
		case '.':
		case '/':
		case '<':
		case '>':
		case '[':
		case ']': goto yy64;
		case '&': goto yy503;
		case ':': goto yy500;
		default: goto yy502;
	}
yy503:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy502;
	}
yy504:
	yyaccept = 49;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy491;
		case '#':
		case '/': goto yy16;
		case '&': goto yy505;
		default: goto yy504;
	}
yy505:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy504;
	}
yy506:
	yyaccept = 49;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case '<':
		case '>':
		case '[':
		case ']': goto yy491;
		case '#':
		case '/': goto yy16;
		case '&': goto yy505;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy506;
		case ':': goto yy507;
		default: goto yy504;
	}
yy507:
	yyaccept = 49;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '#':
		case '(':
		case ')':
		case ',':
		case '.':
		case '/':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy491;
		case '&': goto yy508;
		default: goto yy507;
	}
yy508:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy507;
	}
yy509:
	yyaccept = 49;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '#':
		case '(':
		case ')':
		case ',':
		case '.':
		case '/':
		case '<':
		case '>':
		case '[':
		case ']': goto yy491;
		case '&': goto yy508;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': goto yy509;
		default: goto yy507;
	}
yy510:
	yyaccept = 50;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy494;
		case '#':
		case '/': goto yy16;
		case '&': goto yy511;
		default: goto yy510;
	}
yy511:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy510;
	}
yy512:
	yyaccept = 50;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '#':
		case '(':
		case ')':
		case ',':
		case '.':
		case '/':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy494;
		case '&': goto yy513;
		default: goto yy512;
	}
yy513:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy512;
	}
yy514:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'A':
		case 'a': goto yy516;
		default: goto yy63;
	}
yy515:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\n': goto yy64;
		default: goto yy500;
	}
yy516:
	YYSKIP();
	yych = YYPEEK();
	switch (yych) {
		case 'L':
		case 'l': goto yy517;
		default: goto yy63;
	}
yy517:
	yyaccept = 51;
	YYSKIP();
	YYBACKUP();
	yych = YYPEEK();
	switch (yych) {
		case 0x00:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
		case '!':
		case '(':
		case ')':
		case ',':
		case '.':
		case ':':
		case '<':
		case '>':
		case '[':
		case ']': goto yy98;
		default: goto yy63;
	}
}

    }

unary_op:
    tokenId = EF_TOK_UNARY_OP;
    goto make_op;

binary_op:
    tokenId = EF_TOK_BINARY_OP;
    goto make_op;

make_op:
    *token = create_operand(ctx, OT_OPERATOR);
    (*token)->operand.op.filter = f;
    goto finish;

namedoperand:
    *token = create_operand(ctx, OT_REF);
    size_t nameSize = (uintptr_t)(pos - b);
    (*token)->operand.ref = (char*)UA_malloc(nameSize+1);
    memcpy((*token)->operand.ref, b, nameSize);
    (*token)->operand.ref[nameSize] = 0;
    tokenId = EF_TOK_NAMEDOPERAND;
    goto finish;

json:
    
    match.length = (uintptr_t)(end-b);
    match.data = (UA_Byte*)(uintptr_t)b;
    *token = create_operand(ctx, OT_LITERAL);
    UA_DecodeJsonOptions options;
    memset(&options, 0, sizeof(UA_DecodeJsonOptions));
    size_t jsonOffset = 0;
    options.decodedLength = &jsonOffset;
    res = UA_decodeJson(&match, &(*token)->operand.literal,
                        &UA_TYPES[UA_TYPES_VARIANT], &options);
    tokenId = (res == UA_STATUSCODE_GOOD) ? EF_TOK_LITERAL : 0;
    pos = b + jsonOffset;
    goto finish;

lit:
    
    match.length = (uintptr_t)(pos-b);
    match.data = (UA_Byte*)(uintptr_t)b;
    *token = create_operand(ctx, OT_LITERAL);
    (*token)->operand.literal.data = UA_new(lt);
    (*token)->operand.literal.type = lt;
    if(lt == &UA_TYPES[UA_TYPES_NODEID]) {
        res = UA_NodeId_parse((UA_NodeId*)(*token)->operand.literal.data, match);
    } else if(lt == &UA_TYPES[UA_TYPES_EXPANDEDNODEID]) {
        res = UA_ExpandedNodeId_parse((UA_ExpandedNodeId*)(*token)->operand.literal.data, match);
    } else if(lt == &UA_TYPES[UA_TYPES_GUID]) {
        res = UA_Guid_parse((UA_Guid*)(*token)->operand.literal.data, match);
    } else {
        res = UA_decodeJson(&match, (*token)->operand.literal.data, lt, NULL);
    }
    tokenId = (res == UA_STATUSCODE_GOOD) ? EF_TOK_LITERAL : 0;
    goto finish;

sao:
    
    match.length = (uintptr_t)(pos-b);
    match.data = (UA_Byte*)(uintptr_t)b;
    *token = create_operand(ctx, OT_SAO);
    res = UA_SimpleAttributeOperand_parse(&(*token)->operand.sao, match);
    tokenId = (res == UA_STATUSCODE_GOOD) ? EF_TOK_SAO : 0;

finish:
    if(pos > end)
        pos = end;

    
    if(tokenId != 0)
        *offset = (uintptr_t)(pos - (const char*)content.data);

    return tokenId;
}
