
#include <opcua/util.h>
#include "ua_eventfilter_parser.h"

#define UA_EventFilterParse_ENGINEALWAYSONSTACK 1
#define NDEBUG 1


static void UA_EventFilterParseInit(void *);
static void UA_EventFilterParseFinalize(void *p);
int UA_EventFilterParseFallback(int iToken);
static void UA_EventFilterParse(void *yyp, int yymajor, Operand *token, EFParseContext *ctx);

#ifndef EF_TOK_OR
#define EF_TOK_OR                              1
#define EF_TOK_AND                             2
#define EF_TOK_NOT                             3
#define EF_TOK_BINARY_OP                       4
#define EF_TOK_BETWEEN                         5
#define EF_TOK_INLIST                          6
#define EF_TOK_UNARY_OP                        7
#define EF_TOK_SELECT                          8
#define EF_TOK_COMMA                           9
#define EF_TOK_WHERE                          10
#define EF_TOK_SAO                            11
#define EF_TOK_LITERAL                        12
#define EF_TOK_NAMEDOPERAND                   13
#define EF_TOK_LPAREN                         14
#define EF_TOK_RPAREN                         15
#define EF_TOK_LBRACKET                       16
#define EF_TOK_RBRACKET                       17
#define EF_TOK_FOR                            18
#define EF_TOK_COLONEQUAL                     19
#endif


#ifndef INTERFACE
# define INTERFACE 1
#endif

#define YYCODETYPE unsigned char
#define YYNOCODE 30
#define YYACTIONTYPE unsigned char
#define UA_EventFilterParseTOKENTYPE  Operand * 
typedef union {
  int yyinit;
  UA_EventFilterParseTOKENTYPE yy0;
} YYMINORTYPE;
#ifndef YYSTACKDEPTH
#define YYSTACKDEPTH 100
#endif
#define UA_EventFilterParseARG_SDECL  EFParseContext *ctx ;
#define UA_EventFilterParseARG_PDECL , EFParseContext *ctx 
#define UA_EventFilterParseARG_PARAM ,ctx 
#define UA_EventFilterParseARG_FETCH  EFParseContext *ctx =yypParser->ctx ;
#define UA_EventFilterParseARG_STORE yypParser->ctx =ctx ;
#define UA_EventFilterParseCTX_SDECL
#define UA_EventFilterParseCTX_PDECL
#define UA_EventFilterParseCTX_PARAM
#define UA_EventFilterParseCTX_FETCH
#define UA_EventFilterParseCTX_STORE
#define YYNSTATE             37
#define YYNRULE              26
#define YYNRULE_WITH_ACTION  18
#define YYNTOKEN             20
#define YY_MAX_SHIFT         36
#define YY_MIN_SHIFTREDUCE   49
#define YY_MAX_SHIFTREDUCE   74
#define YY_ERROR_ACTION      75
#define YY_ACCEPT_ACTION     76
#define YY_NO_ACTION         77
#define YY_MIN_REDUCE        78
#define YY_MAX_REDUCE        103

#define YY_NLOOKAHEAD ((int)(sizeof(yy_lookahead)/sizeof(yy_lookahead[0])))

#ifndef yytestcase
# define yytestcase(X)
#endif


#define YY_ACTTAB_COUNT (92)
static const YYACTIONTYPE yy_action[] = {
     30,   23,   82,   11,  103,   12,   10,    9,    8,   32,
     33,   52,   54,   55,   13,   12,   10,    1,    8,   32,
     33,   63,   36,    6,   34,   12,   10,    5,    8,   32,
     33,   12,   10,    2,    8,   32,   33,   12,   10,   62,
      8,   32,   33,   15,   10,   56,    8,   32,   33,   35,
     35,   21,   82,   94,   21,   82,   31,    8,   32,   33,
      4,   76,   18,   24,   82,   14,   17,   77,   25,   82,
     19,   82,   20,   82,   90,   82,   16,   87,   82,   28,
     82,   29,   82,   27,   82,   22,   82,   26,   82,    7,
      3,   96,
};
static const YYCODETYPE yy_lookahead[] = {
     24,   25,   26,    3,   29,    1,    2,    7,    4,    5,
      6,   11,   12,   13,   14,    1,    2,    8,    4,    5,
      6,   17,   23,    9,   13,    1,    2,   10,    4,    5,
      6,    1,    2,    9,    4,    5,    6,    1,    2,   17,
      4,    5,    6,   18,    2,   15,    4,    5,    6,   28,
     29,   25,   26,   27,   25,   26,   27,    4,    5,    6,
      9,   20,   21,   25,   26,   19,   22,   30,   25,   26,
     25,   26,   25,   26,   25,   26,    9,   25,   26,   25,
     26,   25,   26,   25,   26,   25,   26,   25,   26,   16,
     16,    0,   30,   30,   30,   30,   30,   30,   30,   30,
     30,   30,   30,   30,   30,   30,   30,   30,   30,   30,
     30,   30,
};
#define YY_SHIFT_COUNT    (36)
#define YY_SHIFT_MIN      (0)
#define YY_SHIFT_MAX      (91)
static const unsigned char yy_shift_ofst[] = {
      9,    0,    0,    0,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,   11,   11,   25,   17,    4,
     14,   24,   30,   36,   36,   36,   36,   42,   53,   53,
     51,   22,   73,   74,   46,   67,   91,
};
#define YY_REDUCE_COUNT (18)
#define YY_REDUCE_MIN   (-25)
#define YY_REDUCE_MAX   (62)
static const signed char yy_reduce_ofst[] = {
     41,  -24,   26,   29,   38,   43,   45,   47,   49,   52,
     54,   56,   58,   60,   62,   21,  -25,   -1,   44,
};
static const YYACTIONTYPE yy_default[] = {
     97,   75,   75,   75,   75,   75,   75,   75,   75,   75,
     75,   75,   75,   75,   75,   75,   75,  100,   99,   75,
     75,   93,   75,   78,   79,   80,   95,   88,   89,   86,
     98,   75,   75,   75,   75,  101,   75,
};


#ifdef YYFALLBACK
static const YYCODETYPE yyFallback[] = {
};
#endif 

struct yyStackEntry {
  YYACTIONTYPE stateno;  
};
typedef struct yyStackEntry yyStackEntry;

struct yyParser {
  yyStackEntry *yytos;          
#ifdef YYTRACKMAXSTACKDEPTH
  int yyhwm;                    
#endif
#ifndef YYNOERRORRECOVERY
  int yyerrcnt;                 
#endif
  UA_EventFilterParseARG_SDECL                
  UA_EventFilterParseCTX_SDECL                
#if YYSTACKDEPTH<=0
  int yystksz;                  
  yyStackEntry *yystack;        
  yyStackEntry yystk0;          
#else
  yyStackEntry yystack[YYSTACKDEPTH];  
  yyStackEntry *yystackEnd;            
#endif
};
typedef struct yyParser yyParser;

#include <assert.h>
#ifndef NDEBUG
#include <stdio.h>
static FILE *yyTraceFILE = 0;
static char *yyTracePrompt = 0;
#endif 

#ifndef NDEBUG
void UA_EventFilterParseTrace(FILE *TraceFILE, char *zTracePrompt){
  yyTraceFILE = TraceFILE;
  yyTracePrompt = zTracePrompt;
  if( yyTraceFILE==0 ) yyTracePrompt = 0;
  else if( yyTracePrompt==0 ) yyTraceFILE = 0;
}
#endif 

#if defined(YYCOVERAGE) || !defined(NDEBUG)
static const char *const yyTokenName[] = { 
   "$",
   "OR",
   "AND",
   "NOT",
   "BINARY_OP",
   "BETWEEN",
   "INLIST",
   "UNARY_OP",
   "SELECT",
   "COMMA",
   "WHERE",
   "SAO",
   "LITERAL",
   "NAMEDOPERAND",
   "LPAREN",
   "RPAREN",
   "LBRACKET",
   "RBRACKET",
   "FOR",
   "COLONEQUAL",
   "eventFilter",
   "selectClause",
   "whereClause",
   "forClause",
   "selectClauseList",
   "operand",
   "operator",
   "operandList",
   "namedOperandAssignmentList",
   "namedOperandAssignment",
};
#endif 

#ifndef NDEBUG
static const char *const yyRuleName[] = {
  "selectClauseList ::= operand",
  "selectClauseList ::= selectClauseList COMMA operand",
  "whereClause ::= WHERE operand",
  "operand ::= SAO",
  "operand ::= operator",
  "operand ::= LITERAL",
  "operand ::= NAMEDOPERAND",
  "operand ::= LPAREN operand RPAREN",
  "operator ::= NOT operand",
  "operator ::= UNARY_OP operand",
  "operator ::= operand OR operand",
  "operator ::= operand AND operand",
  "operator ::= operand BINARY_OP operand",
  "operator ::= operand INLIST LBRACKET operandList RBRACKET",
  "operator ::= operand BETWEEN LBRACKET operand COMMA operand RBRACKET",
  "operandList ::= operand",
  "operandList ::= operand COMMA operandList",
  "namedOperandAssignment ::= NAMEDOPERAND COLONEQUAL operand",
  "eventFilter ::= selectClause whereClause forClause",
  "selectClause ::=",
  "selectClause ::= SELECT selectClauseList",
  "whereClause ::=",
  "forClause ::=",
  "forClause ::= FOR namedOperandAssignmentList",
  "namedOperandAssignmentList ::= namedOperandAssignment",
  "namedOperandAssignmentList ::= namedOperandAssignmentList COMMA namedOperandAssignment",
};
#endif 


#if YYSTACKDEPTH<=0
static int yyGrowStack(yyParser *p){
  int newSize;
  int idx;
  yyStackEntry *pNew;

  newSize = p->yystksz*2 + 100;
  idx = p->yytos ? (int)(p->yytos - p->yystack) : 0;
  if( p->yystack==&p->yystk0 ){
    pNew = malloc(newSize*sizeof(pNew[0]));
    if( pNew ) pNew[0] = p->yystk0;
  }else{
    pNew = realloc(p->yystack, newSize*sizeof(pNew[0]));
  }
  if( pNew ){
    p->yystack = pNew;
    p->yytos = &p->yystack[idx];
#ifndef NDEBUG
    if( yyTraceFILE ){
      fprintf(yyTraceFILE,"%sStack grows from %d to %d entries.\n",
              yyTracePrompt, p->yystksz, newSize);
    }
#endif
    p->yystksz = newSize;
  }
  return pNew==0; 
}
#endif

#ifndef YYMALLOCARGTYPE
# define YYMALLOCARGTYPE size_t
#endif

void UA_EventFilterParseInit(void *yypRawParser UA_EventFilterParseCTX_PDECL){
  yyParser *yypParser = (yyParser*)yypRawParser;
  UA_EventFilterParseCTX_STORE
#ifdef YYTRACKMAXSTACKDEPTH
  yypParser->yyhwm = 0;
#endif
#if YYSTACKDEPTH<=0
  yypParser->yytos = NULL;
  yypParser->yystack = NULL;
  yypParser->yystksz = 0;
  if( yyGrowStack(yypParser) ){
    yypParser->yystack = &yypParser->yystk0;
    yypParser->yystksz = 1;
  }
#endif
#ifndef YYNOERRORRECOVERY
  yypParser->yyerrcnt = -1;
#endif
  yypParser->yytos = yypParser->yystack;
  yypParser->yystack[0].stateno = 0;
  yypParser->yystack[0].major = 0;
#if YYSTACKDEPTH>0
  yypParser->yystackEnd = &yypParser->yystack[YYSTACKDEPTH-1];
#endif
}

#ifndef UA_EventFilterParse_ENGINEALWAYSONSTACK
void *UA_EventFilterParseAlloc(void *(*mallocProc)(YYMALLOCARGTYPE) UA_EventFilterParseCTX_PDECL){
  yyParser *yypParser;
  yypParser = (yyParser*)(*mallocProc)( (YYMALLOCARGTYPE)sizeof(yyParser) );
  if( yypParser ){
    UA_EventFilterParseCTX_STORE
    UA_EventFilterParseInit(yypParser UA_EventFilterParseCTX_PARAM);
  }
  return (void*)yypParser;
}
#endif 


static void yy_destructor(
  yyParser *yypParser,    
  YYCODETYPE yymajor,     
  YYMINORTYPE *yypminor   
){
  UA_EventFilterParseARG_FETCH
  UA_EventFilterParseCTX_FETCH
  switch( yymajor ){

      
    case 1: 
    case 2: 
    case 3: 
    case 4: 
    case 5: 
    case 6: 
    case 7: 
    case 8: 
    case 9: 
    case 10: 
    case 11: 
    case 12: 
    case 13: 
    case 14: 
    case 15: 
    case 16: 
    case 17: 
    case 18: 
    case 19: 
{
 (void)ctx; 
}
      break;

    default:  break;   
  }
}

static void yy_pop_parser_stack(yyParser *pParser){
  yyStackEntry *yytos;
  assert( pParser->yytos!=0 );
  assert( pParser->yytos > pParser->yystack );
  yytos = pParser->yytos--;
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sPopping %s\n",
      yyTracePrompt,
      yyTokenName[yytos->major]);
  }
#endif
  yy_destructor(pParser, yytos->major, &yytos->minor);
}

void UA_EventFilterParseFinalize(void *p){
  yyParser *pParser = (yyParser*)p;
  while( pParser->yytos>pParser->yystack ) yy_pop_parser_stack(pParser);
#if YYSTACKDEPTH<=0
  if( pParser->yystack!=&pParser->yystk0 ) free(pParser->yystack);
#endif
}

#ifndef UA_EventFilterParse_ENGINEALWAYSONSTACK
void UA_EventFilterParseFree(
  void *p,                    
  void (*freeProc)(void*)     
){
#ifndef YYPARSEFREENEVERNULL
  if( p==0 ) return;
#endif
  UA_EventFilterParseFinalize(p);
  (*freeProc)(p);
}
#endif 

#ifdef YYTRACKMAXSTACKDEPTH
int UA_EventFilterParseStackPeak(void *p){
  yyParser *pParser = (yyParser*)p;
  return pParser->yyhwm;
}
#endif

#if defined(YYCOVERAGE)
static unsigned char yycoverage[YYNSTATE][YYNTOKEN];
#endif

#if defined(YYCOVERAGE)
int UA_EventFilterParseCoverage(FILE *out){
  int stateno, iLookAhead, i;
  int nMissed = 0;
  for(stateno=0; stateno<YYNSTATE; stateno++){
    i = yy_shift_ofst[stateno];
    for(iLookAhead=0; iLookAhead<YYNTOKEN; iLookAhead++){
      if( yy_lookahead[i+iLookAhead]!=iLookAhead ) continue;
      if( yycoverage[stateno][iLookAhead]==0 ) nMissed++;
      if( out ){
        fprintf(out,"State %d lookahead %s %s\n", stateno,
                yyTokenName[iLookAhead],
                yycoverage[stateno][iLookAhead] ? "ok" : "missed");
      }
    }
  }
  return nMissed;
}
#endif

static YYACTIONTYPE yy_find_shift_action(
  YYCODETYPE iLookAhead,    
  YYACTIONTYPE stateno      
){
  int i;

  if( stateno>YY_MAX_SHIFT ) return stateno;
  assert( stateno <= YY_SHIFT_COUNT );
#if defined(YYCOVERAGE)
  yycoverage[stateno][iLookAhead] = 1;
#endif
  do{
    i = yy_shift_ofst[stateno];
    assert( i>=0 );
    assert( i<=YY_ACTTAB_COUNT );
    assert( i+YYNTOKEN<=(int)YY_NLOOKAHEAD );
    assert( iLookAhead!=YYNOCODE );
    assert( iLookAhead < YYNTOKEN );
    i += iLookAhead;
    assert( i<(int)YY_NLOOKAHEAD );
    if( yy_lookahead[i]!=iLookAhead ){
#ifdef YYFALLBACK
      YYCODETYPE iFallback;            
      assert( iLookAhead<sizeof(yyFallback)/sizeof(yyFallback[0]) );
      iFallback = yyFallback[iLookAhead];
      if( iFallback!=0 ){
#ifndef NDEBUG
        if( yyTraceFILE ){
          fprintf(yyTraceFILE, "%sFALLBACK %s => %s\n",
             yyTracePrompt, yyTokenName[iLookAhead], yyTokenName[iFallback]);
        }
#endif
        assert( yyFallback[iFallback]==0 ); 
        iLookAhead = iFallback;
        continue;
      }
#endif
#ifdef YYWILDCARD
      {
        int j = i - iLookAhead + YYWILDCARD;
        assert( j<(int)(sizeof(yy_lookahead)/sizeof(yy_lookahead[0])) );
        if( yy_lookahead[j]==YYWILDCARD && iLookAhead>0 ){
#ifndef NDEBUG
          if( yyTraceFILE ){
            fprintf(yyTraceFILE, "%sWILDCARD %s => %s\n",
               yyTracePrompt, yyTokenName[iLookAhead],
               yyTokenName[YYWILDCARD]);
          }
#endif 
          return yy_action[j];
        }
      }
#endif 
      return yy_default[stateno];
    }else{
      assert( i>=0 && i<(int)(sizeof(yy_action)/sizeof(yy_action[0])) );
      return yy_action[i];
    }
  }while(1);
}

static YYACTIONTYPE yy_find_reduce_action(
  YYACTIONTYPE stateno,     
  YYCODETYPE iLookAhead     
){
  int i;
#ifdef YYERRORSYMBOL
  if( stateno>YY_REDUCE_COUNT ){
    return yy_default[stateno];
  }
#else
  assert( stateno<=YY_REDUCE_COUNT );
#endif
  i = yy_reduce_ofst[stateno];
  assert( iLookAhead!=YYNOCODE );
  i += iLookAhead;
#ifdef YYERRORSYMBOL
  if( i<0 || i>=YY_ACTTAB_COUNT || yy_lookahead[i]!=iLookAhead ){
    return yy_default[stateno];
  }
#else
  assert( i>=0 && i<YY_ACTTAB_COUNT );
  assert( yy_lookahead[i]==iLookAhead );
#endif
  return yy_action[i];
}

static void yyStackOverflow(yyParser *yypParser){
   UA_EventFilterParseARG_FETCH
   UA_EventFilterParseCTX_FETCH
#ifndef NDEBUG
   if( yyTraceFILE ){
     fprintf(yyTraceFILE,"%sStack Overflow!\n",yyTracePrompt);
   }
#endif
   while( yypParser->yytos>yypParser->yystack ) yy_pop_parser_stack(yypParser);


   UA_EventFilterParseARG_STORE 
   UA_EventFilterParseCTX_STORE
}

#ifndef NDEBUG
static void yyTraceShift(yyParser *yypParser, int yyNewState, const char *zTag){
  if( yyTraceFILE ){
    if( yyNewState<YYNSTATE ){
      fprintf(yyTraceFILE,"%s%s '%s', go to state %d\n",
         yyTracePrompt, zTag, yyTokenName[yypParser->yytos->major],
         yyNewState);
    }else{
      fprintf(yyTraceFILE,"%s%s '%s', pending reduce %d\n",
         yyTracePrompt, zTag, yyTokenName[yypParser->yytos->major],
         yyNewState - YY_MIN_REDUCE);
    }
  }
}
#else
# define yyTraceShift(X,Y,Z)
#endif

static void yy_shift(
  yyParser *yypParser,          
  YYACTIONTYPE yyNewState,      
  YYCODETYPE yyMajor,           
  UA_EventFilterParseTOKENTYPE yyMinor        
){
  yyStackEntry *yytos;
  yypParser->yytos++;
#ifdef YYTRACKMAXSTACKDEPTH
  if( (int)(yypParser->yytos - yypParser->yystack)>yypParser->yyhwm ){
    yypParser->yyhwm++;
    assert( yypParser->yyhwm == (int)(yypParser->yytos - yypParser->yystack) );
  }
#endif
#if YYSTACKDEPTH>0 
  if( yypParser->yytos>yypParser->yystackEnd ){
    yypParser->yytos--;
    yyStackOverflow(yypParser);
    return;
  }
#else
  if( yypParser->yytos>=&yypParser->yystack[yypParser->yystksz] ){
    if( yyGrowStack(yypParser) ){
      yypParser->yytos--;
      yyStackOverflow(yypParser);
      return;
    }
  }
#endif
  if( yyNewState > YY_MAX_SHIFT ){
    yyNewState += YY_MIN_REDUCE - YY_MIN_SHIFTREDUCE;
  }
  yytos = yypParser->yytos;
  yytos->stateno = yyNewState;
  yytos->major = yyMajor;
  yytos->minor.yy0 = yyMinor;
  yyTraceShift(yypParser, yyNewState, "Shift");
}

static const YYCODETYPE yyRuleInfoLhs[] = {
    24,  
    24,  
    22,  
    25,  
    25,  
    25,  
    25,  
    25,  
    26,  
    26,  
    26,  
    26,  
    26,  
    26,  
    26,  
    27,  
    27,  
    29,  
    20,  
    21,  
    21,  
    22,  
    23,  
    23,  
    28,  
    28,  
};

static const signed char yyRuleInfoNRhs[] = {
   -1,  
   -3,  
   -2,  
   -1,  
   -1,  
   -1,  
   -1,  
   -3,  
   -2,  
   -2,  
   -3,  
   -3,  
   -3,  
   -5,  
   -7,  
   -1,  
   -3,  
   -3,  
   -3,  
    0,  
   -2,  
    0,  
    0,  
   -2,  
   -1,  
   -3,  
};

static void yy_accept(yyParser*);  

static YYACTIONTYPE yy_reduce(
  yyParser *yypParser,         
  unsigned int yyruleno,       
  int yyLookahead,             
  UA_EventFilterParseTOKENTYPE yyLookaheadToken  
  UA_EventFilterParseCTX_PDECL                   
){
  int yygoto;                     
  YYACTIONTYPE yyact;             
  yyStackEntry *yymsp;            
  int yysize;                     
  UA_EventFilterParseARG_FETCH
  (void)yyLookahead;
  (void)yyLookaheadToken;
  yymsp = yypParser->yytos;

  switch( yyruleno ){

        YYMINORTYPE yylhsminor;
      case 0: 
{ append_select(ctx, yymsp[0].minor.yy0); }
        break;
      case 1: 
{ append_select(ctx, yymsp[0].minor.yy0); }
  yy_destructor(yypParser,9,&yymsp[-1].minor);
        break;
      case 2: 
{  yy_destructor(yypParser,10,&yymsp[-1].minor);
{ ctx->top = yymsp[0].minor.yy0; }
}
        break;
      case 3: 
      case 4:  yytestcase(yyruleno==4);
      case 5:  yytestcase(yyruleno==5);
      case 6:  yytestcase(yyruleno==6);
      case 15:  yytestcase(yyruleno==15);
{ yylhsminor.yy0 = yymsp[0].minor.yy0; }
  yymsp[0].minor.yy0 = yylhsminor.yy0;
        break;
      case 7: 
{  yy_destructor(yypParser,14,&yymsp[-2].minor);
{ yymsp[-2].minor.yy0 = yymsp[-1].minor.yy0; }
  yy_destructor(yypParser,15,&yymsp[0].minor);
}
        break;
      case 8: 
      case 9:  yytestcase(yyruleno==9);
{ yylhsminor.yy0 = yymsp[-1].minor.yy0; append_operand(yylhsminor.yy0, yymsp[0].minor.yy0); }
  yymsp[-1].minor.yy0 = yylhsminor.yy0;
        break;
      case 10: 
      case 11:  yytestcase(yyruleno==11);
      case 12:  yytestcase(yyruleno==12);
{ yylhsminor.yy0 = yymsp[-1].minor.yy0; append_operand(yylhsminor.yy0, yymsp[-2].minor.yy0), append_operand(yylhsminor.yy0, yymsp[0].minor.yy0); }
  yymsp[-2].minor.yy0 = yylhsminor.yy0;
        break;
      case 13: 
{ yylhsminor.yy0 = yymsp[-3].minor.yy0; append_operand(yylhsminor.yy0, yymsp[-4].minor.yy0); while(yymsp[-1].minor.yy0) { append_operand(yylhsminor.yy0, yymsp[-1].minor.yy0); yymsp[-1].minor.yy0 = yymsp[-1].minor.yy0->next; } }
  yy_destructor(yypParser,16,&yymsp[-2].minor);
  yy_destructor(yypParser,17,&yymsp[0].minor);
  yymsp[-4].minor.yy0 = yylhsminor.yy0;
        break;
      case 14: 
{ yylhsminor.yy0 = yymsp[-5].minor.yy0; append_operand(yylhsminor.yy0, yymsp[-6].minor.yy0); append_operand(yylhsminor.yy0, yymsp[-3].minor.yy0); append_operand(yylhsminor.yy0, yymsp[-1].minor.yy0); }
  yy_destructor(yypParser,16,&yymsp[-4].minor);
  yy_destructor(yypParser,9,&yymsp[-2].minor);
  yy_destructor(yypParser,17,&yymsp[0].minor);
  yymsp[-6].minor.yy0 = yylhsminor.yy0;
        break;
      case 16: 
{ yylhsminor.yy0 = yymsp[-2].minor.yy0; yymsp[-2].minor.yy0->next = yymsp[0].minor.yy0; }
  yy_destructor(yypParser,9,&yymsp[-1].minor);
  yymsp[-2].minor.yy0 = yylhsminor.yy0;
        break;
      case 17: 
{ yymsp[0].minor.yy0->ref = save_string(yymsp[-2].minor.yy0->operand.ref); }
  yy_destructor(yypParser,19,&yymsp[-1].minor);
        break;
      case 20: 
{  yy_destructor(yypParser,8,&yymsp[-1].minor);
{
}
}
        break;
      case 23: 
{  yy_destructor(yypParser,18,&yymsp[-1].minor);
{
}
}
        break;
      case 25: 
{
}
  yy_destructor(yypParser,9,&yymsp[-1].minor);
        break;
      default:
       yytestcase(yyruleno==18);
       yytestcase(yyruleno==19);
       yytestcase(yyruleno==21);
       yytestcase(yyruleno==22);
       assert(yyruleno!=24);
        break;

  };
  assert( yyruleno<sizeof(yyRuleInfoLhs)/sizeof(yyRuleInfoLhs[0]) );
  yygoto = yyRuleInfoLhs[yyruleno];
  yysize = yyRuleInfoNRhs[yyruleno];
  yyact = yy_find_reduce_action(yymsp[yysize].stateno,(YYCODETYPE)yygoto);

  assert( !(yyact>YY_MAX_SHIFT && yyact<=YY_MAX_SHIFTREDUCE) );

  
  assert( yyact!=YY_ERROR_ACTION );

  yymsp += yysize+1;
  yypParser->yytos = yymsp;
  yymsp->stateno = (YYACTIONTYPE)yyact;
  yymsp->major = (YYCODETYPE)yygoto;
  yyTraceShift(yypParser, yyact, "... then shift");
  return yyact;
}

#ifndef YYNOERRORRECOVERY
static void yy_parse_failed(
  yyParser *yypParser           
){
  UA_EventFilterParseARG_FETCH
  UA_EventFilterParseCTX_FETCH
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sFail!\n",yyTracePrompt);
  }
#endif
  while( yypParser->yytos>yypParser->yystack ) yy_pop_parser_stack(yypParser);


  UA_EventFilterParseARG_STORE 
  UA_EventFilterParseCTX_STORE
}
#endif 

static void yy_syntax_error(
  yyParser *yypParser,           
  int yymajor,                   
  UA_EventFilterParseTOKENTYPE yyminor         
){
  UA_EventFilterParseARG_FETCH
  UA_EventFilterParseCTX_FETCH
#define TOKEN yyminor

 ctx->error = UA_STATUSCODE_BADINTERNALERROR; 

  UA_EventFilterParseARG_STORE 
  UA_EventFilterParseCTX_STORE
}

static void yy_accept(
  yyParser *yypParser           
){
  UA_EventFilterParseARG_FETCH
  UA_EventFilterParseCTX_FETCH
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sAccept!\n",yyTracePrompt);
  }
#endif
#ifndef YYNOERRORRECOVERY
  yypParser->yyerrcnt = -1;
#endif
  assert( yypParser->yytos==yypParser->yystack );


  UA_EventFilterParseARG_STORE 
  UA_EventFilterParseCTX_STORE
}

void UA_EventFilterParse(
  void *yyp,                   
  int yymajor,                 
  UA_EventFilterParseTOKENTYPE yyminor       
  UA_EventFilterParseARG_PDECL               
){
  YYMINORTYPE yyminorunion;
  YYACTIONTYPE yyact;   
#if !defined(YYERRORSYMBOL) && !defined(YYNOERRORRECOVERY)
  int yyendofinput;     
#endif
#ifdef YYERRORSYMBOL
  int yyerrorhit = 0;   
#endif
  yyParser *yypParser = (yyParser*)yyp;  
  UA_EventFilterParseCTX_FETCH
  UA_EventFilterParseARG_STORE

  assert( yypParser->yytos!=0 );
#if !defined(YYERRORSYMBOL) && !defined(YYNOERRORRECOVERY)
  yyendofinput = (yymajor==0);
#endif

  yyact = yypParser->yytos->stateno;
#ifndef NDEBUG
  if( yyTraceFILE ){
    if( yyact < YY_MIN_REDUCE ){
      fprintf(yyTraceFILE,"%sInput '%s' in state %d\n",
              yyTracePrompt,yyTokenName[yymajor],yyact);
    }else{
      fprintf(yyTraceFILE,"%sInput '%s' with pending reduce %d\n",
              yyTracePrompt,yyTokenName[yymajor],yyact-YY_MIN_REDUCE);
    }
  }
#endif

  while(1){ 
    assert( yypParser->yytos>=yypParser->yystack );
    assert( yyact==yypParser->yytos->stateno );
    yyact = yy_find_shift_action((YYCODETYPE)yymajor,yyact);
    if( yyact >= YY_MIN_REDUCE ){
      unsigned int yyruleno = yyact - YY_MIN_REDUCE; 
#ifndef NDEBUG
      assert( yyruleno<(int)(sizeof(yyRuleName)/sizeof(yyRuleName[0])) );
      if( yyTraceFILE ){
        int yysize = yyRuleInfoNRhs[yyruleno];
        if( yysize ){
          fprintf(yyTraceFILE, "%sReduce %d [%s]%s, pop back to state %d.\n",
            yyTracePrompt,
            yyruleno, yyRuleName[yyruleno],
            yyruleno<YYNRULE_WITH_ACTION ? "" : " without external action",
            yypParser->yytos[yysize].stateno);
        }else{
          fprintf(yyTraceFILE, "%sReduce %d [%s]%s.\n",
            yyTracePrompt, yyruleno, yyRuleName[yyruleno],
            yyruleno<YYNRULE_WITH_ACTION ? "" : " without external action");
        }
      }
#endif 

      if( yyRuleInfoNRhs[yyruleno]==0 ){
#ifdef YYTRACKMAXSTACKDEPTH
        if( (int)(yypParser->yytos - yypParser->yystack)>yypParser->yyhwm ){
          yypParser->yyhwm++;
          assert( yypParser->yyhwm ==
                  (int)(yypParser->yytos - yypParser->yystack));
        }
#endif
#if YYSTACKDEPTH>0 
        if( yypParser->yytos>=yypParser->yystackEnd ){
          yyStackOverflow(yypParser);
          break;
        }
#else
        if( yypParser->yytos>=&yypParser->yystack[yypParser->yystksz-1] ){
          if( yyGrowStack(yypParser) ){
            yyStackOverflow(yypParser);
            break;
          }
        }
#endif
      }
      yyact = yy_reduce(yypParser,yyruleno,yymajor,yyminor UA_EventFilterParseCTX_PARAM);
    }else if( yyact <= YY_MAX_SHIFTREDUCE ){
      yy_shift(yypParser,yyact,(YYCODETYPE)yymajor,yyminor);
#ifndef YYNOERRORRECOVERY
      yypParser->yyerrcnt--;
#endif
      break;
    }else if( yyact==YY_ACCEPT_ACTION ){
      yypParser->yytos--;
      yy_accept(yypParser);
      return;
    }else{
      assert( yyact == YY_ERROR_ACTION );
      yyminorunion.yy0 = yyminor;
#ifdef YYERRORSYMBOL
      int yymx;
#endif
#ifndef NDEBUG
      if( yyTraceFILE ){
        fprintf(yyTraceFILE,"%sSyntax Error!\n",yyTracePrompt);
      }
#endif
#ifdef YYERRORSYMBOL
      if( yypParser->yyerrcnt<0 ){
        yy_syntax_error(yypParser,yymajor,yyminor);
      }
      yymx = yypParser->yytos->major;
      if( yymx==YYERRORSYMBOL || yyerrorhit ){
#ifndef NDEBUG
        if( yyTraceFILE ){
          fprintf(yyTraceFILE,"%sDiscard input token %s\n",
             yyTracePrompt,yyTokenName[yymajor]);
        }
#endif
        yy_destructor(yypParser, (YYCODETYPE)yymajor, &yyminorunion);
        yymajor = YYNOCODE;
      }else{
        while( yypParser->yytos > yypParser->yystack ){
          yyact = yy_find_reduce_action(yypParser->yytos->stateno,
                                        YYERRORSYMBOL);
          if( yyact<=YY_MAX_SHIFTREDUCE ) break;
          yy_pop_parser_stack(yypParser);
        }
        if( yypParser->yytos <= yypParser->yystack || yymajor==0 ){
          yy_destructor(yypParser,(YYCODETYPE)yymajor,&yyminorunion);
          yy_parse_failed(yypParser);
#ifndef YYNOERRORRECOVERY
          yypParser->yyerrcnt = -1;
#endif
          yymajor = YYNOCODE;
        }else if( yymx!=YYERRORSYMBOL ){
          yy_shift(yypParser,yyact,YYERRORSYMBOL,yyminor);
        }
      }
      yypParser->yyerrcnt = 3;
      yyerrorhit = 1;
      if( yymajor==YYNOCODE ) break;
      yyact = yypParser->yytos->stateno;
#elif defined(YYNOERRORRECOVERY)
      yy_syntax_error(yypParser,yymajor, yyminor);
      yy_destructor(yypParser,(YYCODETYPE)yymajor,&yyminorunion);
      break;
#else  
      if( yypParser->yyerrcnt<=0 ){
        yy_syntax_error(yypParser,yymajor, yyminor);
      }
      yypParser->yyerrcnt = 3;
      yy_destructor(yypParser,(YYCODETYPE)yymajor,&yyminorunion);
      if( yyendofinput ){
        yy_parse_failed(yypParser);
#ifndef YYNOERRORRECOVERY
        yypParser->yyerrcnt = -1;
#endif
      }
      break;
#endif
    }
  }
#ifndef NDEBUG
  if( yyTraceFILE ){
    yyStackEntry *i;
    char cDiv = '[';
    fprintf(yyTraceFILE,"%sReturn. Stack=",yyTracePrompt);
    for(i=&yypParser->yystack[1]; i<=yypParser->yytos; i++){
      fprintf(yyTraceFILE,"%c%s", cDiv, yyTokenName[i->major]);
      cDiv = ' ';
    }
    fprintf(yyTraceFILE,"]\n");
  }
#endif
  return;
}

int UA_EventFilterParseFallback(int iToken){
#ifdef YYFALLBACK
  assert( iToken<(int)(sizeof(yyFallback)/sizeof(yyFallback[0])) );
  return yyFallback[iToken];
#else
  (void)iToken;
  return 0;
#endif
}



UA_StatusCode
UA_EventFilter_parse(UA_EventFilter *filter, UA_ByteString content,
                     UA_EventFilterParserOptions *options) {
    yyParser parser;
    UA_EventFilterParseInit(&parser);

    EFParseContext ctx;
    memset(&ctx, 0, sizeof(EFParseContext));
    TAILQ_INIT(&ctx.select_operands);
    ctx.logger = (options) ? options->logger : NULL;

    size_t pos = 0;
    unsigned line = 0, col = 0;
    Operand *token = NULL;
    int tokenId = 0;
    UA_StatusCode res;
    do {
        
        res = UA_EventFilter_skip(content, &pos, &ctx);
        if(res != UA_STATUSCODE_GOOD)
            goto done;

        
        size_t begin = pos;
        tokenId = UA_EventFilter_lex(content, &pos, &ctx, &token);
        UA_EventFilterParse(&parser, tokenId, token, &ctx);

        
        if(ctx.error != UA_STATUSCODE_GOOD) {
            pos2lines(content, begin, &line, &col);
            int extractLen = 10;
            if(pos - begin < 10)
                extractLen = (int)(pos - begin);
            UA_LOG_ERROR(ctx.logger, UA_LOGCATEGORY_USERLAND,
                         "Could not process token at line %u, column %u: "
                         "%.*s...", line, col, extractLen, content.data + begin);
            res = UA_STATUSCODE_BADINTERNALERROR;
            goto done;
        }
    } while(tokenId);

    
    res = UA_EventFilter_skip(content, &pos, &ctx);
    if(res != UA_STATUSCODE_GOOD)
        goto done;

    if(pos < content.length) {
        pos2lines(content, pos, &line, &col);
        UA_LOG_ERROR(ctx.logger, UA_LOGCATEGORY_USERLAND,
                     "Token after the end of the EventFilter expression "
                     "at line %u, column %u", line, col);
        res = UA_STATUSCODE_BADINTERNALERROR;
        goto done;
    }

    
    UA_EventFilter_init(filter);
    res = create_filter(&ctx, filter);

 done:
    UA_EventFilterParseFinalize(&parser);
    EFParseContext_clear(&ctx);
    return res;
}
