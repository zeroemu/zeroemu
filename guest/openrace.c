// Freestanding arm64: N threads race openat(O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0644)
// on a file that does not exist yet (flags = SQLite's unixOpen for a main db).
// On Linux this can never return EEXIST: O_CREAT without O_EXCL is atomic open-or-create.
typedef unsigned long u64; typedef long i64;
#define NR_futex 98
#define NR_mmap 222
#define NR_write 64
#define NR_exit_group 94
#define NR_clone 220
#define NR_openat 56
#define NR_close 57
#define NR_unlinkat 35
static i64 sys6(i64 n,i64 a,i64 b,i64 c,i64 d,i64 e,i64 f){
 register i64 x8 __asm__("x8")=n,x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
 __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define sys(...) sys6_(__VA_ARGS__,0,0,0,0,0,0)
#define sys6_(n,a,b,c,d,e,f,...) sys6(n,(i64)(a),(i64)(b),(i64)(c),(i64)(d),(i64)(e),(i64)(f))
void *memset(void *d,int c,u64 n){char*p=d;while(n--)*p++=(char)c;return d;}
static u64 slen(const char*s){u64 n=0;while(s[n])n++;return n;}
static void puts_(const char*s){sys(NR_write,1,s,slen(s));}
static void putn(long v){char b[24];int i=23;b[i]=0;if(v==0)b[--i]='0';int neg=v<0;if(neg)v=-v;while(v){b[--i]='0'+v%10;v/=10;}if(neg)b[--i]='-';puts_(b+i);}
#define CLONE_THREAD_FLAGS (0x100|0x200|0x400|0x800|0x10000|0x40000|0x200000)
static i64 spawn(void*st,void(*fn)(void*),void*arg,int*ctid){
 register i64 x0 __asm__("x0")=CLONE_THREAD_FLAGS,x1 __asm__("x1")=(i64)st,x2 __asm__("x2")=0,x3 __asm__("x3")=0,x4 __asm__("x4")=(i64)ctid,x8 __asm__("x8")=NR_clone;
 register void*x19 __asm__("x19")=(void*)fn; register void*x20 __asm__("x20")=arg;
 __asm__ volatile("svc #0\ncbnz x0,1f\nmov x0,x20\nblr x19\nmov x0,#0\nmov x8,#93\nsvc #0\n1:\n":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x8),"r"(x19),"r"(x20):"memory","x30");
 return x0;}
static void join(volatile int*c){while(*c!=0)sys(NR_futex,c,0,*c,0);}
#define NT 4
#define ROUNDS 20000
#define STACK 65536
#define O_FLAGS (02|0100|0400000|02000000) /* O_RDWR|O_CREAT|O_NOFOLLOW(aarch64=0100000)... set below */
static const char *PATH="/data/local/tmp/persistent.sqlite";
static volatile int round_no, ready, finished;
static volatile long eexist_total, ok_total, other_total, last_other;
static int tids[NT];
static void worker(void*arg){
 (void)arg;
 // aarch64 asm-generic overrides: O_NOFOLLOW=0100000, O_DIRECTORY=040000; O_CLOEXEC=02000000; O_LARGEFILE=0400000
 long fl=02|0100|0100000|0400000|02000000;
 for(int r=1;r<=ROUNDS;r++){
  __atomic_fetch_add(&ready,1,__ATOMIC_SEQ_CST);
  while(__atomic_load_n(&round_no,__ATOMIC_ACQUIRE)<r){}
  long fd=sys(NR_openat,-100,PATH,fl,0644);
  if(fd>=0){__atomic_fetch_add(&ok_total,1,__ATOMIC_SEQ_CST);sys(NR_close,fd);}
  else if(fd==-17)__atomic_fetch_add(&eexist_total,1,__ATOMIC_SEQ_CST);
  else {__atomic_fetch_add(&other_total,1,__ATOMIC_SEQ_CST);last_other=fd;}
  __atomic_fetch_add(&finished,1,__ATOMIC_SEQ_CST);
 }
}
int cmain(void){
 char*st=(char*)sys(NR_mmap,0,(u64)STACK*NT,3,0x22,-1,0);
 for(int i=0;i<NT;i++){tids[i]=1;spawn(st+(u64)STACK*(i+1),worker,0,&tids[i]);}
 for(int r=1;r<=ROUNDS;r++){
  while(__atomic_load_n(&ready,__ATOMIC_ACQUIRE)<NT*r){}
  sys(NR_unlinkat,-100,PATH,0);
  __atomic_store_n(&round_no,r,__ATOMIC_RELEASE);
  while(__atomic_load_n(&finished,__ATOMIC_ACQUIRE)<NT*r){}
 }
 for(int i=0;i<NT;i++)join(&tids[i]);
 puts_("rounds=");putn(ROUNDS);puts_(" threads=");putn(NT);
 puts_(" ok=");putn(ok_total);puts_(" EEXIST=");putn(eexist_total);puts_(" other=");putn(other_total);puts_(" lastother=");putn(last_other);puts_("\n");
 puts_(eexist_total||other_total?"SOME CHECKS FAILED\n":"all checks passed\n");
 return eexist_total?1:0;
}
void __attribute__((noreturn)) cstart(void){sys(NR_exit_group,cmain());__builtin_unreachable();}
__asm__(".global _start\n_start:\n bl cstart\n");
