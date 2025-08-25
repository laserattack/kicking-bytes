" Vim syntax file
" Language:	Flat Assembler (FASM)
" Maintainer:	Ron Aaron <ron@ronware.org>
" Last Change:	2019/07/31
" Vim URL:	http://www.vim.org/lang.html
" FASM Home:	http://flatassembler.net/
" FASM Version: 1.73

" quit when a syntax file was already loaded
if exists("b:current_syntax")
  finish
endif

let s:cpo_save = &cpo
set cpo&vim

setlocal iskeyword=a-z,A-Z,48-57,.,_
setlocal isident=a-z,A-Z,48-57,.,_
syn case ignore

syn keyword fasmPreprocess 	define equ fix include irp irps irpv macro match
syn keyword fasmPreprocess 	postpone purge rept restore restruc struc
syn keyword fasmMacro		common forward local reverse
syn keyword fasmOperator	and mod or shl shr xor bsf bsr not plt rva align
syn keyword fasmOperator	as at defined dup eq eqtype from in on ptr
syn keyword fasmOperator	relativeto used
syn keyword fasmDirective 	align binary code coff console discardable
syn keyword fasmDirective	display dll dynamic efiboot efiruntime elf entry
syn keyword fasmDirective	executable export extern far fixups format
syn keyword fasmDirective	gnuehframe gnurelro gnustack gui import
syn keyword fasmDirective	interpreter label linkinfo linkremove ms mz
syn keyword fasmDirective	native near notpageable pe public readable
syn keyword fasmDirective	repeat resource section segment shareable stack
syn keyword fasmDirective	static times use16 use32 use64 virtual wdm
syn keyword fasmDirective	writable writeable

syn keyword fasmRegister	ah al bh bl ch cl dh dl spl bpl sil dil
syn keyword fasmRegister	r8b r9b r10b r11b r12b r13b r14b r15b
syn keyword fasmRegister	ax bx cx dx ip sp bp si di
syn keyword fasmRegister	r8w r9w r10w r11w r12w r13w r14w r15w
syn keyword fasmRegister	eax ebx ecx edx esp ebp esi edi eip
syn keyword fasmRegister	r8d r9d r10d r11d r12d r13d r14d r15d
syn keyword fasmRegister	es cs ss ds fs gs
syn keyword fasmRegister	rax rbx rcx rdx rsi rdi rsp rbp
syn keyword fasmRegister	r0 r1 r2 r3 r4 r5 r6 r7
syn keyword fasmRegister	r8 r9 r10 r11 r12 r13 r14 r15
syn keyword fasmRegister	cr0 cr1 cr2 cr3 cr4 cr5 cr6 cr7
syn keyword fasmRegister	dr0 dr1 dr2 dr3 dr4 dr5 dr6 dr7
syn keyword fasmRegister	mm0 mm1 mm2 mm3 mm4 mm5 mm6 mm7
syn keyword fasmRegister	st0 st1 st2 st3 st4 st5 st6 st7
syn keyword fasmRegister	tr0 tr2 tr1 tr3 tr4 tr5 tr6 tr7 
syn keyword fasmRegister	bnd0 bnd1 bnd2 bnd3
syn keyword fasmRegister	xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7
syn keyword fasmRegister	xmm8 xmm9 xmm10 xmm11 xmm12 xmm13 xmm14 xmm15
syn keyword fasmRegister	xmm16 xmm17 xmm18 xmm19 xmm20 xmm21 xmm22 xmm23
syn keyword fasmRegister	xmm24 xmm25 xmm26 xmm27 xmm28 xmm29 xmm30 xmm31
syn keyword fasmRegister	ymm0 ymm1 ymm2 ymm3 ymm4 ymm5 ymm6 ymm7
syn keyword fasmRegister	ymm8 ymm9 ymm10 ymm11 ymm12 ymm13 ymm14 ymm15
syn keyword fasmRegister	ymm16 ymm17 ymm18 ymm19 ymm20 ymm21 ymm22 ymm23
syn keyword fasmRegister	ymm24 ymm25 ymm26 ymm27 ymm28 ymm29 ymm30 ymm31
syn keyword fasmRegister	zmm0 zmm1 zmm2 zmm3 zmm4 zmm5 zmm6 zmm7
syn keyword fasmRegister	zmm8 zmm9 zmm10 zmm11 zmm12 zmm13 zmm14 zmm15
syn keyword fasmRegister	zmm16 zmm17 zmm18 zmm19 zmm20 zmm21 zmm22 zmm23
syn keyword fasmRegister	zmm24 zmm25 zmm26 zmm27 zmm28 zmm29 zmm30 zmm31
syn keyword fasmRegister	k0 k1 k2 k3 k4 k5 k6 k7

syn keyword fasmAddressSizes 	byte word dword fword pword qword tbyte tword
syn keyword fasmAddressSizes 	dqword xword qqword yword dqqword zword

syn keyword fasmDataDirectives 	db dd df dp dq dt du dw rb rd rf rp rq rt rw
syn keyword fasmDataDirectives 	file

syn keyword fasmInstr	bt if in ja jb jc je jg jl jo jp js jz or aaa aad aam
syn keyword fasmInstr	aas adc add and bnd bsf bsr btc btr bts cbw cdq clc cld
syn keyword fasmInstr	cli cmc cmp cqo cwd daa das dec div end err fld fst hlt
syn keyword fasmInstr	inc ins int jae jbe jge jle jmp jna jnb jnc jne jng jnl
syn keyword fasmInstr	jno jnp jns jnz jpe jpo lar lds lea les lfs lgs lsl lss
syn keyword fasmInstr	ltr mov mul neg nop not org out pop por rcl rcr rep ret
syn keyword fasmInstr	rol ror rsm sal sar sbb shl shr stc std sti str sub ud0
syn keyword fasmInstr	ud1 ud2 xor adcx adox andn arpl blci blcs blsi blsr bzhi
syn keyword fasmInstr	call cdqe clac clgi clts clwb cmps cwde data dppd dpps
syn keyword fasmInstr	emms fabs fadd fbld fchs fcom fcos fdiv feni fild fist
syn keyword fasmInstr	fld1 fldz fmul fnop fsin fstp fsub ftst fxam fxch heap
syn keyword fasmInstr	idiv imul insb insd insw int1 int3 into invd iret jcxz
syn keyword fasmInstr	jnae jnbe jnge jnle korb kord korq korw lahf lgdt lidt
syn keyword fasmInstr	lldt lmsw load lock lods loop movd movq movs mulx orpd
syn keyword fasmInstr	orps outs pand pdep pext popa popd popf popq popw push
syn keyword fasmInstr	pxor repe repz retd retf retn retq retw rorx sahf salc
syn keyword fasmInstr	sarx scas seta setb setc sete setg setl seto setp sets
syn keyword fasmInstr	setz sgdt shld shlx shrd shrx sidt sldt smsw stac stgi
syn keyword fasmInstr	stos test verr verw vpor wait xadd xchg xend xlat addpd
syn keyword fasmInstr	addps addsd addss align andpd andps bextr blcic blsic
syn keyword fasmInstr	bndcl bndcn bndcu bndmk bound break bswap cmova cmovb
syn keyword fasmInstr	cmovc cmove cmovg cmovl cmovo cmovp cmovs cmovz cmppd
syn keyword fasmInstr	cmpps cmpsb cmpsd cmpsq cmpss cmpsw cpuid crc32 divpd
syn keyword fasmInstr	divps divsd divss enter entry extrn extrq f2xm1 faddp
syn keyword fasmInstr	fbstp fclex fcomi fcomp fdisi fdivp fdivr femms ffree
syn keyword fasmInstr	fiadd ficom fidiv fimul finit fistp fisub fldcw fldpi
syn keyword fasmInstr	fmulp fneni fprem fptan fsave fsqrt fstcw fstsw fsubp
syn keyword fasmInstr	fsubr fucom fwait fyl2x icebp iretd iretq iretw jecxz
syn keyword fasmInstr	jrcxz kaddb kaddd kaddq kaddw kandb kandd kandq kandw
syn keyword fasmInstr	kmovb kmovd kmovq kmovw knotb knotd knotq knotw kxorb
syn keyword fasmInstr	kxord kxorq kxorw label lddqu leave lodsb lodsd lodsq
syn keyword fasmInstr	lodsw loopd loope loopq loopw loopz lzcnt maxpd maxps
syn keyword fasmInstr	maxsd maxss minpd minps minsd minss movbe movsb movsd
syn keyword fasmInstr	movsq movss movsw movsx movzx mulpd mulps mulsd mulss
syn keyword fasmInstr	mwait outsb outsd outsw pabsb pabsd pabsw paddb paddd
syn keyword fasmInstr	paddq paddw pandn pause pavgb pavgw pf2id pf2iw pfacc
syn keyword fasmInstr	pfadd pfmax pfmin pfmul pfrcp pfsub pi2fd pi2fw popad
syn keyword fasmInstr	popaw popfd popfq popfw pslld psllq psllw psrad psraw
syn keyword fasmInstr	psrld psrlq psrlw psubb psubd psubq psubw ptest pusha
syn keyword fasmInstr	pushd pushf pushq pushw rcpps rcpss rdmsr rdpid rdpmc
syn keyword fasmInstr	rdtsc repne repnz retfd retfq retfw retnd retnq retnw
syn keyword fasmInstr	scasb scasd scasq scasw setae setbe setge setle setna
syn keyword fasmInstr	setnb setnc setne setng setnl setno setnp setns setnz
syn keyword fasmInstr	setpe setpo stack store stosb stosd stosq stosw subpd
syn keyword fasmInstr	subps subsd subss times tzcnt tzmsk vdppd vdpps vmovd
syn keyword fasmInstr	vmovq vmrun vmxon vorpd vorps vpand vpord vporq vpxor
syn keyword fasmInstr	while wrmsr xlatb xorpd xorps xsave xtest aesdec aesenc
syn keyword fasmInstr	aesimc andnpd andnps assert blcmsk blsmsk bndldx bndmov
syn keyword fasmInstr	bndstx clzero cmovae cmovbe cmovge cmovle cmovna cmovnb
syn keyword fasmInstr	cmovnc cmovne cmovng cmovnl cmovno cmovnp cmovns cmovnz
syn keyword fasmInstr	cmovpe cmovpo comisd comiss fcmovb fcmove fcmovu fcomip
syn keyword fasmInstr	fcompp fdivrp ffreep ficomp fidivr fisttp fisubr fldenv
syn keyword fasmInstr	fldl2e fldl2t fldlg2 fldln2 fnclex fndisi fninit fnsave
syn keyword fasmInstr	fnstcw fnstsw format fpatan fprem1 frstor frstpm fsaved
syn keyword fasmInstr	fsavew fscale fsetpm fstenv fsubrp fucomi fucomp fxsave
syn keyword fasmInstr	getsec haddpd haddps hsubpd hsubps invept invlpg kandnb
syn keyword fasmInstr	kandnd kandnq kandnw ktestb ktestd ktestq ktestw kxnorb
syn keyword fasmInstr	kxnord kxnorq kxnorw lfence llwpcb looped loopeq loopew
syn keyword fasmInstr	loopne loopnz loopzd loopzq loopzw lwpins lwpval mfence
syn keyword fasmInstr	movapd movaps movdqa movdqu movhpd movhps movlpd movlps
syn keyword fasmInstr	movnti movntq movsxd movupd movups mwaitx paddsb paddsw
syn keyword fasmInstr	pextrb pextrd pextrq pextrw pfnacc pfsubr phaddd phaddw
syn keyword fasmInstr	phsubd phsubw pinsrb pinsrd pinsrq pinsrw pmaxsb pmaxsd
syn keyword fasmInstr	pmaxsw pmaxub pmaxud pmaxuw pminsb pminsd pminsw pminub
syn keyword fasmInstr	pminud pminuw pmuldq pmulhw pmulld pmullw popcnt psadbw
syn keyword fasmInstr	pshufb pshufd pshufw psignb psignd psignw pslldq psrldq
syn keyword fasmInstr	psubsb psubsw pswapd public pushad pushaw pushfd pushfq
syn keyword fasmInstr	pushfw rdmsrq rdpkru rdrand rdseed rdtscp repeat setalc
syn keyword fasmInstr	setnae setnbe setnge setnle sfence shufpd shufps skinit
syn keyword fasmInstr	slwpcb sqrtpd sqrtps sqrtsd sqrtss swapgs sysret t1mskc
syn keyword fasmInstr	vaddpd vaddps vaddsd vaddss vandpd vandps vcmppd vcmpps
syn keyword fasmInstr	vcmpsd vcmpss vdivpd vdivps vdivsd vdivss vlddqu vmaxpd
syn keyword fasmInstr	vmaxps vmaxsd vmaxss vmcall vmfunc vminpd vminps vminsd
syn keyword fasmInstr	vminss vmload vmovsd vmovss vmread vmsave vmulpd vmulps
syn keyword fasmInstr	vmulsd vmulss vmxoff vpabsb vpabsd vpabsq vpabsw vpaddb
syn keyword fasmInstr	vpaddd vpaddq vpaddw vpandd vpandn vpandq vpavgb vpavgw
syn keyword fasmInstr	vpcmov vpcmpb vpcmpd vpcmpq vpcmpw vpcomb vpcomd vpcomq
syn keyword fasmInstr	vpcomw vpermb vpermd vpermq vpermw vpperm vprold vprolq
syn keyword fasmInstr	vprord vprorq vprotb vprotd vprotq vprotw vpshab vpshad
syn keyword fasmInstr	vpshaq vpshaw vpshlb vpshld vpshlq vpshlw vpslld vpsllq
syn keyword fasmInstr	vpsllw vpsrad vpsraq vpsraw vpsrld vpsrlq vpsrlw vpsubb
syn keyword fasmInstr	vpsubd vpsubq vpsubw vptest vpxord vpxorq vrcpps vrcpss
syn keyword fasmInstr	vsubpd vsubps vsubsd vsubss vxorpd vxorps wbinvd wrmsrq
syn keyword fasmInstr	wrpkru xabort xbegin xgetbv xrstor xsavec xsaves xsetbv
syn keyword fasmInstr	blcfill blendpd blendps blsfill clflush cmovnae cmovnbe
syn keyword fasmInstr	cmovnge cmovnle cmpeqpd cmpeqps cmpeqsd cmpeqss cmplepd
syn keyword fasmInstr	cmpleps cmplesd cmpless cmpltpd cmpltps cmpltsd cmpltss
syn keyword fasmInstr	cmpxchg display fcmovbe fcmovnb fcmovne fcmovnu fdecstp
syn keyword fasmInstr	fincstp fldenvd fldenvw fnsaved fnsavew fnstenv frndint
syn keyword fasmInstr	frstord frstorw fsincos fstenvd fstenvw fucomip fucompp
syn keyword fasmInstr	fxrstor fxtract fyl2xp1 insertq invlpga invpcid invvpid
syn keyword fasmInstr	ldmxcsr loopned loopneq loopnew loopnzd loopnzq loopnzw
syn keyword fasmInstr	monitor movddup movdq2q movhlps movlhps movntdq movntpd
syn keyword fasmInstr	movntps movntsd movntss movq2dq mpsadbw paddusb paddusw
syn keyword fasmInstr	palignr pavgusb pblendw pcmpeqb pcmpeqd pcmpeqq pcmpeqw
syn keyword fasmInstr	pcmpgtb pcmpgtd pcmpgtq pcmpgtw pcommit pfcmpeq pfcmpge
syn keyword fasmInstr	pfcmpgt pfpnacc pfrsqrt phaddsw phsubsw pmaddwd pmulhrw
syn keyword fasmInstr	pmulhuw pmuludq pshufhw pshuflw psubusb psubusw roundpd
syn keyword fasmInstr	roundps roundsd roundss rsqrtps rsqrtss section segment
syn keyword fasmInstr	stmxcsr syscall sysexit sysretq ucomisd ucomiss vaesdec
syn keyword fasmInstr	vaesenc vaesimc valignd valignq vandnpd vandnps vcomisd
syn keyword fasmInstr	vcomiss vexp2pd vexp2ps vfrczpd vfrczps vfrczsd vfrczss
syn keyword fasmInstr	vhaddpd vhaddps vhsubpd vhsubps virtual vmclear vmmcall
syn keyword fasmInstr	vmovapd vmovaps vmovdqa vmovdqu vmovhpd vmovhps vmovlpd
syn keyword fasmInstr	vmovlps vmovupd vmovups vmptrld vmptrst vmwrite vpaddsb
syn keyword fasmInstr	vpaddsw vpandnd vpandnq vpcmpub vpcmpud vpcmpuq vpcmpuw
syn keyword fasmInstr	vpcomub vpcomud vpcomuq vpcomuw vpermpd vpermps vpextrb
syn keyword fasmInstr	vpextrd vpextrq vpextrw vphaddd vphaddw vphsubd vphsubw
syn keyword fasmInstr	vpinsrb vpinsrd vpinsrq vpinsrw vpmaxsb vpmaxsd vpmaxsq
syn keyword fasmInstr	vpmaxsw vpmaxub vpmaxud vpmaxuq vpmaxuw vpminsb vpminsd
syn keyword fasmInstr	vpminsq vpminsw vpminub vpminud vpminuq vpminuw vpmovdb
syn keyword fasmInstr	vpmovdw vpmovqb vpmovqd vpmovqw vpmovwb vpmuldq vpmulhw
syn keyword fasmInstr	vpmulld vpmullq vpmullw vprolvd vprolvq vprorvd vprorvq
syn keyword fasmInstr	vpsadbw vpshufb vpshufd vpsignb vpsignd vpsignw vpslldq
syn keyword fasmInstr	vpsllvd vpsllvq vpsllvw vpsravd vpsravq vpsravw vpsrldq
syn keyword fasmInstr	vpsrlvd vpsrlvq vpsrlvw vpsubsb vpsubsw vshufpd vshufps
syn keyword fasmInstr	vsqrtpd vsqrtps vsqrtsd vsqrtss vtestpd vtestps xrstors
syn keyword fasmInstr	xsave64 addsubpd addsubps blendvpd blendvps cmpneqpd
syn keyword fasmInstr	cmpneqps cmpneqsd cmpneqss cmpnlepd cmpnleps cmpnlesd
syn keyword fasmInstr	cmpnless cmpnltpd cmpnltps cmpnltsd cmpnltss cmpordpd
syn keyword fasmInstr	cmpordps cmpordsd cmpordss cvtdq2pd cvtdq2ps cvtpd2dq
syn keyword fasmInstr	cvtpd2pi cvtpd2ps cvtpi2pd cvtpi2ps cvtps2dq cvtps2pd
syn keyword fasmInstr	cvtps2pi cvtsd2si cvtsd2ss cvtsi2sd cvtsi2ss cvtss2sd
syn keyword fasmInstr	cvtss2si fcmovnbe fnstenvd fnstenvw fxsave64 insertps
syn keyword fasmInstr	kortestb kortestd kortestq kortestw kshiftlb kshiftld
syn keyword fasmInstr	kshiftlq kshiftlw kshiftrb kshiftrd kshiftrq kshiftrw
syn keyword fasmInstr	kunpckbw kunpckdq kunpckwd maskmovq monitorx movmskpd
syn keyword fasmInstr	movmskps movntdqa movshdup movsldup packssdw packsswb
syn keyword fasmInstr	packusdw packuswb pblendvb pfrcpit1 pfrcpit2 pfrsqit1
syn keyword fasmInstr	pmovmskb pmovsxbd pmovsxbq pmovsxbw pmovsxdq pmovsxwd
syn keyword fasmInstr	pmovsxwq pmovzxbd pmovzxbq pmovzxbw pmovzxdq pmovzxwd
syn keyword fasmInstr	pmovzxwq pmulhrsw prefetch rdfsbase rdgsbase sha1msg1
syn keyword fasmInstr	sha1msg2 sysenter sysexitq unpckhpd unpckhps unpcklpd
syn keyword fasmInstr	unpcklps vblendpd vblendps vcmpeqpd vcmpeqps vcmpeqsd
syn keyword fasmInstr	vcmpeqss vcmpgepd vcmpgeps vcmpgesd vcmpgess vcmpgtpd
syn keyword fasmInstr	vcmpgtps vcmpgtsd vcmpgtss vcmplepd vcmpleps vcmplesd
syn keyword fasmInstr	vcmpless vcmpltpd vcmpltps vcmpltsd vcmpltss vfmaddpd
syn keyword fasmInstr	vfmaddps vfmaddsd vfmaddss vfmsubpd vfmsubps vfmsubsd
syn keyword fasmInstr	vfmsubss vldmxcsr vmlaunch vmovddup vmovdqu8 vmovhlps
syn keyword fasmInstr	vmovlhps vmovntdq vmovntpd vmovntps vmpsadbw vmresume
syn keyword fasmInstr	vpaddusb vpaddusw vpalignr vpblendd vpblendw vpcmpeqb
syn keyword fasmInstr	vpcmpeqd vpcmpeqq vpcmpeqw vpcmpgtb vpcmpgtd vpcmpgtq
syn keyword fasmInstr	vpcmpgtw vpcmpleb vpcmpled vpcmpleq vpcmplew vpcmpltb
syn keyword fasmInstr	vpcmpltd vpcmpltq vpcmpltw vpcomeqb vpcomeqd vpcomeqq
syn keyword fasmInstr	vpcomeqw vpcomgeb vpcomged vpcomgeq vpcomgew vpcomgtb
syn keyword fasmInstr	vpcomgtd vpcomgtq vpcomgtw vpcomleb vpcomled vpcomleq
syn keyword fasmInstr	vpcomlew vpcomltb vpcomltd vpcomltq vpcomltw vpermi2b
syn keyword fasmInstr	vpermi2d vpermi2q vpermi2w vpermt2b vpermt2d vpermt2q
syn keyword fasmInstr	vpermt2w vphaddbd vphaddbq vphaddbw vphadddq vphaddsw
syn keyword fasmInstr	vphaddwd vphaddwq vphsubbw vphsubdq vphsubsw vphsubwd
syn keyword fasmInstr	vplzcntd vplzcntq vpmacsdd vpmacswd vpmacsww vpmaddwd
syn keyword fasmInstr	vpmovb2m vpmovd2m vpmovm2b vpmovm2d vpmovm2q vpmovm2w
syn keyword fasmInstr	vpmovq2m vpmovsdb vpmovsdw vpmovsqb vpmovsqd vpmovsqw
syn keyword fasmInstr	vpmovswb vpmovw2m vpmulhuw vpmuludq vpshufhw vpshuflw
syn keyword fasmInstr	vpsubusb vpsubusw vptestmb vptestmd vptestmq vptestmw
syn keyword fasmInstr	vrangepd vrangeps vrangesd vrangess vrcp14pd vrcp14ps
syn keyword fasmInstr	vrcp14sd vrcp14ss vrcp28pd vrcp28ps vrcp28sd vrcp28ss
syn keyword fasmInstr	vroundpd vroundps vroundsd vroundss vrsqrtps vrsqrtss
syn keyword fasmInstr	vstmxcsr vucomisd vucomiss vzeroall wrfsbase wrgsbase
syn keyword fasmInstr	xacquire xrelease xrstor64 xsavec64 xsaveopt xsaves64
syn keyword fasmInstr	cmpxchg8b cvttpd2dq cvttpd2pi cvttps2dq cvttps2pi
syn keyword fasmInstr	cvttsd2si cvttss2si extractps fxrstor64 pclmulqdq
syn keyword fasmInstr	pcmpestri pcmpestrm pcmpistri pcmpistrm pmaddubsw
syn keyword fasmInstr	prefetchw punpckhbw punpckhdq punpckhwd punpcklbw
syn keyword fasmInstr	punpckldq punpcklwd sha1nexte sha1rnds4 useavx256
syn keyword fasmInstr	useavx512 vaddsubpd vaddsubps vblendmpd vblendmps
syn keyword fasmInstr	vblendvpd vblendvps vcmpneqpd vcmpneqps vcmpneqsd
syn keyword fasmInstr	vcmpneqss vcmpngepd vcmpngeps vcmpngesd vcmpngess
syn keyword fasmInstr	vcmpngtpd vcmpngtps vcmpngtsd vcmpngtss vcmpnlepd
syn keyword fasmInstr	vcmpnleps vcmpnlesd vcmpnless vcmpnltpd vcmpnltps
syn keyword fasmInstr	vcmpnltsd vcmpnltss vcmpordpd vcmpordps vcmpordsd
syn keyword fasmInstr	vcmpordss vcvtdq2pd vcvtdq2ps vcvtpd2dq vcvtpd2ps
syn keyword fasmInstr	vcvtpd2qq vcvtph2ps vcvtps2dq vcvtps2pd vcvtps2ph
syn keyword fasmInstr	vcvtps2qq vcvtqq2pd vcvtqq2ps vcvtsd2si vcvtsd2ss
syn keyword fasmInstr	vcvtsi2sd vcvtsi2ss vcvtss2sd vcvtss2si vdbpsadbw
syn keyword fasmInstr	vexpandpd vexpandps vfnmaddpd vfnmaddps vfnmaddsd
syn keyword fasmInstr	vfnmaddss vfnmsubpd vfnmsubps vfnmsubsd vfnmsubss
syn keyword fasmInstr	vgetexppd vgetexpps vgetexpsd vgetexpss vinsertps
syn keyword fasmInstr	vmovdqa32 vmovdqa64 vmovdqu16 vmovdqu32 vmovdqu64
syn keyword fasmInstr	vmovmskpd vmovmskps vmovntdqa vmovshdup vmovsldup
syn keyword fasmInstr	vpackssdw vpacksswb vpackusdw vpackuswb vpblendmb
syn keyword fasmInstr	vpblendmd vpblendmq vpblendmw vpblendvb vpcmpleub
syn keyword fasmInstr	vpcmpleud vpcmpleuq vpcmpleuw vpcmpltub vpcmpltud
syn keyword fasmInstr	vpcmpltuq vpcmpltuw vpcmpneqb vpcmpneqd vpcmpneqq
syn keyword fasmInstr	vpcmpneqw vpcmpnleb vpcmpnled vpcmpnleq vpcmpnlew
syn keyword fasmInstr	vpcmpnltb vpcmpnltd vpcmpnltq vpcmpnltw vpcomequb
syn keyword fasmInstr	vpcomequd vpcomequq vpcomequw vpcomgeub vpcomgeud
syn keyword fasmInstr	vpcomgeuq vpcomgeuw vpcomgtub vpcomgtud vpcomgtuq
syn keyword fasmInstr	vpcomgtuw vpcomleub vpcomleud vpcomleuq vpcomleuw
syn keyword fasmInstr	vpcomltub vpcomltud vpcomltuq vpcomltuw vpcomneqb
syn keyword fasmInstr	vpcomneqd vpcomneqq vpcomneqw vpermi2pd vpermi2ps
syn keyword fasmInstr	vpermilpd vpermilps vpermt2pd vpermt2ps vpexpandd
syn keyword fasmInstr	vpexpandq vphaddubd vphaddubq vphaddubw vphaddudq
syn keyword fasmInstr	vphadduwd vphadduwq vpmacsdqh vpmacsdql vpmacssdd
syn keyword fasmInstr	vpmacsswd vpmacssww vpmadcswd vpmovmskb vpmovsxbd
syn keyword fasmInstr	vpmovsxbq vpmovsxbw vpmovsxdq vpmovsxwd vpmovsxwq
syn keyword fasmInstr	vpmovusdb vpmovusdw vpmovusqb vpmovusqd vpmovusqw
syn keyword fasmInstr	vpmovuswb vpmovzxbd vpmovzxbq vpmovzxbw vpmovzxdq
syn keyword fasmInstr	vpmovzxwd vpmovzxwq vpmulhrsw vptestnmb vptestnmd
syn keyword fasmInstr	vptestnmq vptestnmw vreducepd vreduceps vreducesd
syn keyword fasmInstr	vreducess vscalefpd vscalefps vscalefsd vscalefss
syn keyword fasmInstr	vunpckhpd vunpckhps vunpcklpd vunpcklps xrstors64
syn keyword fasmInstr	aesdeclast aesenclast clflushopt cmpunordpd cmpunordps
syn keyword fasmInstr	cmpunordsd cmpunordss cmpxchg16b loadall286 loadall386
syn keyword fasmInstr	maskmovdqu phminposuw prefetcht0 prefetcht1 prefetcht2
syn keyword fasmInstr	punpckhqdq punpcklqdq sha256msg1 sha256msg2 vcmptruepd
syn keyword fasmInstr	vcmptrueps vcmptruesd vcmptruess vcvtpd2udq vcvtpd2uqq
syn keyword fasmInstr	vcvtps2udq vcvtps2uqq vcvtsd2usi vcvtss2usi vcvttpd2dq
syn keyword fasmInstr	vcvttpd2qq vcvttps2dq vcvttps2qq vcvttsd2si vcvttss2si
syn keyword fasmInstr	vcvtudq2pd vcvtudq2ps vcvtuqq2pd vcvtuqq2ps vcvtusi2sd
syn keyword fasmInstr	vcvtusi2ss vextractps vfpclasspd vfpclassps vfpclasssd
syn keyword fasmInstr	vfpclassss vgatherdpd vgatherdps vgatherqpd vgatherqps
syn keyword fasmInstr	vgetmantpd vgetmantps vgetmantsd vgetmantss vmaskmovpd
syn keyword fasmInstr	vmaskmovps vpclmulqdq vpcmpestri vpcmpestrm vpcmpistri
syn keyword fasmInstr	vpcmpistrm vpcmpnequb vpcmpnequd vpcmpnequq vpcmpnequw
syn keyword fasmInstr	vpcmpnleub vpcmpnleud vpcmpnleuq vpcmpnleuw vpcmpnltub
syn keyword fasmInstr	vpcmpnltud vpcmpnltuq vpcmpnltuw vpcomnequb vpcomnequd
syn keyword fasmInstr	vpcomnequq vpcomnequw vpcomtrueb vpcomtrued vpcomtrueq
syn keyword fasmInstr	vpcomtruew vperm2f128 vperm2i128 vpermil2pd vpermil2ps
syn keyword fasmInstr	vpgatherdd vpgatherdq vpgatherqd vpgatherqq vpmacssdqh
syn keyword fasmInstr	vpmacssdql vpmadcsswd vpmaddubsw vpmaskmovd vpmaskmovq
syn keyword fasmInstr	vpternlogd vpternlogq vpunpckhbw vpunpckhdq vpunpckhwd
syn keyword fasmInstr	vpunpcklbw vpunpckldq vpunpcklwd vrsqrt14pd vrsqrt14ps
syn keyword fasmInstr	vrsqrt14sd vrsqrt14ss vrsqrt28pd vrsqrt28ps vrsqrt28sd
syn keyword fasmInstr	vrsqrt28ss vshuff32x4 vshuff64x2 vshufi32x4 vshufi64x2
syn keyword fasmInstr	vzeroupper xsaveopt64 pclmulhqhdq pclmullqhdq
syn keyword fasmInstr	prefetchnta prefetchwt1 sha256rnds2 vaesdeclast
syn keyword fasmInstr	vaesenclast vcmpeq_ospd vcmpeq_osps vcmpeq_ossd
syn keyword fasmInstr	vcmpeq_osss vcmpeq_uqpd vcmpeq_uqps vcmpeq_uqsd
syn keyword fasmInstr	vcmpeq_uqss vcmpeq_uspd vcmpeq_usps vcmpeq_ussd
syn keyword fasmInstr	vcmpeq_usss vcmpfalsepd vcmpfalseps vcmpfalsesd
syn keyword fasmInstr	vcmpfalsess vcmpge_oqpd vcmpge_oqps vcmpge_oqsd
syn keyword fasmInstr	vcmpge_oqss vcmpgt_oqpd vcmpgt_oqps vcmpgt_oqsd
syn keyword fasmInstr	vcmpgt_oqss vcmple_oqpd vcmple_oqps vcmple_oqsd
syn keyword fasmInstr	vcmple_oqss vcmplt_oqpd vcmplt_oqps vcmplt_oqsd
syn keyword fasmInstr	vcmplt_oqss vcmpord_spd vcmpord_sps vcmpord_ssd
syn keyword fasmInstr	vcmpord_sss vcmpunordpd vcmpunordps vcmpunordsd
syn keyword fasmInstr	vcmpunordss vcompresspd vcompressps vcvttpd2udq
syn keyword fasmInstr	vcvttpd2uqq vcvttps2udq vcvttps2uqq vcvttsd2usi
syn keyword fasmInstr	vcvttss2usi vfixupimmpd vfixupimmps vfixupimmsd
syn keyword fasmInstr	vfixupimmss vfmadd132pd vfmadd132ps vfmadd132sd
syn keyword fasmInstr	vfmadd132ss vfmadd213pd vfmadd213ps vfmadd213sd
syn keyword fasmInstr	vfmadd213ss vfmadd231pd vfmadd231ps vfmadd231sd
syn keyword fasmInstr	vfmadd231ss vfmaddsubpd vfmaddsubps vfmsub132pd
syn keyword fasmInstr	vfmsub132ps vfmsub132sd vfmsub132ss vfmsub213pd
syn keyword fasmInstr	vfmsub213ps vfmsub213sd vfmsub213ss vfmsub231pd
syn keyword fasmInstr	vfmsub231ps vfmsub231sd vfmsub231ss vfmsubaddpd
syn keyword fasmInstr	vfmsubaddps vinsertf128 vinserti128 vmaskmovdqu
syn keyword fasmInstr	vpcomfalseb vpcomfalsed vpcomfalseq vpcomfalsew
syn keyword fasmInstr	vpcompressd vpcompressq vpcomtrueub vpcomtrueud
syn keyword fasmInstr	vpcomtrueuq vpcomtrueuw vpconflictd vpconflictq
syn keyword fasmInstr	vphminposuw vpmadd52huq vpmadd52luq vpscatterdd
syn keyword fasmInstr	vpscatterdq vpscatterqd vpscatterqq vpunpckhqdq
syn keyword fasmInstr	vpunpcklqdq vrndscalepd vrndscaleps vrndscalesd
syn keyword fasmInstr	vrndscaless vscatterdpd vscatterdps vscatterqpd
syn keyword fasmInstr	vscatterqps pclmulhqhqdq pclmulhqlqdq pclmullqhqdq
syn keyword fasmInstr	pclmullqlqdq vbroadcastsd vbroadcastss vcmpneq_oqpd
syn keyword fasmInstr	vcmpneq_oqps vcmpneq_oqsd vcmpneq_oqss vcmpneq_ospd
syn keyword fasmInstr	vcmpneq_osps vcmpneq_ossd vcmpneq_osss vcmpneq_uspd
syn keyword fasmInstr	vcmpneq_usps vcmpneq_ussd vcmpneq_usss vcmpnge_uqpd
syn keyword fasmInstr	vcmpnge_uqps vcmpnge_uqsd vcmpnge_uqss vcmpngt_uqpd
syn keyword fasmInstr	vcmpngt_uqps vcmpngt_uqsd vcmpngt_uqss vcmpnle_uqpd
syn keyword fasmInstr	vcmpnle_uqps vcmpnle_uqsd vcmpnle_uqss vcmpnlt_uqpd
syn keyword fasmInstr	vcmpnlt_uqps vcmpnlt_uqsd vcmpnlt_uqss vextractf128
syn keyword fasmInstr	vextracti128 vfnmadd132pd vfnmadd132ps vfnmadd132sd
syn keyword fasmInstr	vfnmadd132ss vfnmadd213pd vfnmadd213ps vfnmadd213sd
syn keyword fasmInstr	vfnmadd213ss vfnmadd231pd vfnmadd231ps vfnmadd231sd
syn keyword fasmInstr	vfnmadd231ss vfnmsub132pd vfnmsub132ps vfnmsub132sd
syn keyword fasmInstr	vfnmsub132ss vfnmsub213pd vfnmsub213ps vfnmsub213sd
syn keyword fasmInstr	vfnmsub213ss vfnmsub231pd vfnmsub231ps vfnmsub231sd
syn keyword fasmInstr	vfnmsub231ss vinsertf32x4 vinsertf32x8 vinsertf64x2
syn keyword fasmInstr	vinsertf64x4 vinserti32x4 vinserti32x8 vinserti64x2
syn keyword fasmInstr	vinserti64x4 vpbroadcastb vpbroadcastd vpbroadcastq
syn keyword fasmInstr	vpbroadcastw vpclmulhqhdq vpclmullqhdq vpcomfalseub
syn keyword fasmInstr	vpcomfalseud vpcomfalseuq vpcomfalseuw vpermilmo2pd
syn keyword fasmInstr	vpermilmo2ps vpermilmz2pd vpermilmz2ps vpermiltd2pd
syn keyword fasmInstr	vpermiltd2ps vcmptrue_uspd vcmptrue_usps vcmptrue_ussd
syn keyword fasmInstr	vcmptrue_usss vcmpunord_spd vcmpunord_sps vcmpunord_ssd
syn keyword fasmInstr	vcmpunord_sss vextractf32x4 vextractf32x8 vextractf64x2
syn keyword fasmInstr	vextractf64x4 vextracti32x4 vextracti32x8 vextracti64x2
syn keyword fasmInstr	vextracti64x4 vgatherpf0dpd vgatherpf0dps vgatherpf0qpd
syn keyword fasmInstr	vgatherpf0qps vgatherpf1dpd vgatherpf1dps vgatherpf1qpd
syn keyword fasmInstr	vgatherpf1qps vpclmulhqlqdq vpclmullqlqdq vbroadcastf128
syn keyword fasmInstr	vbroadcasti128 vcmpfalse_ospd vcmpfalse_osps
syn keyword fasmInstr	vcmpfalse_ossd vcmpfalse_osss vfmaddsub132pd
syn keyword fasmInstr	vfmaddsub132ps vfmaddsub213pd vfmaddsub213ps
syn keyword fasmInstr	vfmaddsub231pd vfmaddsub231ps vfmsubadd132pd
syn keyword fasmInstr	vfmsubadd132ps vfmsubadd213pd vfmsubadd213ps
syn keyword fasmInstr	vfmsubadd231pd vfmsubadd231ps vpmultishiftqb
syn keyword fasmInstr	vscatterpf0dpd vscatterpf0dps vscatterpf0qpd
syn keyword fasmInstr	vscatterpf0qps vscatterpf1dpd vscatterpf1dps
syn keyword fasmInstr	vscatterpf1qpd vscatterpf1qps aeskeygenassist
syn keyword fasmInstr	vbroadcastf32x2 vbroadcastf32x4 vbroadcastf32x8
syn keyword fasmInstr	vbroadcastf64x2 vbroadcastf64x4 vbroadcasti32x2
syn keyword fasmInstr	vbroadcasti32x4 vbroadcasti32x8 vbroadcasti64x2
syn keyword fasmInstr	vbroadcasti64x4 vpbroadcastmb2q vpbroadcastmw2d
syn keyword fasmInstr	vaeskeygenassist

syn match	fasmNumericOperator	"[+-/*]"
syn match	fasmLogicalOperator	"[=|&~<>]\|<=\|>=\|<>"
" numbers
syn match	fasmBinaryNumber	"\<[01][01_]*b\>"
syn match	fasmHexNumber		"\<\d[0-9a-fA-F_]*h\>"
syn match	fasmHexNumber		"\<\(0x\|$\)[0-9a-fA-F_]*\>"
syn match	fasmFPUNumber		"\<\d\+\(\.\d*\)\=\(e[-+]\=\d*\)\=\>"
syn match	fasmOctalNumber		"\<\(0\o\+o\=\|\o\+o\)\>"
syn match	fasmDecimalNumber	"\<\(0\|[1-9][0-9_]*\)\>"
syn region	fasmComment		start=";" end="$"
syn region	fasmString		start="\"" end="\"\|$"
syn region	fasmString		start="'" end="'\|$"
syn match	fasmSymbol		"[()|\[\]:]"
syn match	fasmSpecial		"[#?%$,]"
syn match	fasmLabel		"^\s*[^; \t]\+:"

hi def link	fasmAddressSizes	type
hi def link	fasmNumericOperator	fasmOperator
hi def link	fasmLogicalOperator	fasmOperator

hi def link	fasmBinaryNumber	fasmNumber
hi def link	fasmHexNumber		fasmNumber
hi def link	fasmFPUNumber		fasmNumber
hi def link	fasmOctalNumber		fasmNumber
hi def link	fasmDecimalNumber	fasmNumber

hi def link	fasmSymbols		fasmRegister
hi def link	fasmPreprocess		fasmDirective

"  link to standard syn groups so the 'colorschemes' work:
hi def link	fasmOperator operator
hi def link	fasmComment  comment
hi def link	fasmDirective	preproc
hi def link	fasmRegister  type
hi def link	fasmNumber   constant
hi def link	fasmSymbol structure
hi def link	fasmString  String
hi def link	fasmSpecial	special
hi def link	fasmInstr keyword
hi def link	fasmLabel label
hi def link	fasmPrefix preproc
let b:current_syntax = "fasm"

let &cpo = s:cpo_save
unlet s:cpo_save

" vim: ts=8 sw=8 :
