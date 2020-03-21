	.file	"main.c"
	.option nopic
	.section	.rodata
	.align	3
	.type	l, @object
	.size	l, 16
l:
	.word	-559038737
	.word	-1057047874
	.word	195936478
	.word	-559038242
	.align	3
	.type	k, @object
	.size	k, 64
k:
	.word	0
	.word	1
	.word	16
	.word	17
	.word	2
	.word	32
	.word	33
	.word	34
	.word	48
	.word	49
	.word	50
	.word	51
	.word	64
	.word	65
	.word	66
	.word	67
	.align	3
	.type	r, @object
	.size	r, 64
r:
	.word	50
	.word	100
	.word	118
	.word	38
	.word	53
	.word	22
	.word	68
	.word	67
	.word	1
	.word	80
	.word	87
	.word	4
	.word	36
	.word	121
	.word	35
	.word	34
	.align	3
.LC0:
	.string	"[+] Correct flag!"
	.align	3
.LC1:
	.string	"[-] Incorrect flag!"
	.text
	.align	1
	.globl	main
	.type	main, @function
main:
	add	sp,sp,-176
	sd	ra,168(sp)
	sd	s0,160(sp)
	add	s0,sp,176
	add	a5,s0,-152
	li	a2,71
	mv	a1,a5
	li	a0,0
	call	read
	mv	a5,a0
	sw	a5,-24(s0)
	lw	a5,-24(s0)
	addw	a5,a5,-1
	sext.w	a5,a5
	add	a4,s0,-16
	add	a5,a4,a5
	sb	zero,-136(a5)
	add	a5,s0,-152
	mv	a0,a5
	call	strlen
	mv	a4,a0
	li	a5,70
	bne	a4,a5,.L38
	lbu	a5,-103(s0)
	mv	a4,a5
	li	a5,52
	bne	a4,a5,.L39
	lbu	a5,-104(s0)
	mv	a4,a5
	li	a5,56
	bne	a4,a5,.L40
	lbu	a5,-152(s0)
	sext.w	a5,a5
	sllw	a5,a5,24
	sext.w	a5,a5
	sext.w	a5,a5
	sw	a5,-168(s0)
	lw	a4,-168(s0)
	lbu	a5,-148(s0)
	sext.w	a5,a5
	sllw	a5,a5,16
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-168(s0)
	lw	a4,-168(s0)
	lbu	a5,-144(s0)
	sext.w	a5,a5
	sllw	a5,a5,8
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-168(s0)
	lw	a4,-168(s0)
	lbu	a5,-140(s0)
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-168(s0)
	lbu	a5,-120(s0)
	mv	a4,a5
	li	a5,102
	bne	a4,a5,.L41
	lbu	a5,-151(s0)
	sext.w	a5,a5
	sllw	a5,a5,24
	sext.w	a5,a5
	sext.w	a5,a5
	sw	a5,-164(s0)
	lw	a4,-164(s0)
	lbu	a5,-147(s0)
	sext.w	a5,a5
	sllw	a5,a5,16
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-164(s0)
	lw	a4,-164(s0)
	lbu	a5,-143(s0)
	sext.w	a5,a5
	sllw	a5,a5,8
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-164(s0)
	lw	a4,-164(s0)
	lbu	a5,-139(s0)
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-164(s0)
	lbu	a5,-119(s0)
	mv	a4,a5
	li	a5,56
	bne	a4,a5,.L42
	lbu	a5,-150(s0)
	sext.w	a5,a5
	sllw	a5,a5,24
	sext.w	a5,a5
	sext.w	a5,a5
	sw	a5,-160(s0)
	lw	a4,-160(s0)
	lbu	a5,-146(s0)
	sext.w	a5,a5
	sllw	a5,a5,16
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-160(s0)
	lw	a4,-160(s0)
	lbu	a5,-142(s0)
	sext.w	a5,a5
	sllw	a5,a5,8
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-160(s0)
	lw	a4,-160(s0)
	lbu	a5,-138(s0)
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-160(s0)
	lbu	a5,-105(s0)
	mv	a4,a5
	li	a5,101
	bne	a4,a5,.L43
	lbu	a5,-149(s0)
	sext.w	a5,a5
	sllw	a5,a5,24
	sext.w	a5,a5
	sext.w	a5,a5
	sw	a5,-156(s0)
	lw	a4,-156(s0)
	lbu	a5,-145(s0)
	sext.w	a5,a5
	sllw	a5,a5,16
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-156(s0)
	lw	a4,-156(s0)
	lbu	a5,-141(s0)
	sext.w	a5,a5
	sllw	a5,a5,8
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-156(s0)
	lw	a4,-156(s0)
	lbu	a5,-137(s0)
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-156(s0)
	lbu	a5,-106(s0)
	mv	a4,a5
	li	a5,50
	bne	a4,a5,.L44
	lw	a5,-168(s0)
	mv	a4,a5
	li	a5,1098592256
	add	a5,a5,868
	bne	a4,a5,.L45
	lbu	a5,-107(s0)
	mv	a4,a5
	li	a5,53
	bne	a4,a5,.L46
	lw	a5,-164(s0)
	mv	a4,a5
	li	a5,1698115584
	add	a5,a5,54
	bne	a4,a5,.L47
	lbu	a5,-113(s0)
	mv	a4,a5
	li	a5,51
	bne	a4,a5,.L48
	lw	a5,-160(s0)
	mv	a4,a5
	li	a5,1915904000
	add	a5,a5,1586
	bne	a4,a5,.L49
	lbu	a5,-108(s0)
	mv	a4,a5
	li	a5,50
	bne	a4,a5,.L50
	lw	a5,-156(s0)
	mv	a4,a5
	li	a5,1865887744
	add	a5,a5,1593
	bne	a4,a5,.L51
	lbu	a5,-109(s0)
	mv	a4,a5
	li	a5,54
	bne	a4,a5,.L52
	lbu	a5,-83(s0)
	sext.w	a5,a5
	sllw	a5,a5,24
	sext.w	a5,a5
	sext.w	a5,a5
	sw	a5,-168(s0)
	lw	a4,-168(s0)
	lbu	a5,-87(s0)
	sext.w	a5,a5
	sllw	a5,a5,16
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-168(s0)
	lw	a4,-168(s0)
	lbu	a5,-91(s0)
	sext.w	a5,a5
	sllw	a5,a5,8
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-168(s0)
	lw	a4,-168(s0)
	lbu	a5,-95(s0)
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-168(s0)
	lbu	a5,-115(s0)
	mv	a4,a5
	li	a5,52
	bne	a4,a5,.L53
	lbu	a5,-84(s0)
	sext.w	a5,a5
	sllw	a5,a5,24
	sext.w	a5,a5
	sext.w	a5,a5
	sw	a5,-164(s0)
	lw	a4,-164(s0)
	lbu	a5,-88(s0)
	sext.w	a5,a5
	sllw	a5,a5,16
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-164(s0)
	lw	a4,-164(s0)
	lbu	a5,-92(s0)
	sext.w	a5,a5
	sllw	a5,a5,8
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-164(s0)
	lw	a4,-164(s0)
	lbu	a5,-96(s0)
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-164(s0)
	lbu	a5,-117(s0)
	mv	a4,a5
	li	a5,56
	bne	a4,a5,.L54
	lbu	a5,-85(s0)
	sext.w	a5,a5
	sllw	a5,a5,24
	sext.w	a5,a5
	sext.w	a5,a5
	sw	a5,-160(s0)
	lw	a4,-160(s0)
	lbu	a5,-89(s0)
	sext.w	a5,a5
	sllw	a5,a5,16
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-160(s0)
	lw	a4,-160(s0)
	lbu	a5,-93(s0)
	sext.w	a5,a5
	sllw	a5,a5,8
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-160(s0)
	lw	a4,-160(s0)
	lbu	a5,-97(s0)
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-160(s0)
	lbu	a5,-114(s0)
	mv	a4,a5
	li	a5,97
	bne	a4,a5,.L55
	lbu	a5,-86(s0)
	sext.w	a5,a5
	sllw	a5,a5,24
	sext.w	a5,a5
	sext.w	a5,a5
	sw	a5,-156(s0)
	lw	a4,-156(s0)
	lbu	a5,-90(s0)
	sext.w	a5,a5
	sllw	a5,a5,16
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-156(s0)
	lw	a4,-156(s0)
	lbu	a5,-94(s0)
	sext.w	a5,a5
	sllw	a5,a5,8
	sext.w	a5,a5
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-156(s0)
	lw	a4,-156(s0)
	lbu	a5,-98(s0)
	sext.w	a5,a5
	or	a5,a4,a5
	sext.w	a5,a5
	sw	a5,-156(s0)
	lbu	a5,-110(s0)
	mv	a4,a5
	li	a5,99
	bne	a4,a5,.L56
	li	a5,-559038464
	add	a4,a5,-273
	lw	a5,-168(s0)
	subw	a5,a4,a5
	sext.w	a5,a5
	mv	a4,a5
	li	a5,1635291136
	add	a5,a5,-1098
	bne	a4,a5,.L57
	lbu	a5,-111(s0)
	mv	a4,a5
	li	a5,98
	bne	a4,a5,.L58
	li	a5,-1057046528
	add	a4,a5,-1346
	lw	a5,-164(s0)
	subw	a5,a4,a5
	sext.w	a5,a5
	mv	a4,a5
	li	a5,-2000068608
	add	a5,a5,-1654
	bne	a4,a5,.L59
	lbu	a5,-112(s0)
	mv	a4,a5
	li	a5,56
	bne	a4,a5,.L60
	li	a5,195936256
	add	a4,a5,222
	lw	a5,-160(s0)
	subw	a5,a4,a5
	sext.w	a5,a5
	mv	a4,a5
	li	a5,-632844288
	add	a5,a5,-1155
	bne	a4,a5,.L61
	lbu	a5,-118(s0)
	mv	a4,a5
	li	a5,50
	bne	a4,a5,.L62
	li	a5,-559038464
	add	a4,a5,222
	lw	a5,-156(s0)
	subw	a5,a4,a5
	sext.w	a5,a5
	mv	a4,a5
	li	a5,2088472576
	add	a5,a5,-1879
	bne	a4,a5,.L63
	lbu	a5,-116(s0)
	mv	a4,a5
	li	a5,48
	bne	a4,a5,.L64
	li	a5,16
	sw	a5,-20(s0)
	j	.L30
.L32:
	lw	a4,-20(s0)
	sraw	a5,a4,31
	srlw	a5,a5,28
	addw	a4,a4,a5
	and	a4,a4,15
	subw	a5,a4,a5
	sext.w	a4,a5
	lui	a5,%hi(k)
	sll	a4,a4,2
	addi	a5,a5,%lo(k)
	add	a5,a4,a5
	lw	a4,0(a5)
	lw	a5,-20(s0)
	add	a3,s0,-16
	add	a5,a3,a5
	lbu	a5,-136(a5)
	sext.w	a5,a5
	xor	a5,a4,a5
	sext.w	a3,a5
	lw	a4,-20(s0)
	sraw	a5,a4,31
	srlw	a5,a5,28
	addw	a4,a4,a5
	and	a4,a4,15
	subw	a5,a4,a5
	sext.w	a4,a5
	lui	a5,%hi(r)
	sll	a4,a4,2
	addi	a5,a5,%lo(r)
	add	a5,a4,a5
	lw	a5,0(a5)
	mv	a4,a3
	bne	a4,a5,.L65
	lw	a5,-20(s0)
	addw	a5,a5,1
	sw	a5,-20(s0)
.L30:
	lw	a5,-20(s0)
	sext.w	a4,a5
	li	a5,31
	ble	a4,a5,.L32
	lbu	a5,-102(s0)
	mv	a4,a5
	li	a5,101
	bne	a4,a5,.L66
	lbu	a5,-101(s0)
	mv	a4,a5
	li	a5,99
	bne	a4,a5,.L67
	lbu	a5,-100(s0)
	mv	a4,a5
	li	a5,98
	bne	a4,a5,.L68
	lbu	a5,-99(s0)
	mv	a4,a5
	li	a5,97
	bne	a4,a5,.L69
	lui	a5,%hi(.LC0)
	addi	a0,a5,%lo(.LC0)
	call	puts
	li	a0,1337
	call	exit
.L38:
	nop
	j	.L3
.L39:
	nop
	j	.L3
.L40:
	nop
	j	.L3
.L41:
	nop
	j	.L3
.L42:
	nop
	j	.L3
.L43:
	nop
	j	.L3
.L44:
	nop
	j	.L3
.L45:
	nop
	j	.L3
.L46:
	nop
	j	.L3
.L47:
	nop
	j	.L3
.L48:
	nop
	j	.L3
.L49:
	nop
	j	.L3
.L50:
	nop
	j	.L3
.L51:
	nop
	j	.L3
.L52:
	nop
	j	.L3
.L53:
	nop
	j	.L3
.L54:
	nop
	j	.L3
.L55:
	nop
	j	.L3
.L56:
	nop
	j	.L3
.L57:
	nop
	j	.L3
.L58:
	nop
	j	.L3
.L59:
	nop
	j	.L3
.L60:
	nop
	j	.L3
.L61:
	nop
	j	.L3
.L62:
	nop
	j	.L3
.L63:
	nop
	j	.L3
.L64:
	nop
	j	.L3
.L65:
	nop
	j	.L3
.L66:
	nop
	j	.L3
.L67:
	nop
	j	.L3
.L68:
	nop
	j	.L3
.L69:
	nop
.L3:
	lui	a5,%hi(.LC1)
	addi	a0,a5,%lo(.LC1)
	call	puts
	li	a5,0
	mv	a0,a5
	ld	ra,168(sp)
	ld	s0,160(sp)
	add	sp,sp,176
	jr	ra
	.size	main, .-main
	.ident	"GCC: (GNU) 7.1.1 20170509"
