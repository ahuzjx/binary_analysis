
stack_flow:     file format elf64-x86-64


Disassembly of section .init:

0000000000400bb0 <_init>:
  400bb0:	48 83 ec 08          	sub    $0x8,%rsp
  400bb4:	48 8b 05 3d 34 20 00 	mov    0x20343d(%rip),%rax        # 603ff8 <__gmon_start__>
  400bbb:	48 85 c0             	test   %rax,%rax
  400bbe:	74 05                	je     400bc5 <_init+0x15>
  400bc0:	e8 b3 01 00 00       	callq  400d78 <.plt.got+0x8>
  400bc5:	48 83 c4 08          	add    $0x8,%rsp
  400bc9:	c3                   	retq   

Disassembly of section .plt:

0000000000400bd0 <.plt>:
  400bd0:	ff 35 32 34 20 00    	pushq  0x203432(%rip)        # 604008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400bd6:	ff 25 34 34 20 00    	jmpq   *0x203434(%rip)        # 604010 <_GLOBAL_OFFSET_TABLE_+0x10>
  400bdc:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400be0 <mprotect@plt>:
  400be0:	ff 25 32 34 20 00    	jmpq   *0x203432(%rip)        # 604018 <mprotect@GLIBC_2.2.5>
  400be6:	68 00 00 00 00       	pushq  $0x0
  400beb:	e9 e0 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400bf0 <_ZNSolsEi@plt>:
  400bf0:	ff 25 2a 34 20 00    	jmpq   *0x20342a(%rip)        # 604020 <_ZNSolsEi@GLIBCXX_3.4>
  400bf6:	68 01 00 00 00       	pushq  $0x1
  400bfb:	e9 d0 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400c00 <memset@plt>:
  400c00:	ff 25 22 34 20 00    	jmpq   *0x203422(%rip)        # 604028 <memset@GLIBC_2.2.5>
  400c06:	68 02 00 00 00       	pushq  $0x2
  400c0b:	e9 c0 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400c10 <_ZNSt8ios_base4InitC1Ev@plt>:
  400c10:	ff 25 1a 34 20 00    	jmpq   *0x20341a(%rip)        # 604030 <_ZNSt8ios_base4InitC1Ev@GLIBCXX_3.4>
  400c16:	68 03 00 00 00       	pushq  $0x3
  400c1b:	e9 b0 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400c20 <__libc_start_main@plt>:
  400c20:	ff 25 12 34 20 00    	jmpq   *0x203412(%rip)        # 604038 <__libc_start_main@GLIBC_2.2.5>
  400c26:	68 04 00 00 00       	pushq  $0x4
  400c2b:	e9 a0 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400c30 <_exit@plt>:
  400c30:	ff 25 0a 34 20 00    	jmpq   *0x20340a(%rip)        # 604040 <_exit@GLIBC_2.2.5>
  400c36:	68 05 00 00 00       	pushq  $0x5
  400c3b:	e9 90 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400c40 <__cxa_atexit@plt>:
  400c40:	ff 25 02 34 20 00    	jmpq   *0x203402(%rip)        # 604048 <__cxa_atexit@GLIBC_2.2.5>
  400c46:	68 06 00 00 00       	pushq  $0x6
  400c4b:	e9 80 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400c50 <sysconf@plt>:
  400c50:	ff 25 fa 33 20 00    	jmpq   *0x2033fa(%rip)        # 604050 <sysconf@GLIBC_2.2.5>
  400c56:	68 07 00 00 00       	pushq  $0x7
  400c5b:	e9 70 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400c60 <getpid@plt>:
  400c60:	ff 25 f2 33 20 00    	jmpq   *0x2033f2(%rip)        # 604058 <getpid@GLIBC_2.2.5>
  400c66:	68 08 00 00 00       	pushq  $0x8
  400c6b:	e9 60 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400c70 <_ZNSt8ios_base4InitD1Ev@plt>:
  400c70:	ff 25 ea 33 20 00    	jmpq   *0x2033ea(%rip)        # 604060 <_ZNSt8ios_base4InitD1Ev@GLIBCXX_3.4>
  400c76:	68 09 00 00 00       	pushq  $0x9
  400c7b:	e9 50 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400c80 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>:
  400c80:	ff 25 e2 33 20 00    	jmpq   *0x2033e2(%rip)        # 604068 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@GLIBCXX_3.4>
  400c86:	68 0a 00 00 00       	pushq  $0xa
  400c8b:	e9 40 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400c90 <strlen@plt>:
  400c90:	ff 25 da 33 20 00    	jmpq   *0x2033da(%rip)        # 604070 <strlen@GLIBC_2.2.5>
  400c96:	68 0b 00 00 00       	pushq  $0xb
  400c9b:	e9 30 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400ca0 <kill@plt>:
  400ca0:	ff 25 d2 33 20 00    	jmpq   *0x2033d2(%rip)        # 604078 <kill@GLIBC_2.2.5>
  400ca6:	68 0c 00 00 00       	pushq  $0xc
  400cab:	e9 20 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400cb0 <strtol@plt>:
  400cb0:	ff 25 ca 33 20 00    	jmpq   *0x2033ca(%rip)        # 604080 <strtol@GLIBC_2.2.5>
  400cb6:	68 0d 00 00 00       	pushq  $0xd
  400cbb:	e9 10 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400cc0 <getenv@plt>:
  400cc0:	ff 25 c2 33 20 00    	jmpq   *0x2033c2(%rip)        # 604088 <getenv@GLIBC_2.2.5>
  400cc6:	68 0e 00 00 00       	pushq  $0xe
  400ccb:	e9 00 ff ff ff       	jmpq   400bd0 <.plt>

0000000000400cd0 <__errno_location@plt>:
  400cd0:	ff 25 ba 33 20 00    	jmpq   *0x2033ba(%rip)        # 604090 <__errno_location@GLIBC_2.2.5>
  400cd6:	68 0f 00 00 00       	pushq  $0xf
  400cdb:	e9 f0 fe ff ff       	jmpq   400bd0 <.plt>

0000000000400ce0 <madvise@plt>:
  400ce0:	ff 25 b2 33 20 00    	jmpq   *0x2033b2(%rip)        # 604098 <madvise@GLIBC_2.2.5>
  400ce6:	68 10 00 00 00       	pushq  $0x10
  400ceb:	e9 e0 fe ff ff       	jmpq   400bd0 <.plt>

0000000000400cf0 <__xpg_strerror_r@plt>:
  400cf0:	ff 25 aa 33 20 00    	jmpq   *0x2033aa(%rip)        # 6040a0 <__xpg_strerror_r@GLIBC_2.3.4>
  400cf6:	68 11 00 00 00       	pushq  $0x11
  400cfb:	e9 d0 fe ff ff       	jmpq   400bd0 <.plt>

0000000000400d00 <_ZNSolsEPFRSoS_E@plt>:
  400d00:	ff 25 a2 33 20 00    	jmpq   *0x2033a2(%rip)        # 6040a8 <_ZNSolsEPFRSoS_E@GLIBCXX_3.4>
  400d06:	68 12 00 00 00       	pushq  $0x12
  400d0b:	e9 c0 fe ff ff       	jmpq   400bd0 <.plt>

0000000000400d10 <sem_post@plt>:
  400d10:	ff 25 9a 33 20 00    	jmpq   *0x20339a(%rip)        # 6040b0 <sem_post>
  400d16:	68 13 00 00 00       	pushq  $0x13
  400d1b:	e9 b0 fe ff ff       	jmpq   400bd0 <.plt>

0000000000400d20 <_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_@plt>:
  400d20:	ff 25 92 33 20 00    	jmpq   *0x203392(%rip)        # 6040b8 <_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_@GLIBCXX_3.4>
  400d26:	68 14 00 00 00       	pushq  $0x14
  400d2b:	e9 a0 fe ff ff       	jmpq   400bd0 <.plt>

0000000000400d30 <write@plt>:
  400d30:	ff 25 8a 33 20 00    	jmpq   *0x20338a(%rip)        # 6040c0 <write@GLIBC_2.2.5>
  400d36:	68 15 00 00 00       	pushq  $0x15
  400d3b:	e9 90 fe ff ff       	jmpq   400bd0 <.plt>

0000000000400d40 <memcpy@plt>:
  400d40:	ff 25 82 33 20 00    	jmpq   *0x203382(%rip)        # 6040c8 <memcpy@GLIBC_2.14>
  400d46:	68 16 00 00 00       	pushq  $0x16
  400d4b:	e9 80 fe ff ff       	jmpq   400bd0 <.plt>

0000000000400d50 <mmap@plt>:
  400d50:	ff 25 7a 33 20 00    	jmpq   *0x20337a(%rip)        # 6040d0 <mmap@GLIBC_2.2.5>
  400d56:	68 17 00 00 00       	pushq  $0x17
  400d5b:	e9 70 fe ff ff       	jmpq   400bd0 <.plt>

0000000000400d60 <sem_wait@plt>:
  400d60:	ff 25 72 33 20 00    	jmpq   *0x203372(%rip)        # 6040d8 <sem_wait>
  400d66:	68 18 00 00 00       	pushq  $0x18
  400d6b:	e9 60 fe ff ff       	jmpq   400bd0 <.plt>

Disassembly of section .plt.got:

0000000000400d70 <.plt.got>:
  400d70:	ff 25 7a 32 20 00    	jmpq   *0x20327a(%rip)        # 603ff0 <sem_init>
  400d76:	66 90                	xchg   %ax,%ax
  400d78:	ff 25 7a 32 20 00    	jmpq   *0x20327a(%rip)        # 603ff8 <__gmon_start__>
  400d7e:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000400d80 <_start>:
  400d80:	31 ed                	xor    %ebp,%ebp
  400d82:	49 89 d1             	mov    %rdx,%r9
  400d85:	5e                   	pop    %rsi
  400d86:	48 89 e2             	mov    %rsp,%rdx
  400d89:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  400d8d:	50                   	push   %rax
  400d8e:	54                   	push   %rsp
  400d8f:	49 c7 c0 20 25 40 00 	mov    $0x402520,%r8
  400d96:	48 c7 c1 b0 24 40 00 	mov    $0x4024b0,%rcx
  400d9d:	48 c7 c7 29 24 40 00 	mov    $0x402429,%rdi
  400da4:	e8 77 fe ff ff       	callq  400c20 <__libc_start_main@plt>
  400da9:	f4                   	hlt    
  400daa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000400db0 <deregister_tm_clones>:
  400db0:	b8 07 41 60 00       	mov    $0x604107,%eax
  400db5:	55                   	push   %rbp
  400db6:	48 2d 00 41 60 00    	sub    $0x604100,%rax
  400dbc:	48 83 f8 0e          	cmp    $0xe,%rax
  400dc0:	48 89 e5             	mov    %rsp,%rbp
  400dc3:	77 02                	ja     400dc7 <deregister_tm_clones+0x17>
  400dc5:	5d                   	pop    %rbp
  400dc6:	c3                   	retq   
  400dc7:	b8 00 00 00 00       	mov    $0x0,%eax
  400dcc:	48 85 c0             	test   %rax,%rax
  400dcf:	74 f4                	je     400dc5 <deregister_tm_clones+0x15>
  400dd1:	5d                   	pop    %rbp
  400dd2:	bf 00 41 60 00       	mov    $0x604100,%edi
  400dd7:	ff e0                	jmpq   *%rax
  400dd9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000400de0 <register_tm_clones>:
  400de0:	b8 00 41 60 00       	mov    $0x604100,%eax
  400de5:	55                   	push   %rbp
  400de6:	48 2d 00 41 60 00    	sub    $0x604100,%rax
  400dec:	48 c1 f8 03          	sar    $0x3,%rax
  400df0:	48 89 e5             	mov    %rsp,%rbp
  400df3:	48 89 c2             	mov    %rax,%rdx
  400df6:	48 c1 ea 3f          	shr    $0x3f,%rdx
  400dfa:	48 01 d0             	add    %rdx,%rax
  400dfd:	48 d1 f8             	sar    %rax
  400e00:	75 02                	jne    400e04 <register_tm_clones+0x24>
  400e02:	5d                   	pop    %rbp
  400e03:	c3                   	retq   
  400e04:	ba 00 00 00 00       	mov    $0x0,%edx
  400e09:	48 85 d2             	test   %rdx,%rdx
  400e0c:	74 f4                	je     400e02 <register_tm_clones+0x22>
  400e0e:	5d                   	pop    %rbp
  400e0f:	48 89 c6             	mov    %rax,%rsi
  400e12:	bf 00 41 60 00       	mov    $0x604100,%edi
  400e17:	ff e2                	jmpq   *%rdx
  400e19:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000400e20 <__do_global_dtors_aux>:
  400e20:	80 3d e9 33 20 00 00 	cmpb   $0x0,0x2033e9(%rip)        # 604210 <completed.6355>
  400e27:	75 11                	jne    400e3a <__do_global_dtors_aux+0x1a>
  400e29:	55                   	push   %rbp
  400e2a:	48 89 e5             	mov    %rsp,%rbp
  400e2d:	e8 7e ff ff ff       	callq  400db0 <deregister_tm_clones>
  400e32:	5d                   	pop    %rbp
  400e33:	c6 05 d6 33 20 00 01 	movb   $0x1,0x2033d6(%rip)        # 604210 <completed.6355>
  400e3a:	f3 c3                	repz retq 
  400e3c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400e40 <frame_dummy>:
  400e40:	48 83 3d a0 2f 20 00 	cmpq   $0x0,0x202fa0(%rip)        # 603de8 <__JCR_END__>
  400e47:	00 
  400e48:	74 1e                	je     400e68 <frame_dummy+0x28>
  400e4a:	b8 00 00 00 00       	mov    $0x0,%eax
  400e4f:	48 85 c0             	test   %rax,%rax
  400e52:	74 14                	je     400e68 <frame_dummy+0x28>
  400e54:	55                   	push   %rbp
  400e55:	bf e8 3d 60 00       	mov    $0x603de8,%edi
  400e5a:	48 89 e5             	mov    %rsp,%rbp
  400e5d:	ff d0                	callq  *%rax
  400e5f:	5d                   	pop    %rbp
  400e60:	e9 7b ff ff ff       	jmpq   400de0 <register_tm_clones>
  400e65:	0f 1f 00             	nopl   (%rax)
  400e68:	e9 73 ff ff ff       	jmpq   400de0 <register_tm_clones>
  400e6d:	0f 1f 00             	nopl   (%rax)

0000000000400e70 <free_locked>:
  400e70:	55                   	push   %rbp
  400e71:	48 89 fd             	mov    %rdi,%rbp
  400e74:	53                   	push   %rbx
  400e75:	48 83 ec 08          	sub    $0x8,%rsp
  400e79:	48 85 ff             	test   %rdi,%rdi
  400e7c:	0f 84 3e 01 00 00    	je     400fc0 <free_locked+0x150>
  400e82:	8b 0d dc 33 20 00    	mov    0x2033dc(%rip),%ecx        # 604264 <noAllocationListProtection>
  400e88:	85 c9                	test   %ecx,%ecx
  400e8a:	0f 84 78 01 00 00    	je     401008 <free_locked+0x198>
  400e90:	48 8b 05 e9 33 20 00 	mov    0x2033e9(%rip),%rax        # 604280 <slotCount>
  400e97:	48 8b 1d f2 33 20 00 	mov    0x2033f2(%rip),%rbx        # 604290 <allocationList>
  400e9e:	48 85 c0             	test   %rax,%rax
  400ea1:	75 1b                	jne    400ebe <free_locked+0x4e>
  400ea3:	e9 28 01 00 00       	jmpq   400fd0 <free_locked+0x160>
  400ea8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  400eaf:	00 
  400eb0:	48 83 c3 28          	add    $0x28,%rbx
  400eb4:	48 83 e8 01          	sub    $0x1,%rax
  400eb8:	0f 84 12 01 00 00    	je     400fd0 <free_locked+0x160>
  400ebe:	48 3b 2b             	cmp    (%rbx),%rbp
  400ec1:	75 ed                	jne    400eb0 <free_locked+0x40>
  400ec3:	8b 43 20             	mov    0x20(%rbx),%eax
  400ec6:	83 f8 02             	cmp    $0x2,%eax
  400ec9:	74 20                	je     400eeb <free_locked+0x7b>
  400ecb:	8b 15 97 33 20 00    	mov    0x203397(%rip),%edx        # 604268 <internalUse>
  400ed1:	85 d2                	test   %edx,%edx
  400ed3:	74 05                	je     400eda <free_locked+0x6a>
  400ed5:	83 f8 04             	cmp    $0x4,%eax
  400ed8:	74 11                	je     400eeb <free_locked+0x7b>
  400eda:	48 8d 3d 6f 16 00 00 	lea    0x166f(%rip),%rdi        # 402550 <__dso_handle+0x8>
  400ee1:	48 89 ee             	mov    %rbp,%rsi
  400ee4:	31 c0                	xor    %eax,%eax
  400ee6:	e8 25 12 00 00       	callq  402110 <EF_Abort>
  400eeb:	48 8d 05 fe 31 20 00 	lea    0x2031fe(%rip),%rax        # 6040f0 <EF_PROTECT_FREE>
  400ef2:	48 8b 7b 08          	mov    0x8(%rbx),%rdi
  400ef6:	48 8b 73 18          	mov    0x18(%rbx),%rsi
  400efa:	83 38 01             	cmpl   $0x1,(%rax)
  400efd:	19 c0                	sbb    %eax,%eax
  400eff:	83 e0 fe             	and    $0xfffffffe,%eax
  400f02:	83 c0 03             	add    $0x3,%eax
  400f05:	89 43 20             	mov    %eax,0x20(%rbx)
  400f08:	e8 33 0e 00 00       	callq  401d40 <Page_Delete>
  400f0d:	48 8b 0d 6c 33 20 00 	mov    0x20336c(%rip),%rcx        # 604280 <slotCount>
  400f14:	4c 8b 43 08          	mov    0x8(%rbx),%r8
  400f18:	48 8b 3d 71 33 20 00 	mov    0x203371(%rip),%rdi        # 604290 <allocationList>
  400f1f:	48 85 c9             	test   %rcx,%rcx
  400f22:	0f 84 2e 01 00 00    	je     401056 <free_locked+0x1e6>
  400f28:	4c 8b 4f 08          	mov    0x8(%rdi),%r9
  400f2c:	4c 89 c8             	mov    %r9,%rax
  400f2f:	48 03 47 18          	add    0x18(%rdi),%rax
  400f33:	49 39 c0             	cmp    %rax,%r8
  400f36:	0f 84 62 01 00 00    	je     40109e <free_locked+0x22e>
  400f3c:	48 89 ce             	mov    %rcx,%rsi
  400f3f:	48 89 f8             	mov    %rdi,%rax
  400f42:	eb 11                	jmp    400f55 <free_locked+0xe5>
  400f44:	0f 1f 40 00          	nopl   0x0(%rax)
  400f48:	48 8b 50 08          	mov    0x8(%rax),%rdx
  400f4c:	48 03 50 18          	add    0x18(%rax),%rdx
  400f50:	49 39 d0             	cmp    %rdx,%r8
  400f53:	74 0c                	je     400f61 <free_locked+0xf1>
  400f55:	48 83 c0 28          	add    $0x28,%rax
  400f59:	48 83 ee 01          	sub    $0x1,%rsi
  400f5d:	75 e9                	jne    400f48 <free_locked+0xd8>
  400f5f:	31 c0                	xor    %eax,%eax
  400f61:	48 8b 73 18          	mov    0x18(%rbx),%rsi
  400f65:	48 89 fa             	mov    %rdi,%rdx
  400f68:	49 01 f0             	add    %rsi,%r8
  400f6b:	4d 39 c1             	cmp    %r8,%r9
  400f6e:	75 0e                	jne    400f7e <free_locked+0x10e>
  400f70:	eb 18                	jmp    400f8a <free_locked+0x11a>
  400f72:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  400f78:	4c 3b 42 08          	cmp    0x8(%rdx),%r8
  400f7c:	74 0c                	je     400f8a <free_locked+0x11a>
  400f7e:	48 83 c2 28          	add    $0x28,%rdx
  400f82:	48 83 e9 01          	sub    $0x1,%rcx
  400f86:	75 f0                	jne    400f78 <free_locked+0x108>
  400f88:	31 d2                	xor    %edx,%edx
  400f8a:	48 85 c0             	test   %rax,%rax
  400f8d:	48 89 f1             	mov    %rsi,%rcx
  400f90:	74 0c                	je     400f9e <free_locked+0x12e>
  400f92:	8b 73 20             	mov    0x20(%rbx),%esi
  400f95:	39 70 20             	cmp    %esi,0x20(%rax)
  400f98:	0f 84 c2 00 00 00    	je     401060 <free_locked+0x1f0>
  400f9e:	48 85 d2             	test   %rdx,%rdx
  400fa1:	74 08                	je     400fab <free_locked+0x13b>
  400fa3:	8b 43 20             	mov    0x20(%rbx),%eax
  400fa6:	39 42 20             	cmp    %eax,0x20(%rdx)
  400fa9:	74 75                	je     401020 <free_locked+0x1b0>
  400fab:	48 8b 43 08          	mov    0x8(%rbx),%rax
  400faf:	48 89 4b 10          	mov    %rcx,0x10(%rbx)
  400fb3:	48 89 03             	mov    %rax,(%rbx)
  400fb6:	8b 05 a8 32 20 00    	mov    0x2032a8(%rip),%eax        # 604264 <noAllocationListProtection>
  400fbc:	85 c0                	test   %eax,%eax
  400fbe:	74 30                	je     400ff0 <free_locked+0x180>
  400fc0:	48 83 c4 08          	add    $0x8,%rsp
  400fc4:	5b                   	pop    %rbx
  400fc5:	5d                   	pop    %rbp
  400fc6:	c3                   	retq   
  400fc7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  400fce:	00 00 
  400fd0:	48 8d 3d 99 15 00 00 	lea    0x1599(%rip),%rdi        # 402570 <__dso_handle+0x28>
  400fd7:	48 89 ee             	mov    %rbp,%rsi
  400fda:	31 c0                	xor    %eax,%eax
  400fdc:	31 db                	xor    %ebx,%ebx
  400fde:	e8 2d 11 00 00       	callq  402110 <EF_Abort>
  400fe3:	e9 db fe ff ff       	jmpq   400ec3 <free_locked+0x53>
  400fe8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  400fef:	00 
  400ff0:	48 8b 35 91 32 20 00 	mov    0x203291(%rip),%rsi        # 604288 <allocationListSize>
  400ff7:	48 83 c4 08          	add    $0x8,%rsp
  400ffb:	5b                   	pop    %rbx
  400ffc:	5d                   	pop    %rbp
  400ffd:	e9 fe 0c 00 00       	jmpq   401d00 <Page_DenyAccess>
  401002:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  401008:	48 8b 35 79 32 20 00 	mov    0x203279(%rip),%rsi        # 604288 <allocationListSize>
  40100f:	48 8b 3d 7a 32 20 00 	mov    0x20327a(%rip),%rdi        # 604290 <allocationList>
  401016:	e8 a5 0c 00 00       	callq  401cc0 <Page_AllowAccess>
  40101b:	e9 70 fe ff ff       	jmpq   400e90 <free_locked+0x20>
  401020:	48 03 4a 18          	add    0x18(%rdx),%rcx
  401024:	48 83 05 4c 32 20 00 	addq   $0x1,0x20324c(%rip)        # 604278 <unUsedSlots>
  40102b:	01 
  40102c:	48 89 4b 18          	mov    %rcx,0x18(%rbx)
  401030:	48 c7 02 00 00 00 00 	movq   $0x0,(%rdx)
  401037:	48 c7 42 08 00 00 00 	movq   $0x0,0x8(%rdx)
  40103e:	00 
  40103f:	48 c7 42 10 00 00 00 	movq   $0x0,0x10(%rdx)
  401046:	00 
  401047:	48 c7 42 18 00 00 00 	movq   $0x0,0x18(%rdx)
  40104e:	00 
  40104f:	c7 42 20 00 00 00 00 	movl   $0x0,0x20(%rdx)
  401056:	48 8b 4b 18          	mov    0x18(%rbx),%rcx
  40105a:	e9 4c ff ff ff       	jmpq   400fab <free_locked+0x13b>
  40105f:	90                   	nop
  401060:	48 01 48 18          	add    %rcx,0x18(%rax)
  401064:	48 83 05 0c 32 20 00 	addq   $0x1,0x20320c(%rip)        # 604278 <unUsedSlots>
  40106b:	01 
  40106c:	48 c7 43 18 00 00 00 	movq   $0x0,0x18(%rbx)
  401073:	00 
  401074:	48 c7 03 00 00 00 00 	movq   $0x0,(%rbx)
  40107b:	48 c7 43 08 00 00 00 	movq   $0x0,0x8(%rbx)
  401082:	00 
  401083:	48 c7 43 10 00 00 00 	movq   $0x0,0x10(%rbx)
  40108a:	00 
  40108b:	c7 43 20 00 00 00 00 	movl   $0x0,0x20(%rbx)
  401092:	48 8b 48 18          	mov    0x18(%rax),%rcx
  401096:	48 89 c3             	mov    %rax,%rbx
  401099:	e9 00 ff ff ff       	jmpq   400f9e <free_locked+0x12e>
  40109e:	48 89 f8             	mov    %rdi,%rax
  4010a1:	e9 bb fe ff ff       	jmpq   400f61 <free_locked+0xf1>
  4010a6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4010ad:	00 00 00 

00000000004010b0 <memalign_locked>:
  4010b0:	41 57                	push   %r15
  4010b2:	49 89 f7             	mov    %rsi,%r15
  4010b5:	41 56                	push   %r14
  4010b7:	41 55                	push   %r13
  4010b9:	41 54                	push   %r12
  4010bb:	55                   	push   %rbp
  4010bc:	53                   	push   %rbx
  4010bd:	48 89 fb             	mov    %rdi,%rbx
  4010c0:	48 83 ec 18          	sub    $0x18,%rsp
  4010c4:	48 85 f6             	test   %rsi,%rsi
  4010c7:	75 13                	jne    4010dc <memalign_locked+0x2c>
  4010c9:	48 8d 05 18 30 20 00 	lea    0x203018(%rip),%rax        # 6040e8 <EF_ALLOW_MALLOC_0>
  4010d0:	44 8b 08             	mov    (%rax),%r9d
  4010d3:	45 85 c9             	test   %r9d,%r9d
  4010d6:	0f 84 77 02 00 00    	je     401353 <memalign_locked+0x2a3>
  4010dc:	48 8d 05 09 30 20 00 	lea    0x203009(%rip),%rax        # 6040ec <EF_PROTECT_BELOW>
  4010e3:	44 8b 00             	mov    (%rax),%r8d
  4010e6:	45 85 c0             	test   %r8d,%r8d
  4010e9:	75 1d                	jne    401108 <memalign_locked+0x58>
  4010eb:	48 83 fb 01          	cmp    $0x1,%rbx
  4010ef:	76 17                	jbe    401108 <memalign_locked+0x58>
  4010f1:	31 d2                	xor    %edx,%edx
  4010f3:	4c 89 f8             	mov    %r15,%rax
  4010f6:	48 f7 f3             	div    %rbx
  4010f9:	48 85 d2             	test   %rdx,%rdx
  4010fc:	0f 85 46 02 00 00    	jne    401348 <memalign_locked+0x298>
  401102:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  401108:	48 8b 0d 11 31 20 00 	mov    0x203111(%rip),%rcx        # 604220 <bytesPerPage>
  40110f:	31 d2                	xor    %edx,%edx
  401111:	49 8d 2c 0f          	lea    (%r15,%rcx,1),%rbp
  401115:	48 89 e8             	mov    %rbp,%rax
  401118:	48 f7 f1             	div    %rcx
  40111b:	48 85 d2             	test   %rdx,%rdx
  40111e:	74 06                	je     401126 <memalign_locked+0x76>
  401120:	48 01 cd             	add    %rcx,%rbp
  401123:	48 29 d5             	sub    %rdx,%rbp
  401126:	8b 3d 38 31 20 00    	mov    0x203138(%rip),%edi        # 604264 <noAllocationListProtection>
  40112c:	85 ff                	test   %edi,%edi
  40112e:	0f 84 fc 01 00 00    	je     401330 <memalign_locked+0x280>
  401134:	8b 35 2e 31 20 00    	mov    0x20312e(%rip),%esi        # 604268 <internalUse>
  40113a:	85 f6                	test   %esi,%esi
  40113c:	75 0e                	jne    40114c <memalign_locked+0x9c>
  40113e:	48 83 3d 32 31 20 00 	cmpq   $0x6,0x203132(%rip)        # 604278 <unUsedSlots>
  401145:	06 
  401146:	0f 86 1a 02 00 00    	jbe    401366 <memalign_locked+0x2b6>
  40114c:	48 8b 0d 2d 31 20 00 	mov    0x20312d(%rip),%rcx        # 604280 <slotCount>
  401153:	48 8b 15 36 31 20 00 	mov    0x203136(%rip),%rdx        # 604290 <allocationList>
  40115a:	48 85 c9             	test   %rcx,%rcx
  40115d:	0f 84 4b 03 00 00    	je     4014ae <memalign_locked+0x3fe>
  401163:	45 31 ed             	xor    %r13d,%r13d
  401166:	45 31 f6             	xor    %r14d,%r14d
  401169:	31 db                	xor    %ebx,%ebx
  40116b:	eb 32                	jmp    40119f <memalign_locked+0xef>
  40116d:	0f 1f 00             	nopl   (%rax)
  401170:	85 ff                	test   %edi,%edi
  401172:	75 1d                	jne    401191 <memalign_locked+0xe1>
  401174:	4d 85 ed             	test   %r13,%r13
  401177:	0f 84 2b 01 00 00    	je     4012a8 <memalign_locked+0x1f8>
  40117d:	4d 85 f6             	test   %r14,%r14
  401180:	0f 84 5a 01 00 00    	je     4012e0 <memalign_locked+0x230>
  401186:	48 85 db             	test   %rbx,%rbx
  401189:	74 06                	je     401191 <memalign_locked+0xe1>
  40118b:	48 39 6b 18          	cmp    %rbp,0x18(%rbx)
  40118f:	74 3f                	je     4011d0 <memalign_locked+0x120>
  401191:	48 83 c2 28          	add    $0x28,%rdx
  401195:	48 83 e9 01          	sub    $0x1,%rcx
  401199:	0f 84 21 01 00 00    	je     4012c0 <memalign_locked+0x210>
  40119f:	8b 7a 20             	mov    0x20(%rdx),%edi
  4011a2:	83 ff 01             	cmp    $0x1,%edi
  4011a5:	75 c9                	jne    401170 <memalign_locked+0xc0>
  4011a7:	48 8b 7a 18          	mov    0x18(%rdx),%rdi
  4011ab:	48 39 fd             	cmp    %rdi,%rbp
  4011ae:	77 e1                	ja     401191 <memalign_locked+0xe1>
  4011b0:	48 85 db             	test   %rbx,%rbx
  4011b3:	74 06                	je     4011bb <memalign_locked+0x10b>
  4011b5:	48 3b 7b 18          	cmp    0x18(%rbx),%rdi
  4011b9:	73 d6                	jae    401191 <memalign_locked+0xe1>
  4011bb:	48 39 fd             	cmp    %rdi,%rbp
  4011be:	48 89 d3             	mov    %rdx,%rbx
  4011c1:	75 ce                	jne    401191 <memalign_locked+0xe1>
  4011c3:	4d 85 ed             	test   %r13,%r13
  4011c6:	74 c9                	je     401191 <memalign_locked+0xe1>
  4011c8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4011cf:	00 
  4011d0:	48 85 db             	test   %rbx,%rbx
  4011d3:	0f 84 45 02 00 00    	je     40141e <memalign_locked+0x36e>
  4011d9:	48 8b 43 18          	mov    0x18(%rbx),%rax
  4011dd:	4c 8b 63 08          	mov    0x8(%rbx),%r12
  4011e1:	83 3d 80 30 20 00 01 	cmpl   $0x1,0x203080(%rip)        # 604268 <internalUse>
  4011e8:	19 d2                	sbb    %edx,%edx
  4011ea:	83 e2 fe             	and    $0xfffffffe,%edx
  4011ed:	83 c2 04             	add    $0x4,%edx
  4011f0:	48 39 c5             	cmp    %rax,%rbp
  4011f3:	89 53 20             	mov    %edx,0x20(%rbx)
  4011f6:	73 27                	jae    40121f <memalign_locked+0x16f>
  4011f8:	49 8d 0c 2c          	lea    (%r12,%rbp,1),%rcx
  4011fc:	48 83 2d 74 30 20 00 	subq   $0x1,0x203074(%rip)        # 604278 <unUsedSlots>
  401203:	01 
  401204:	48 29 e8             	sub    %rbp,%rax
  401207:	49 89 45 18          	mov    %rax,0x18(%r13)
  40120b:	41 c7 45 20 01 00 00 	movl   $0x1,0x20(%r13)
  401212:	00 
  401213:	49 89 4d 08          	mov    %rcx,0x8(%r13)
  401217:	4c 8b 63 08          	mov    0x8(%rbx),%r12
  40121b:	48 89 6b 18          	mov    %rbp,0x18(%rbx)
  40121f:	48 8d 05 c6 2e 20 00 	lea    0x202ec6(%rip),%rax        # 6040ec <EF_PROTECT_BELOW>
  401226:	8b 08                	mov    (%rax),%ecx
  401228:	85 c9                	test   %ecx,%ecx
  40122a:	0f 85 c0 00 00 00    	jne    4012f0 <memalign_locked+0x240>
  401230:	48 8b 05 e9 2f 20 00 	mov    0x202fe9(%rip),%rax        # 604220 <bytesPerPage>
  401237:	48 89 ee             	mov    %rbp,%rsi
  40123a:	48 39 c5             	cmp    %rax,%rbp
  40123d:	74 12                	je     401251 <memalign_locked+0x1a1>
  40123f:	48 29 c6             	sub    %rax,%rsi
  401242:	4c 89 e7             	mov    %r12,%rdi
  401245:	e8 76 0a 00 00       	callq  401cc0 <Page_AllowAccess>
  40124a:	48 8b 35 cf 2f 20 00 	mov    0x202fcf(%rip),%rsi        # 604220 <bytesPerPage>
  401251:	48 29 f5             	sub    %rsi,%rbp
  401254:	4c 01 e5             	add    %r12,%rbp
  401257:	48 89 ef             	mov    %rbp,%rdi
  40125a:	e8 e1 0a 00 00       	callq  401d40 <Page_Delete>
  40125f:	48 89 e8             	mov    %rbp,%rax
  401262:	4c 29 f8             	sub    %r15,%rax
  401265:	8b 15 fd 2f 20 00    	mov    0x202ffd(%rip),%edx        # 604268 <internalUse>
  40126b:	48 89 03             	mov    %rax,(%rbx)
  40126e:	4c 89 7b 10          	mov    %r15,0x10(%rbx)
  401272:	85 d2                	test   %edx,%edx
  401274:	75 1d                	jne    401293 <memalign_locked+0x1e3>
  401276:	48 8b 35 0b 30 20 00 	mov    0x20300b(%rip),%rsi        # 604288 <allocationListSize>
  40127d:	48 8b 3d 0c 30 20 00 	mov    0x20300c(%rip),%rdi        # 604290 <allocationList>
  401284:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  401289:	e8 72 0a 00 00       	callq  401d00 <Page_DenyAccess>
  40128e:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
  401293:	48 83 c4 18          	add    $0x18,%rsp
  401297:	5b                   	pop    %rbx
  401298:	5d                   	pop    %rbp
  401299:	41 5c                	pop    %r12
  40129b:	41 5d                	pop    %r13
  40129d:	41 5e                	pop    %r14
  40129f:	41 5f                	pop    %r15
  4012a1:	c3                   	retq   
  4012a2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  4012a8:	49 89 d5             	mov    %rdx,%r13
  4012ab:	48 83 c2 28          	add    $0x28,%rdx
  4012af:	48 83 e9 01          	sub    $0x1,%rcx
  4012b3:	0f 85 e6 fe ff ff    	jne    40119f <memalign_locked+0xef>
  4012b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  4012c0:	4d 85 ed             	test   %r13,%r13
  4012c3:	0f 85 07 ff ff ff    	jne    4011d0 <memalign_locked+0x120>
  4012c9:	48 8d 3d 44 13 00 00 	lea    0x1344(%rip),%rdi        # 402614 <__dso_handle+0xcc>
  4012d0:	31 c0                	xor    %eax,%eax
  4012d2:	45 31 ed             	xor    %r13d,%r13d
  4012d5:	e8 56 10 00 00       	callq  402330 <EF_InternalError>
  4012da:	e9 f1 fe ff ff       	jmpq   4011d0 <memalign_locked+0x120>
  4012df:	90                   	nop
  4012e0:	49 89 d6             	mov    %rdx,%r14
  4012e3:	e9 a9 fe ff ff       	jmpq   401191 <memalign_locked+0xe1>
  4012e8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4012ef:	00 
  4012f0:	48 8b 35 29 2f 20 00 	mov    0x202f29(%rip),%rsi        # 604220 <bytesPerPage>
  4012f7:	4c 89 e7             	mov    %r12,%rdi
  4012fa:	e8 41 0a 00 00       	callq  401d40 <Page_Delete>
  4012ff:	48 8b 15 1a 2f 20 00 	mov    0x202f1a(%rip),%rdx        # 604220 <bytesPerPage>
  401306:	48 39 d5             	cmp    %rdx,%rbp
  401309:	49 8d 04 14          	lea    (%r12,%rdx,1),%rax
  40130d:	0f 84 52 ff ff ff    	je     401265 <memalign_locked+0x1b5>
  401313:	48 89 ee             	mov    %rbp,%rsi
  401316:	48 89 c7             	mov    %rax,%rdi
  401319:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  40131e:	48 29 d6             	sub    %rdx,%rsi
  401321:	e8 9a 09 00 00       	callq  401cc0 <Page_AllowAccess>
  401326:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
  40132b:	e9 35 ff ff ff       	jmpq   401265 <memalign_locked+0x1b5>
  401330:	48 8b 35 51 2f 20 00 	mov    0x202f51(%rip),%rsi        # 604288 <allocationListSize>
  401337:	48 8b 3d 52 2f 20 00 	mov    0x202f52(%rip),%rdi        # 604290 <allocationList>
  40133e:	e8 7d 09 00 00       	callq  401cc0 <Page_AllowAccess>
  401343:	e9 ec fd ff ff       	jmpq   401134 <memalign_locked+0x84>
  401348:	49 01 df             	add    %rbx,%r15
  40134b:	49 29 d7             	sub    %rdx,%r15
  40134e:	e9 b5 fd ff ff       	jmpq   401108 <memalign_locked+0x58>
  401353:	48 8d 3d 3e 12 00 00 	lea    0x123e(%rip),%rdi        # 402598 <__dso_handle+0x50>
  40135a:	31 c0                	xor    %eax,%eax
  40135c:	e8 af 0d 00 00       	callq  402110 <EF_Abort>
  401361:	e9 76 fd ff ff       	jmpq   4010dc <memalign_locked+0x2c>
  401366:	4c 8b 35 23 2f 20 00 	mov    0x202f23(%rip),%r14        # 604290 <allocationList>
  40136d:	48 8b 35 14 2f 20 00 	mov    0x202f14(%rip),%rsi        # 604288 <allocationListSize>
  401374:	4c 89 f7             	mov    %r14,%rdi
  401377:	49 89 f5             	mov    %rsi,%r13
  40137a:	4c 03 2d 9f 2e 20 00 	add    0x202e9f(%rip),%r13        # 604220 <bytesPerPage>
  401381:	e8 3a 09 00 00       	callq  401cc0 <Page_AllowAccess>
  401386:	48 8d 05 67 2d 20 00 	lea    0x202d67(%rip),%rax        # 6040f4 <EF_ALIGNMENT>
  40138d:	c7 05 cd 2e 20 00 01 	movl   $0x1,0x202ecd(%rip)        # 604264 <noAllocationListProtection>
  401394:	00 00 00 
  401397:	c7 05 c7 2e 20 00 01 	movl   $0x1,0x202ec7(%rip)        # 604268 <internalUse>
  40139e:	00 00 00 
  4013a1:	4c 89 ee             	mov    %r13,%rsi
  4013a4:	48 63 38             	movslq (%rax),%rdi
  4013a7:	e8 04 fd ff ff       	callq  4010b0 <memalign_locked>
  4013ac:	4c 8b 25 d5 2e 20 00 	mov    0x202ed5(%rip),%r12        # 604288 <allocationListSize>
  4013b3:	48 8b 35 d6 2e 20 00 	mov    0x202ed6(%rip),%rsi        # 604290 <allocationList>
  4013ba:	48 89 c7             	mov    %rax,%rdi
  4013bd:	48 89 c3             	mov    %rax,%rbx
  4013c0:	4c 89 e2             	mov    %r12,%rdx
  4013c3:	e8 78 f9 ff ff       	callq  400d40 <memcpy@plt>
  4013c8:	48 8b 15 51 2e 20 00 	mov    0x202e51(%rip),%rdx        # 604220 <bytesPerPage>
  4013cf:	4a 8d 3c 23          	lea    (%rbx,%r12,1),%rdi
  4013d3:	31 f6                	xor    %esi,%esi
  4013d5:	e8 26 f8 ff ff       	callq  400c00 <memset@plt>
  4013da:	4c 89 f7             	mov    %r14,%rdi
  4013dd:	48 8b 05 8c 2e 20 00 	mov    0x202e8c(%rip),%rax        # 604270 <slotsPerPage>
  4013e4:	48 89 1d a5 2e 20 00 	mov    %rbx,0x202ea5(%rip)        # 604290 <allocationList>
  4013eb:	4c 89 2d 96 2e 20 00 	mov    %r13,0x202e96(%rip)        # 604288 <allocationListSize>
  4013f2:	48 01 05 87 2e 20 00 	add    %rax,0x202e87(%rip)        # 604280 <slotCount>
  4013f9:	48 01 05 78 2e 20 00 	add    %rax,0x202e78(%rip)        # 604278 <unUsedSlots>
  401400:	e8 6b fa ff ff       	callq  400e70 <free_locked>
  401405:	c7 05 55 2e 20 00 00 	movl   $0x0,0x202e55(%rip)        # 604264 <noAllocationListProtection>
  40140c:	00 00 00 
  40140f:	c7 05 4f 2e 20 00 00 	movl   $0x0,0x202e4f(%rip)        # 604268 <internalUse>
  401416:	00 00 00 
  401419:	e9 2e fd ff ff       	jmpq   40114c <memalign_locked+0x9c>
  40141e:	4d 85 f6             	test   %r14,%r14
  401421:	0f 84 91 00 00 00    	je     4014b8 <memalign_locked+0x408>
  401427:	48 81 fd 00 00 10 00 	cmp    $0x100000,%rbp
  40142e:	bb 00 00 10 00       	mov    $0x100000,%ebx
  401433:	48 8b 0d e6 2d 20 00 	mov    0x202de6(%rip),%rcx        # 604220 <bytesPerPage>
  40143a:	48 0f 43 dd          	cmovae %rbp,%rbx
  40143e:	31 d2                	xor    %edx,%edx
  401440:	48 89 d8             	mov    %rbx,%rax
  401443:	48 f7 f1             	div    %rcx
  401446:	48 85 d2             	test   %rdx,%rdx
  401449:	74 06                	je     401451 <memalign_locked+0x3a1>
  40144b:	48 01 cb             	add    %rcx,%rbx
  40144e:	48 29 d3             	sub    %rdx,%rbx
  401451:	48 89 df             	mov    %rbx,%rdi
  401454:	e8 f7 07 00 00       	callq  401c50 <Page_Create>
  401459:	49 89 c4             	mov    %rax,%r12
  40145c:	49 89 45 08          	mov    %rax,0x8(%r13)
  401460:	48 8d 05 7d 2c 20 00 	lea    0x202c7d(%rip),%rax        # 6040e4 <EF_FILL>
  401467:	48 83 2d 09 2e 20 00 	subq   $0x1,0x202e09(%rip)        # 604278 <unUsedSlots>
  40146e:	01 
  40146f:	49 89 5d 18          	mov    %rbx,0x18(%r13)
  401473:	41 c7 45 20 01 00 00 	movl   $0x1,0x20(%r13)
  40147a:	00 
  40147b:	8b 30                	mov    (%rax),%esi
  40147d:	83 fe ff             	cmp    $0xffffffff,%esi
  401480:	74 1e                	je     4014a0 <memalign_locked+0x3f0>
  401482:	48 89 da             	mov    %rbx,%rdx
  401485:	4c 89 e7             	mov    %r12,%rdi
  401488:	4c 89 eb             	mov    %r13,%rbx
  40148b:	e8 70 f7 ff ff       	callq  400c00 <memset@plt>
  401490:	49 8b 45 18          	mov    0x18(%r13),%rax
  401494:	4d 8b 65 08          	mov    0x8(%r13),%r12
  401498:	4d 89 f5             	mov    %r14,%r13
  40149b:	e9 41 fd ff ff       	jmpq   4011e1 <memalign_locked+0x131>
  4014a0:	48 89 d8             	mov    %rbx,%rax
  4014a3:	4c 89 eb             	mov    %r13,%rbx
  4014a6:	4d 89 f5             	mov    %r14,%r13
  4014a9:	e9 33 fd ff ff       	jmpq   4011e1 <memalign_locked+0x131>
  4014ae:	45 31 f6             	xor    %r14d,%r14d
  4014b1:	31 db                	xor    %ebx,%ebx
  4014b3:	e9 11 fe ff ff       	jmpq   4012c9 <memalign_locked+0x219>
  4014b8:	48 8d 3d 66 11 00 00 	lea    0x1166(%rip),%rdi        # 402625 <__dso_handle+0xdd>
  4014bf:	31 c0                	xor    %eax,%eax
  4014c1:	e8 6a 0e 00 00       	callq  402330 <EF_InternalError>
  4014c6:	e9 5c ff ff ff       	jmpq   401427 <memalign_locked+0x377>
  4014cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000004014d0 <lock.part.0>:
  4014d0:	48 83 ec 08          	sub    $0x8,%rsp
  4014d4:	0f 1f 40 00          	nopl   0x0(%rax)
  4014d8:	48 8d 3d 61 2d 20 00 	lea    0x202d61(%rip),%rdi        # 604240 <EF_sem>
  4014df:	e8 7c f8 ff ff       	callq  400d60 <sem_wait@plt>
  4014e4:	85 c0                	test   %eax,%eax
  4014e6:	78 f0                	js     4014d8 <lock.part.0+0x8>
  4014e8:	48 83 c4 08          	add    $0x8,%rsp
  4014ec:	c3                   	retq   
  4014ed:	0f 1f 00             	nopl   (%rax)

00000000004014f0 <release.part.1>:
  4014f0:	48 8d 3d 49 2d 20 00 	lea    0x202d49(%rip),%rdi        # 604240 <EF_sem>
  4014f7:	48 83 ec 08          	sub    $0x8,%rsp
  4014fb:	e8 10 f8 ff ff       	callq  400d10 <sem_post@plt>
  401500:	85 c0                	test   %eax,%eax
  401502:	78 0c                	js     401510 <release.part.1+0x20>
  401504:	48 83 c4 08          	add    $0x8,%rsp
  401508:	c3                   	retq   
  401509:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  401510:	48 8d 3d 1f 11 00 00 	lea    0x111f(%rip),%rdi        # 402636 <__dso_handle+0xee>
  401517:	31 c0                	xor    %eax,%eax
  401519:	48 83 c4 08          	add    $0x8,%rsp
  40151d:	e9 0e 0e 00 00       	jmpq   402330 <EF_InternalError>
  401522:	0f 1f 40 00          	nopl   0x0(%rax)
  401526:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40152d:	00 00 00 

0000000000401530 <initialize>:
  401530:	41 54                	push   %r12
  401532:	55                   	push   %rbp
  401533:	53                   	push   %rbx
  401534:	48 8d 1d bd 2b 20 00 	lea    0x202bbd(%rip),%rbx        # 6040f8 <EF_DISABLE_BANNER>
  40153b:	8b 13                	mov    (%rbx),%edx
  40153d:	83 fa ff             	cmp    $0xffffffff,%edx
  401540:	0f 84 12 02 00 00    	je     401758 <initialize+0x228>
  401546:	85 d2                	test   %edx,%edx
  401548:	0f 84 f2 01 00 00    	je     401740 <initialize+0x210>
  40154e:	48 83 3d 9a 2a 20 00 	cmpq   $0x0,0x202a9a(%rip)        # 603ff0 <sem_init>
  401555:	00 
  401556:	74 0e                	je     401566 <initialize+0x36>
  401558:	8b 0d 02 2d 20 00    	mov    0x202d02(%rip),%ecx        # 604260 <pthread_initialization>
  40155e:	85 c9                	test   %ecx,%ecx
  401560:	0f 84 62 01 00 00    	je     4016c8 <initialize+0x198>
  401566:	8b 15 bc 2c 20 00    	mov    0x202cbc(%rip),%edx        # 604228 <semEnabled>
  40156c:	85 d2                	test   %edx,%edx
  40156e:	0f 85 79 01 00 00    	jne    4016ed <initialize+0x1bd>
  401574:	48 8d 1d 79 2b 20 00 	lea    0x202b79(%rip),%rbx        # 6040f4 <EF_ALIGNMENT>
  40157b:	83 3b ff             	cmpl   $0xffffffff,(%rbx)
  40157e:	0f 84 80 01 00 00    	je     401704 <initialize+0x1d4>
  401584:	48 8d 1d 61 2b 20 00 	lea    0x202b61(%rip),%rbx        # 6040ec <EF_PROTECT_BELOW>
  40158b:	83 3b ff             	cmpl   $0xffffffff,(%rbx)
  40158e:	0f 84 f4 01 00 00    	je     401788 <initialize+0x258>
  401594:	48 8d 1d 55 2b 20 00 	lea    0x202b55(%rip),%rbx        # 6040f0 <EF_PROTECT_FREE>
  40159b:	83 3b ff             	cmpl   $0xffffffff,(%rbx)
  40159e:	0f 84 1c 02 00 00    	je     4017c0 <initialize+0x290>
  4015a4:	48 8d 1d 3d 2b 20 00 	lea    0x202b3d(%rip),%rbx        # 6040e8 <EF_ALLOW_MALLOC_0>
  4015ab:	83 3b ff             	cmpl   $0xffffffff,(%rbx)
  4015ae:	0f 84 44 02 00 00    	je     4017f8 <initialize+0x2c8>
  4015b4:	48 8d 1d 29 2b 20 00 	lea    0x202b29(%rip),%rbx        # 6040e4 <EF_FILL>
  4015bb:	83 3b ff             	cmpl   $0xffffffff,(%rbx)
  4015be:	0f 84 6c 02 00 00    	je     401830 <initialize+0x300>
  4015c4:	e8 a7 07 00 00       	callq  401d70 <Page_Size>
  4015c9:	48 ba cd cc cc cc cc 	movabs $0xcccccccccccccccd,%rdx
  4015d0:	cc cc cc 
  4015d3:	48 89 c1             	mov    %rax,%rcx
  4015d6:	48 89 05 43 2c 20 00 	mov    %rax,0x202c43(%rip)        # 604220 <bytesPerPage>
  4015dd:	48 f7 e2             	mul    %rdx
  4015e0:	bd 00 00 10 00       	mov    $0x100000,%ebp
  4015e5:	48 89 0d 9c 2c 20 00 	mov    %rcx,0x202c9c(%rip)        # 604288 <allocationListSize>
  4015ec:	48 c1 ea 05          	shr    $0x5,%rdx
  4015f0:	48 81 f9 00 00 10 00 	cmp    $0x100000,%rcx
  4015f7:	48 0f 43 e9          	cmovae %rcx,%rbp
  4015fb:	48 89 15 6e 2c 20 00 	mov    %rdx,0x202c6e(%rip)        # 604270 <slotsPerPage>
  401602:	48 89 15 77 2c 20 00 	mov    %rdx,0x202c77(%rip)        # 604280 <slotCount>
  401609:	48 89 e8             	mov    %rbp,%rax
  40160c:	31 d2                	xor    %edx,%edx
  40160e:	48 f7 f1             	div    %rcx
  401611:	48 85 d2             	test   %rdx,%rdx
  401614:	74 06                	je     40161c <initialize+0xec>
  401616:	48 01 cd             	add    %rcx,%rbp
  401619:	48 29 d5             	sub    %rdx,%rbp
  40161c:	48 89 ef             	mov    %rbp,%rdi
  40161f:	e8 2c 06 00 00       	callq  401c50 <Page_Create>
  401624:	4c 8b 25 5d 2c 20 00 	mov    0x202c5d(%rip),%r12        # 604288 <allocationListSize>
  40162b:	31 f6                	xor    %esi,%esi
  40162d:	48 89 c7             	mov    %rax,%rdi
  401630:	48 89 c3             	mov    %rax,%rbx
  401633:	48 89 05 56 2c 20 00 	mov    %rax,0x202c56(%rip)        # 604290 <allocationList>
  40163a:	4c 89 e2             	mov    %r12,%rdx
  40163d:	e8 be f5 ff ff       	callq  400c00 <memset@plt>
  401642:	4c 39 e5             	cmp    %r12,%rbp
  401645:	4c 89 63 10          	mov    %r12,0x10(%rbx)
  401649:	4c 89 63 18          	mov    %r12,0x18(%rbx)
  40164d:	48 89 1b             	mov    %rbx,(%rbx)
  401650:	48 89 5b 08          	mov    %rbx,0x8(%rbx)
  401654:	c7 43 20 04 00 00 00 	movl   $0x4,0x20(%rbx)
  40165b:	77 33                	ja     401690 <initialize+0x160>
  40165d:	48 8b 73 40          	mov    0x40(%rbx),%rsi
  401661:	48 8b 7b 30          	mov    0x30(%rbx),%rdi
  401665:	e8 96 06 00 00       	callq  401d00 <Page_DenyAccess>
  40166a:	48 8b 05 0f 2c 20 00 	mov    0x202c0f(%rip),%rax        # 604280 <slotCount>
  401671:	48 83 e8 02          	sub    $0x2,%rax
  401675:	48 89 05 fc 2b 20 00 	mov    %rax,0x202bfc(%rip)        # 604278 <unUsedSlots>
  40167c:	8b 05 a6 2b 20 00    	mov    0x202ba6(%rip),%eax        # 604228 <semEnabled>
  401682:	85 c0                	test   %eax,%eax
  401684:	75 32                	jne    4016b8 <initialize+0x188>
  401686:	5b                   	pop    %rbx
  401687:	5d                   	pop    %rbp
  401688:	41 5c                	pop    %r12
  40168a:	c3                   	retq   
  40168b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  401690:	4a 8d 3c 23          	lea    (%rbx,%r12,1),%rdi
  401694:	4c 29 e5             	sub    %r12,%rbp
  401697:	c7 43 48 01 00 00 00 	movl   $0x1,0x48(%rbx)
  40169e:	48 89 6b 38          	mov    %rbp,0x38(%rbx)
  4016a2:	48 89 6b 40          	mov    %rbp,0x40(%rbx)
  4016a6:	48 89 ee             	mov    %rbp,%rsi
  4016a9:	48 89 7b 28          	mov    %rdi,0x28(%rbx)
  4016ad:	48 89 7b 30          	mov    %rdi,0x30(%rbx)
  4016b1:	eb b2                	jmp    401665 <initialize+0x135>
  4016b3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  4016b8:	5b                   	pop    %rbx
  4016b9:	5d                   	pop    %rbp
  4016ba:	41 5c                	pop    %r12
  4016bc:	31 c0                	xor    %eax,%eax
  4016be:	e9 2d fe ff ff       	jmpq   4014f0 <release.part.1>
  4016c3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  4016c8:	48 8d 3d 71 2b 20 00 	lea    0x202b71(%rip),%rdi        # 604240 <EF_sem>
  4016cf:	31 f6                	xor    %esi,%esi
  4016d1:	ba 01 00 00 00       	mov    $0x1,%edx
  4016d6:	e8 95 f6 ff ff       	callq  400d70 <.plt.got>
  4016db:	85 c0                	test   %eax,%eax
  4016dd:	0f 88 83 fe ff ff    	js     401566 <initialize+0x36>
  4016e3:	c7 05 3b 2b 20 00 01 	movl   $0x1,0x202b3b(%rip)        # 604228 <semEnabled>
  4016ea:	00 00 00 
  4016ed:	31 c0                	xor    %eax,%eax
  4016ef:	e8 dc fd ff ff       	callq  4014d0 <lock.part.0>
  4016f4:	48 8d 1d f9 29 20 00 	lea    0x2029f9(%rip),%rbx        # 6040f4 <EF_ALIGNMENT>
  4016fb:	83 3b ff             	cmpl   $0xffffffff,(%rbx)
  4016fe:	0f 85 80 fe ff ff    	jne    401584 <initialize+0x54>
  401704:	48 8d 3d 5b 0f 00 00 	lea    0xf5b(%rip),%rdi        # 402666 <__dso_handle+0x11e>
  40170b:	e8 b0 f5 ff ff       	callq  400cc0 <getenv@plt>
  401710:	48 85 c0             	test   %rax,%rax
  401713:	0f 84 77 01 00 00    	je     401890 <initialize+0x360>
  401719:	ba 0a 00 00 00       	mov    $0xa,%edx
  40171e:	31 f6                	xor    %esi,%esi
  401720:	48 89 c7             	mov    %rax,%rdi
  401723:	e8 88 f5 ff ff       	callq  400cb0 <strtol@plt>
  401728:	89 03                	mov    %eax,(%rbx)
  40172a:	e9 55 fe ff ff       	jmpq   401584 <initialize+0x54>
  40172f:	90                   	nop
  401730:	c7 03 00 00 00 00    	movl   $0x0,(%rbx)
  401736:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40173d:	00 00 00 
  401740:	48 8d 3d 79 0f 00 00 	lea    0xf79(%rip),%rdi        # 4026c0 <version>
  401747:	31 c0                	xor    %eax,%eax
  401749:	e8 52 06 00 00       	callq  401da0 <EF_Print>
  40174e:	e9 fb fd ff ff       	jmpq   40154e <initialize+0x1e>
  401753:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  401758:	48 8d 3d f5 0e 00 00 	lea    0xef5(%rip),%rdi        # 402654 <__dso_handle+0x10c>
  40175f:	e8 5c f5 ff ff       	callq  400cc0 <getenv@plt>
  401764:	48 85 c0             	test   %rax,%rax
  401767:	74 c7                	je     401730 <initialize+0x200>
  401769:	ba 0a 00 00 00       	mov    $0xa,%edx
  40176e:	31 f6                	xor    %esi,%esi
  401770:	48 89 c7             	mov    %rax,%rdi
  401773:	e8 38 f5 ff ff       	callq  400cb0 <strtol@plt>
  401778:	89 c2                	mov    %eax,%edx
  40177a:	89 03                	mov    %eax,(%rbx)
  40177c:	e9 c5 fd ff ff       	jmpq   401546 <initialize+0x16>
  401781:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  401788:	48 8d 3d e4 0e 00 00 	lea    0xee4(%rip),%rdi        # 402673 <__dso_handle+0x12b>
  40178f:	e8 2c f5 ff ff       	callq  400cc0 <getenv@plt>
  401794:	48 85 c0             	test   %rax,%rax
  401797:	0f 84 e3 00 00 00    	je     401880 <initialize+0x350>
  40179d:	31 f6                	xor    %esi,%esi
  40179f:	ba 0a 00 00 00       	mov    $0xa,%edx
  4017a4:	48 89 c7             	mov    %rax,%rdi
  4017a7:	e8 04 f5 ff ff       	callq  400cb0 <strtol@plt>
  4017ac:	85 c0                	test   %eax,%eax
  4017ae:	0f 95 c0             	setne  %al
  4017b1:	0f b6 c0             	movzbl %al,%eax
  4017b4:	89 03                	mov    %eax,(%rbx)
  4017b6:	e9 d9 fd ff ff       	jmpq   401594 <initialize+0x64>
  4017bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  4017c0:	48 8d 3d bd 0e 00 00 	lea    0xebd(%rip),%rdi        # 402684 <__dso_handle+0x13c>
  4017c7:	e8 f4 f4 ff ff       	callq  400cc0 <getenv@plt>
  4017cc:	48 85 c0             	test   %rax,%rax
  4017cf:	0f 84 9b 00 00 00    	je     401870 <initialize+0x340>
  4017d5:	31 f6                	xor    %esi,%esi
  4017d7:	ba 0a 00 00 00       	mov    $0xa,%edx
  4017dc:	48 89 c7             	mov    %rax,%rdi
  4017df:	e8 cc f4 ff ff       	callq  400cb0 <strtol@plt>
  4017e4:	85 c0                	test   %eax,%eax
  4017e6:	0f 95 c0             	setne  %al
  4017e9:	0f b6 c0             	movzbl %al,%eax
  4017ec:	89 03                	mov    %eax,(%rbx)
  4017ee:	e9 b1 fd ff ff       	jmpq   4015a4 <initialize+0x74>
  4017f3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  4017f8:	48 8d 3d 95 0e 00 00 	lea    0xe95(%rip),%rdi        # 402694 <__dso_handle+0x14c>
  4017ff:	e8 bc f4 ff ff       	callq  400cc0 <getenv@plt>
  401804:	48 85 c0             	test   %rax,%rax
  401807:	74 57                	je     401860 <initialize+0x330>
  401809:	31 f6                	xor    %esi,%esi
  40180b:	ba 0a 00 00 00       	mov    $0xa,%edx
  401810:	48 89 c7             	mov    %rax,%rdi
  401813:	e8 98 f4 ff ff       	callq  400cb0 <strtol@plt>
  401818:	85 c0                	test   %eax,%eax
  40181a:	0f 95 c0             	setne  %al
  40181d:	0f b6 c0             	movzbl %al,%eax
  401820:	89 03                	mov    %eax,(%rbx)
  401822:	e9 8d fd ff ff       	jmpq   4015b4 <initialize+0x84>
  401827:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  40182e:	00 00 
  401830:	48 8d 3d 6f 0e 00 00 	lea    0xe6f(%rip),%rdi        # 4026a6 <__dso_handle+0x15e>
  401837:	e8 84 f4 ff ff       	callq  400cc0 <getenv@plt>
  40183c:	48 85 c0             	test   %rax,%rax
  40183f:	0f 84 7f fd ff ff    	je     4015c4 <initialize+0x94>
  401845:	ba 0a 00 00 00       	mov    $0xa,%edx
  40184a:	31 f6                	xor    %esi,%esi
  40184c:	48 89 c7             	mov    %rax,%rdi
  40184f:	e8 5c f4 ff ff       	callq  400cb0 <strtol@plt>
  401854:	25 ff 00 00 00       	and    $0xff,%eax
  401859:	89 03                	mov    %eax,(%rbx)
  40185b:	e9 64 fd ff ff       	jmpq   4015c4 <initialize+0x94>
  401860:	c7 03 00 00 00 00    	movl   $0x0,(%rbx)
  401866:	e9 49 fd ff ff       	jmpq   4015b4 <initialize+0x84>
  40186b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  401870:	c7 03 00 00 00 00    	movl   $0x0,(%rbx)
  401876:	e9 29 fd ff ff       	jmpq   4015a4 <initialize+0x74>
  40187b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  401880:	c7 03 00 00 00 00    	movl   $0x0,(%rbx)
  401886:	e9 09 fd ff ff       	jmpq   401594 <initialize+0x64>
  40188b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  401890:	c7 03 04 00 00 00    	movl   $0x4,(%rbx)
  401896:	e9 e9 fc ff ff       	jmpq   401584 <initialize+0x54>
  40189b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000004018a0 <__libc_malloc_pthread_startup>:
  4018a0:	40 84 ff             	test   %dil,%dil
  4018a3:	75 4b                	jne    4018f0 <__libc_malloc_pthread_startup+0x50>
  4018a5:	8b 05 7d 29 20 00    	mov    0x20297d(%rip),%eax        # 604228 <semEnabled>
  4018ab:	c7 05 ab 29 20 00 00 	movl   $0x0,0x2029ab(%rip)        # 604260 <pthread_initialization>
  4018b2:	00 00 00 
  4018b5:	85 c0                	test   %eax,%eax
  4018b7:	75 33                	jne    4018ec <__libc_malloc_pthread_startup+0x4c>
  4018b9:	48 83 3d 2f 27 20 00 	cmpq   $0x0,0x20272f(%rip)        # 603ff0 <sem_init>
  4018c0:	00 
  4018c1:	74 29                	je     4018ec <__libc_malloc_pthread_startup+0x4c>
  4018c3:	48 8d 3d 76 29 20 00 	lea    0x202976(%rip),%rdi        # 604240 <EF_sem>
  4018ca:	48 83 ec 08          	sub    $0x8,%rsp
  4018ce:	31 f6                	xor    %esi,%esi
  4018d0:	ba 01 00 00 00       	mov    $0x1,%edx
  4018d5:	e8 96 f4 ff ff       	callq  400d70 <.plt.got>
  4018da:	85 c0                	test   %eax,%eax
  4018dc:	78 0a                	js     4018e8 <__libc_malloc_pthread_startup+0x48>
  4018de:	c7 05 40 29 20 00 01 	movl   $0x1,0x202940(%rip)        # 604228 <semEnabled>
  4018e5:	00 00 00 
  4018e8:	48 83 c4 08          	add    $0x8,%rsp
  4018ec:	f3 c3                	repz retq 
  4018ee:	66 90                	xchg   %ax,%ax
  4018f0:	c7 05 66 29 20 00 01 	movl   $0x1,0x202966(%rip)        # 604260 <pthread_initialization>
  4018f7:	00 00 00 
  4018fa:	e9 31 fc ff ff       	jmpq   401530 <initialize>
  4018ff:	90                   	nop

0000000000401900 <memalign>:
  401900:	53                   	push   %rbx
  401901:	48 83 ec 10          	sub    $0x10,%rsp
  401905:	48 83 3d 83 29 20 00 	cmpq   $0x0,0x202983(%rip)        # 604290 <allocationList>
  40190c:	00 
  40190d:	74 51                	je     401960 <memalign+0x60>
  40190f:	8b 15 13 29 20 00    	mov    0x202913(%rip),%edx        # 604228 <semEnabled>
  401915:	85 d2                	test   %edx,%edx
  401917:	75 27                	jne    401940 <memalign+0x40>
  401919:	e8 92 f7 ff ff       	callq  4010b0 <memalign_locked>
  40191e:	48 89 c3             	mov    %rax,%rbx
  401921:	8b 05 01 29 20 00    	mov    0x202901(%rip),%eax        # 604228 <semEnabled>
  401927:	85 c0                	test   %eax,%eax
  401929:	74 07                	je     401932 <memalign+0x32>
  40192b:	31 c0                	xor    %eax,%eax
  40192d:	e8 be fb ff ff       	callq  4014f0 <release.part.1>
  401932:	48 83 c4 10          	add    $0x10,%rsp
  401936:	48 89 d8             	mov    %rbx,%rax
  401939:	5b                   	pop    %rbx
  40193a:	c3                   	retq   
  40193b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  401940:	31 c0                	xor    %eax,%eax
  401942:	48 89 74 24 08       	mov    %rsi,0x8(%rsp)
  401947:	48 89 3c 24          	mov    %rdi,(%rsp)
  40194b:	e8 80 fb ff ff       	callq  4014d0 <lock.part.0>
  401950:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
  401955:	48 8b 3c 24          	mov    (%rsp),%rdi
  401959:	eb be                	jmp    401919 <memalign+0x19>
  40195b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  401960:	48 89 74 24 08       	mov    %rsi,0x8(%rsp)
  401965:	48 89 3c 24          	mov    %rdi,(%rsp)
  401969:	e8 c2 fb ff ff       	callq  401530 <initialize>
  40196e:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
  401973:	48 8b 3c 24          	mov    (%rsp),%rdi
  401977:	eb 96                	jmp    40190f <memalign+0xf>
  401979:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000401980 <posix_memalign>:
  401980:	48 8d 4e ff          	lea    -0x1(%rsi),%rcx
  401984:	53                   	push   %rbx
  401985:	b8 16 00 00 00       	mov    $0x16,%eax
  40198a:	48 89 fb             	mov    %rdi,%rbx
  40198d:	48 89 f7             	mov    %rsi,%rdi
  401990:	48 83 c9 07          	or     $0x7,%rcx
  401994:	48 85 f1             	test   %rsi,%rcx
  401997:	74 07                	je     4019a0 <posix_memalign+0x20>
  401999:	5b                   	pop    %rbx
  40199a:	c3                   	retq   
  40199b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  4019a0:	48 89 d6             	mov    %rdx,%rsi
  4019a3:	e8 58 ff ff ff       	callq  401900 <memalign>
  4019a8:	48 89 c2             	mov    %rax,%rdx
  4019ab:	b8 0c 00 00 00       	mov    $0xc,%eax
  4019b0:	48 85 d2             	test   %rdx,%rdx
  4019b3:	74 e4                	je     401999 <posix_memalign+0x19>
  4019b5:	48 89 13             	mov    %rdx,(%rbx)
  4019b8:	30 c0                	xor    %al,%al
  4019ba:	5b                   	pop    %rbx
  4019bb:	c3                   	retq   
  4019bc:	0f 1f 40 00          	nopl   0x0(%rax)

00000000004019c0 <free>:
  4019c0:	48 85 ff             	test   %rdi,%rdi
  4019c3:	53                   	push   %rbx
  4019c4:	48 89 fb             	mov    %rdi,%rbx
  4019c7:	74 26                	je     4019ef <free+0x2f>
  4019c9:	48 83 3d bf 28 20 00 	cmpq   $0x0,0x2028bf(%rip)        # 604290 <allocationList>
  4019d0:	00 
  4019d1:	74 3d                	je     401a10 <free+0x50>
  4019d3:	8b 15 4f 28 20 00    	mov    0x20284f(%rip),%edx        # 604228 <semEnabled>
  4019d9:	85 d2                	test   %edx,%edx
  4019db:	75 23                	jne    401a00 <free+0x40>
  4019dd:	48 89 df             	mov    %rbx,%rdi
  4019e0:	e8 8b f4 ff ff       	callq  400e70 <free_locked>
  4019e5:	8b 05 3d 28 20 00    	mov    0x20283d(%rip),%eax        # 604228 <semEnabled>
  4019eb:	85 c0                	test   %eax,%eax
  4019ed:	75 09                	jne    4019f8 <free+0x38>
  4019ef:	5b                   	pop    %rbx
  4019f0:	c3                   	retq   
  4019f1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  4019f8:	5b                   	pop    %rbx
  4019f9:	31 c0                	xor    %eax,%eax
  4019fb:	e9 f0 fa ff ff       	jmpq   4014f0 <release.part.1>
  401a00:	31 c0                	xor    %eax,%eax
  401a02:	e8 c9 fa ff ff       	callq  4014d0 <lock.part.0>
  401a07:	eb d4                	jmp    4019dd <free+0x1d>
  401a09:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  401a10:	48 8d 3d a9 0b 00 00 	lea    0xba9(%rip),%rdi        # 4025c0 <__dso_handle+0x78>
  401a17:	31 c0                	xor    %eax,%eax
  401a19:	e8 f2 06 00 00       	callq  402110 <EF_Abort>
  401a1e:	eb b3                	jmp    4019d3 <free+0x13>

0000000000401a20 <realloc>:
  401a20:	41 55                	push   %r13
  401a22:	41 54                	push   %r12
  401a24:	55                   	push   %rbp
  401a25:	48 89 f5             	mov    %rsi,%rbp
  401a28:	53                   	push   %rbx
  401a29:	48 89 fb             	mov    %rdi,%rbx
  401a2c:	48 83 ec 08          	sub    $0x8,%rsp
  401a30:	48 83 3d 58 28 20 00 	cmpq   $0x0,0x202858(%rip)        # 604290 <allocationList>
  401a37:	00 
  401a38:	0f 84 3e 01 00 00    	je     401b7c <realloc+0x15c>
  401a3e:	8b 15 e4 27 20 00    	mov    0x2027e4(%rip),%edx        # 604228 <semEnabled>
  401a44:	85 d2                	test   %edx,%edx
  401a46:	0f 85 24 01 00 00    	jne    401b70 <realloc+0x150>
  401a4c:	48 8d 05 a1 26 20 00 	lea    0x2026a1(%rip),%rax        # 6040f4 <EF_ALIGNMENT>
  401a53:	48 89 ee             	mov    %rbp,%rsi
  401a56:	48 63 38             	movslq (%rax),%rdi
  401a59:	e8 52 f6 ff ff       	callq  4010b0 <memalign_locked>
  401a5e:	48 85 db             	test   %rbx,%rbx
  401a61:	49 89 c4             	mov    %rax,%r12
  401a64:	0f 84 83 00 00 00    	je     401aed <realloc+0xcd>
  401a6a:	48 8b 35 17 28 20 00 	mov    0x202817(%rip),%rsi        # 604288 <allocationListSize>
  401a71:	48 8b 3d 18 28 20 00 	mov    0x202818(%rip),%rdi        # 604290 <allocationList>
  401a78:	e8 43 02 00 00       	callq  401cc0 <Page_AllowAccess>
  401a7d:	48 8b 0d fc 27 20 00 	mov    0x2027fc(%rip),%rcx        # 604280 <slotCount>
  401a84:	c7 05 d6 27 20 00 01 	movl   $0x1,0x2027d6(%rip)        # 604264 <noAllocationListProtection>
  401a8b:	00 00 00 
  401a8e:	4c 8b 05 fb 27 20 00 	mov    0x2027fb(%rip),%r8        # 604290 <allocationList>
  401a95:	48 85 c9             	test   %rcx,%rcx
  401a98:	75 14                	jne    401aae <realloc+0x8e>
  401a9a:	e9 a1 00 00 00       	jmpq   401b40 <realloc+0x120>
  401a9f:	90                   	nop
  401aa0:	49 83 c0 28          	add    $0x28,%r8
  401aa4:	48 83 e9 01          	sub    $0x1,%rcx
  401aa8:	0f 84 92 00 00 00    	je     401b40 <realloc+0x120>
  401aae:	49 3b 18             	cmp    (%r8),%rbx
  401ab1:	75 ed                	jne    401aa0 <realloc+0x80>
  401ab3:	4d 8b 68 10          	mov    0x10(%r8),%r13
  401ab7:	4c 39 ed             	cmp    %r13,%rbp
  401aba:	4c 0f 46 ed          	cmovbe %rbp,%r13
  401abe:	4d 85 ed             	test   %r13,%r13
  401ac1:	75 65                	jne    401b28 <realloc+0x108>
  401ac3:	48 89 df             	mov    %rbx,%rdi
  401ac6:	e8 a5 f3 ff ff       	callq  400e70 <free_locked>
  401acb:	48 8b 35 b6 27 20 00 	mov    0x2027b6(%rip),%rsi        # 604288 <allocationListSize>
  401ad2:	48 8b 3d b7 27 20 00 	mov    0x2027b7(%rip),%rdi        # 604290 <allocationList>
  401ad9:	c7 05 81 27 20 00 00 	movl   $0x0,0x202781(%rip)        # 604264 <noAllocationListProtection>
  401ae0:	00 00 00 
  401ae3:	e8 18 02 00 00       	callq  401d00 <Page_DenyAccess>
  401ae8:	4c 39 ed             	cmp    %r13,%rbp
  401aeb:	77 23                	ja     401b10 <realloc+0xf0>
  401aed:	8b 05 35 27 20 00    	mov    0x202735(%rip),%eax        # 604228 <semEnabled>
  401af3:	85 c0                	test   %eax,%eax
  401af5:	74 07                	je     401afe <realloc+0xde>
  401af7:	31 c0                	xor    %eax,%eax
  401af9:	e8 f2 f9 ff ff       	callq  4014f0 <release.part.1>
  401afe:	48 83 c4 08          	add    $0x8,%rsp
  401b02:	4c 89 e0             	mov    %r12,%rax
  401b05:	5b                   	pop    %rbx
  401b06:	5d                   	pop    %rbp
  401b07:	41 5c                	pop    %r12
  401b09:	41 5d                	pop    %r13
  401b0b:	c3                   	retq   
  401b0c:	0f 1f 40 00          	nopl   0x0(%rax)
  401b10:	48 89 ea             	mov    %rbp,%rdx
  401b13:	4b 8d 3c 2c          	lea    (%r12,%r13,1),%rdi
  401b17:	31 f6                	xor    %esi,%esi
  401b19:	4c 29 ea             	sub    %r13,%rdx
  401b1c:	e8 df f0 ff ff       	callq  400c00 <memset@plt>
  401b21:	eb ca                	jmp    401aed <realloc+0xcd>
  401b23:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  401b28:	4c 89 ea             	mov    %r13,%rdx
  401b2b:	48 89 de             	mov    %rbx,%rsi
  401b2e:	4c 89 e7             	mov    %r12,%rdi
  401b31:	e8 0a f2 ff ff       	callq  400d40 <memcpy@plt>
  401b36:	eb 8b                	jmp    401ac3 <realloc+0xa3>
  401b38:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  401b3f:	00 
  401b40:	48 8d 3d a1 0a 00 00 	lea    0xaa1(%rip),%rdi        # 4025e8 <__dso_handle+0xa0>
  401b47:	31 c0                	xor    %eax,%eax
  401b49:	48 89 ea             	mov    %rbp,%rdx
  401b4c:	48 89 de             	mov    %rbx,%rsi
  401b4f:	e8 bc 05 00 00       	callq  402110 <EF_Abort>
  401b54:	45 31 c0             	xor    %r8d,%r8d
  401b57:	4d 8b 68 10          	mov    0x10(%r8),%r13
  401b5b:	4c 39 ed             	cmp    %r13,%rbp
  401b5e:	4c 0f 46 ed          	cmovbe %rbp,%r13
  401b62:	4d 85 ed             	test   %r13,%r13
  401b65:	0f 84 58 ff ff ff    	je     401ac3 <realloc+0xa3>
  401b6b:	eb bb                	jmp    401b28 <realloc+0x108>
  401b6d:	0f 1f 00             	nopl   (%rax)
  401b70:	31 c0                	xor    %eax,%eax
  401b72:	e8 59 f9 ff ff       	callq  4014d0 <lock.part.0>
  401b77:	e9 d0 fe ff ff       	jmpq   401a4c <realloc+0x2c>
  401b7c:	0f 1f 40 00          	nopl   0x0(%rax)
  401b80:	e8 ab f9 ff ff       	callq  401530 <initialize>
  401b85:	e9 b4 fe ff ff       	jmpq   401a3e <realloc+0x1e>
  401b8a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000401b90 <malloc>:
  401b90:	48 83 3d f8 26 20 00 	cmpq   $0x0,0x2026f8(%rip)        # 604290 <allocationList>
  401b97:	00 
  401b98:	48 89 fe             	mov    %rdi,%rsi
  401b9b:	74 13                	je     401bb0 <malloc+0x20>
  401b9d:	48 8d 05 50 25 20 00 	lea    0x202550(%rip),%rax        # 6040f4 <EF_ALIGNMENT>
  401ba4:	48 63 38             	movslq (%rax),%rdi
  401ba7:	e9 54 fd ff ff       	jmpq   401900 <memalign>
  401bac:	0f 1f 40 00          	nopl   0x0(%rax)
  401bb0:	48 83 ec 18          	sub    $0x18,%rsp
  401bb4:	48 89 7c 24 08       	mov    %rdi,0x8(%rsp)
  401bb9:	e8 72 f9 ff ff       	callq  401530 <initialize>
  401bbe:	48 8d 05 2f 25 20 00 	lea    0x20252f(%rip),%rax        # 6040f4 <EF_ALIGNMENT>
  401bc5:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
  401bca:	48 63 38             	movslq (%rax),%rdi
  401bcd:	48 83 c4 18          	add    $0x18,%rsp
  401bd1:	e9 2a fd ff ff       	jmpq   401900 <memalign>
  401bd6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  401bdd:	00 00 00 

0000000000401be0 <calloc>:
  401be0:	55                   	push   %rbp
  401be1:	53                   	push   %rbx
  401be2:	48 89 fb             	mov    %rdi,%rbx
  401be5:	48 0f af de          	imul   %rsi,%rbx
  401be9:	48 83 ec 08          	sub    $0x8,%rsp
  401bed:	48 89 df             	mov    %rbx,%rdi
  401bf0:	e8 9b ff ff ff       	callq  401b90 <malloc>
  401bf5:	48 89 da             	mov    %rbx,%rdx
  401bf8:	31 f6                	xor    %esi,%esi
  401bfa:	48 89 c7             	mov    %rax,%rdi
  401bfd:	48 89 c5             	mov    %rax,%rbp
  401c00:	e8 fb ef ff ff       	callq  400c00 <memset@plt>
  401c05:	48 83 c4 08          	add    $0x8,%rsp
  401c09:	48 89 e8             	mov    %rbp,%rax
  401c0c:	5b                   	pop    %rbx
  401c0d:	5d                   	pop    %rbp
  401c0e:	c3                   	retq   
  401c0f:	90                   	nop

0000000000401c10 <valloc>:
  401c10:	48 89 fe             	mov    %rdi,%rsi
  401c13:	48 8b 3d 06 26 20 00 	mov    0x202606(%rip),%rdi        # 604220 <bytesPerPage>
  401c1a:	e9 e1 fc ff ff       	jmpq   401900 <memalign>
  401c1f:	90                   	nop

0000000000401c20 <stringErrorReport>:
  401c20:	48 81 ec 88 00 00 00 	sub    $0x88,%rsp
  401c27:	e8 a4 f0 ff ff       	callq  400cd0 <__errno_location@plt>
  401c2c:	8b 38                	mov    (%rax),%edi
  401c2e:	48 89 e6             	mov    %rsp,%rsi
  401c31:	ba 80 00 00 00       	mov    $0x80,%edx
  401c36:	e8 b5 f0 ff ff       	callq  400cf0 <__xpg_strerror_r@plt>
  401c3b:	48 81 c4 88 00 00 00 	add    $0x88,%rsp
  401c42:	48 98                	cltq   
  401c44:	c3                   	retq   
  401c45:	90                   	nop
  401c46:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  401c4d:	00 00 00 

0000000000401c50 <Page_Create>:
  401c50:	55                   	push   %rbp
  401c51:	48 63 f7             	movslq %edi,%rsi
  401c54:	48 89 fd             	mov    %rdi,%rbp
  401c57:	45 31 c9             	xor    %r9d,%r9d
  401c5a:	41 b8 ff ff ff ff    	mov    $0xffffffff,%r8d
  401c60:	b9 22 00 00 00       	mov    $0x22,%ecx
  401c65:	53                   	push   %rbx
  401c66:	ba 03 00 00 00       	mov    $0x3,%edx
  401c6b:	48 83 ec 08          	sub    $0x8,%rsp
  401c6f:	48 8b 3d 22 26 20 00 	mov    0x202622(%rip),%rdi        # 604298 <startAddr>
  401c76:	e8 d5 f0 ff ff       	callq  400d50 <mmap@plt>
  401c7b:	48 01 c5             	add    %rax,%rbp
  401c7e:	48 83 f8 ff          	cmp    $0xffffffffffffffff,%rax
  401c82:	48 89 c3             	mov    %rax,%rbx
  401c85:	48 89 2d 0c 26 20 00 	mov    %rbp,0x20260c(%rip)        # 604298 <startAddr>
  401c8c:	74 12                	je     401ca0 <Page_Create+0x50>
  401c8e:	48 83 c4 08          	add    $0x8,%rsp
  401c92:	48 89 d8             	mov    %rbx,%rax
  401c95:	5b                   	pop    %rbx
  401c96:	5d                   	pop    %rbp
  401c97:	c3                   	retq   
  401c98:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  401c9f:	00 
  401ca0:	e8 7b ff ff ff       	callq  401c20 <stringErrorReport>
  401ca5:	48 8d 3d 63 0a 00 00 	lea    0xa63(%rip),%rdi        # 40270f <version+0x4f>
  401cac:	48 89 c6             	mov    %rax,%rsi
  401caf:	31 c0                	xor    %eax,%eax
  401cb1:	e8 da 05 00 00       	callq  402290 <EF_Exit>
  401cb6:	48 83 c4 08          	add    $0x8,%rsp
  401cba:	48 89 d8             	mov    %rbx,%rax
  401cbd:	5b                   	pop    %rbx
  401cbe:	5d                   	pop    %rbp
  401cbf:	c3                   	retq   

0000000000401cc0 <Page_AllowAccess>:
  401cc0:	48 83 ec 08          	sub    $0x8,%rsp
  401cc4:	ba 03 00 00 00       	mov    $0x3,%edx
  401cc9:	e8 12 ef ff ff       	callq  400be0 <mprotect@plt>
  401cce:	85 c0                	test   %eax,%eax
  401cd0:	78 0e                	js     401ce0 <Page_AllowAccess+0x20>
  401cd2:	48 83 c4 08          	add    $0x8,%rsp
  401cd6:	c3                   	retq   
  401cd7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  401cde:	00 00 
  401ce0:	e8 3b ff ff ff       	callq  401c20 <stringErrorReport>
  401ce5:	48 8d 3d 35 0a 00 00 	lea    0xa35(%rip),%rdi        # 402721 <version+0x61>
  401cec:	48 89 c6             	mov    %rax,%rsi
  401cef:	48 83 c4 08          	add    $0x8,%rsp
  401cf3:	31 c0                	xor    %eax,%eax
  401cf5:	e9 96 05 00 00       	jmpq   402290 <EF_Exit>
  401cfa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000401d00 <Page_DenyAccess>:
  401d00:	48 83 ec 08          	sub    $0x8,%rsp
  401d04:	31 d2                	xor    %edx,%edx
  401d06:	e8 d5 ee ff ff       	callq  400be0 <mprotect@plt>
  401d0b:	85 c0                	test   %eax,%eax
  401d0d:	78 09                	js     401d18 <Page_DenyAccess+0x18>
  401d0f:	48 83 c4 08          	add    $0x8,%rsp
  401d13:	c3                   	retq   
  401d14:	0f 1f 40 00          	nopl   0x0(%rax)
  401d18:	e8 03 ff ff ff       	callq  401c20 <stringErrorReport>
  401d1d:	48 8d 3d fd 09 00 00 	lea    0x9fd(%rip),%rdi        # 402721 <version+0x61>
  401d24:	48 89 c6             	mov    %rax,%rsi
  401d27:	48 83 c4 08          	add    $0x8,%rsp
  401d2b:	31 c0                	xor    %eax,%eax
  401d2d:	e9 5e 05 00 00       	jmpq   402290 <EF_Exit>
  401d32:	0f 1f 40 00          	nopl   0x0(%rax)
  401d36:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  401d3d:	00 00 00 

0000000000401d40 <Page_Delete>:
  401d40:	55                   	push   %rbp
  401d41:	48 89 f5             	mov    %rsi,%rbp
  401d44:	53                   	push   %rbx
  401d45:	48 89 fb             	mov    %rdi,%rbx
  401d48:	48 83 ec 08          	sub    $0x8,%rsp
  401d4c:	e8 af ff ff ff       	callq  401d00 <Page_DenyAccess>
  401d51:	48 83 c4 08          	add    $0x8,%rsp
  401d55:	48 89 df             	mov    %rbx,%rdi
  401d58:	48 89 ee             	mov    %rbp,%rsi
  401d5b:	5b                   	pop    %rbx
  401d5c:	5d                   	pop    %rbp
  401d5d:	ba 04 00 00 00       	mov    $0x4,%edx
  401d62:	e9 79 ef ff ff       	jmpq   400ce0 <madvise@plt>
  401d67:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  401d6e:	00 00 

0000000000401d70 <Page_Size>:
  401d70:	bf 1e 00 00 00       	mov    $0x1e,%edi
  401d75:	e9 d6 ee ff ff       	jmpq   400c50 <sysconf@plt>
  401d7a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000401d80 <do_abort>:
  401d80:	48 83 ec 08          	sub    $0x8,%rsp
  401d84:	e8 d7 ee ff ff       	callq  400c60 <getpid@plt>
  401d89:	be 04 00 00 00       	mov    $0x4,%esi
  401d8e:	89 c7                	mov    %eax,%edi
  401d90:	e8 0b ef ff ff       	callq  400ca0 <kill@plt>
  401d95:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  401d9a:	e8 91 ee ff ff       	callq  400c30 <_exit@plt>
  401d9f:	90                   	nop

0000000000401da0 <EF_Print>:
  401da0:	48 81 ec d8 00 00 00 	sub    $0xd8,%rsp
  401da7:	84 c0                	test   %al,%al
  401da9:	48 89 74 24 28       	mov    %rsi,0x28(%rsp)
  401dae:	48 89 54 24 30       	mov    %rdx,0x30(%rsp)
  401db3:	48 89 4c 24 38       	mov    %rcx,0x38(%rsp)
  401db8:	4c 89 44 24 40       	mov    %r8,0x40(%rsp)
  401dbd:	4c 89 4c 24 48       	mov    %r9,0x48(%rsp)
  401dc2:	74 37                	je     401dfb <EF_Print+0x5b>
  401dc4:	0f 29 44 24 50       	movaps %xmm0,0x50(%rsp)
  401dc9:	0f 29 4c 24 60       	movaps %xmm1,0x60(%rsp)
  401dce:	0f 29 54 24 70       	movaps %xmm2,0x70(%rsp)
  401dd3:	0f 29 9c 24 80 00 00 	movaps %xmm3,0x80(%rsp)
  401dda:	00 
  401ddb:	0f 29 a4 24 90 00 00 	movaps %xmm4,0x90(%rsp)
  401de2:	00 
  401de3:	0f 29 ac 24 a0 00 00 	movaps %xmm5,0xa0(%rsp)
  401dea:	00 
  401deb:	0f 29 b4 24 b0 00 00 	movaps %xmm6,0xb0(%rsp)
  401df2:	00 
  401df3:	0f 29 bc 24 c0 00 00 	movaps %xmm7,0xc0(%rsp)
  401dfa:	00 
  401dfb:	48 8d 84 24 e0 00 00 	lea    0xe0(%rsp),%rax
  401e02:	00 
  401e03:	48 8d 74 24 08       	lea    0x8(%rsp),%rsi
  401e08:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
  401e0d:	48 8d 44 24 20       	lea    0x20(%rsp),%rax
  401e12:	c7 44 24 08 08 00 00 	movl   $0x8,0x8(%rsp)
  401e19:	00 
  401e1a:	c7 44 24 0c 30 00 00 	movl   $0x30,0xc(%rsp)
  401e21:	00 
  401e22:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
  401e27:	e8 14 00 00 00       	callq  401e40 <EF_Printv>
  401e2c:	48 81 c4 d8 00 00 00 	add    $0xd8,%rsp
  401e33:	c3                   	retq   
  401e34:	66 90                	xchg   %ax,%ax
  401e36:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  401e3d:	00 00 00 

0000000000401e40 <EF_Printv>:
  401e40:	41 56                	push   %r14
  401e42:	41 55                	push   %r13
  401e44:	41 54                	push   %r12
  401e46:	55                   	push   %rbp
  401e47:	48 89 f5             	mov    %rsi,%rbp
  401e4a:	53                   	push   %rbx
  401e4b:	48 89 fb             	mov    %rdi,%rbx
  401e4e:	48 83 ec 10          	sub    $0x10,%rsp
  401e52:	4c 8d 64 24 0e       	lea    0xe(%rsp),%r12
  401e57:	4c 8d 6c 24 0f       	lea    0xf(%rsp),%r13
  401e5c:	0f 1f 40 00          	nopl   0x0(%rax)
  401e60:	0f b6 03             	movzbl (%rbx),%eax
  401e63:	84 c0                	test   %al,%al
  401e65:	88 44 24 0e          	mov    %al,0xe(%rsp)
  401e69:	74 55                	je     401ec0 <EF_Printv+0x80>
  401e6b:	3c 25                	cmp    $0x25,%al
  401e6d:	75 61                	jne    401ed0 <EF_Printv+0x90>
  401e6f:	0f b6 43 01          	movzbl 0x1(%rbx),%eax
  401e73:	4c 8d 73 02          	lea    0x2(%rbx),%r14
  401e77:	3c 63                	cmp    $0x63,%al
  401e79:	88 44 24 0e          	mov    %al,0xe(%rsp)
  401e7d:	0f 84 ad 00 00 00    	je     401f30 <EF_Printv+0xf0>
  401e83:	7e 6b                	jle    401ef0 <EF_Printv+0xb0>
  401e85:	3c 73                	cmp    $0x73,%al
  401e87:	0f 84 53 01 00 00    	je     401fe0 <EF_Printv+0x1a0>
  401e8d:	3c 78                	cmp    $0x78,%al
  401e8f:	90                   	nop
  401e90:	0f 84 1a 01 00 00    	je     401fb0 <EF_Printv+0x170>
  401e96:	3c 64                	cmp    $0x64,%al
  401e98:	0f 84 d2 00 00 00    	je     401f70 <EF_Printv+0x130>
  401e9e:	48 8d 3d 1b 09 00 00 	lea    0x91b(%rip),%rdi        # 4027c0 <bad_pattern.3666>
  401ea5:	0f be f0             	movsbl %al,%esi
  401ea8:	4c 89 f3             	mov    %r14,%rbx
  401eab:	31 c0                	xor    %eax,%eax
  401ead:	e8 ee fe ff ff       	callq  401da0 <EF_Print>
  401eb2:	0f b6 03             	movzbl (%rbx),%eax
  401eb5:	84 c0                	test   %al,%al
  401eb7:	88 44 24 0e          	mov    %al,0xe(%rsp)
  401ebb:	75 ae                	jne    401e6b <EF_Printv+0x2b>
  401ebd:	0f 1f 00             	nopl   (%rax)
  401ec0:	48 83 c4 10          	add    $0x10,%rsp
  401ec4:	5b                   	pop    %rbx
  401ec5:	5d                   	pop    %rbp
  401ec6:	41 5c                	pop    %r12
  401ec8:	41 5d                	pop    %r13
  401eca:	41 5e                	pop    %r14
  401ecc:	c3                   	retq   
  401ecd:	0f 1f 00             	nopl   (%rax)
  401ed0:	ba 01 00 00 00       	mov    $0x1,%edx
  401ed5:	4c 89 e6             	mov    %r12,%rsi
  401ed8:	bf 02 00 00 00       	mov    $0x2,%edi
  401edd:	48 83 c3 01          	add    $0x1,%rbx
  401ee1:	e8 4a ee ff ff       	callq  400d30 <write@plt>
  401ee6:	e9 75 ff ff ff       	jmpq   401e60 <EF_Printv+0x20>
  401eeb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  401ef0:	3c 25                	cmp    $0x25,%al
  401ef2:	0f 84 28 01 00 00    	je     402020 <EF_Printv+0x1e0>
  401ef8:	3c 61                	cmp    $0x61,%al
  401efa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  401f00:	75 9c                	jne    401e9e <EF_Printv+0x5e>
  401f02:	8b 45 00             	mov    0x0(%rbp),%eax
  401f05:	83 f8 30             	cmp    $0x30,%eax
  401f08:	0f 83 8a 01 00 00    	jae    402098 <EF_Printv+0x258>
  401f0e:	89 c2                	mov    %eax,%edx
  401f10:	48 03 55 10          	add    0x10(%rbp),%rdx
  401f14:	83 c0 08             	add    $0x8,%eax
  401f17:	89 45 00             	mov    %eax,0x0(%rbp)
  401f1a:	48 8b 3a             	mov    (%rdx),%rdi
  401f1d:	be 10 00 00 00       	mov    $0x10,%esi
  401f22:	4c 89 f3             	mov    %r14,%rbx
  401f25:	e8 86 02 00 00       	callq  4021b0 <printNumber>
  401f2a:	e9 31 ff ff ff       	jmpq   401e60 <EF_Printv+0x20>
  401f2f:	90                   	nop
  401f30:	8b 45 00             	mov    0x0(%rbp),%eax
  401f33:	83 f8 30             	cmp    $0x30,%eax
  401f36:	0f 83 44 01 00 00    	jae    402080 <EF_Printv+0x240>
  401f3c:	89 c2                	mov    %eax,%edx
  401f3e:	48 03 55 10          	add    0x10(%rbp),%rdx
  401f42:	83 c0 08             	add    $0x8,%eax
  401f45:	89 45 00             	mov    %eax,0x0(%rbp)
  401f48:	8b 02                	mov    (%rdx),%eax
  401f4a:	4c 89 ee             	mov    %r13,%rsi
  401f4d:	ba 01 00 00 00       	mov    $0x1,%edx
  401f52:	bf 02 00 00 00       	mov    $0x2,%edi
  401f57:	4c 89 f3             	mov    %r14,%rbx
  401f5a:	88 44 24 0f          	mov    %al,0xf(%rsp)
  401f5e:	e8 cd ed ff ff       	callq  400d30 <write@plt>
  401f63:	e9 f8 fe ff ff       	jmpq   401e60 <EF_Printv+0x20>
  401f68:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  401f6f:	00 
  401f70:	8b 45 00             	mov    0x0(%rbp),%eax
  401f73:	83 f8 30             	cmp    $0x30,%eax
  401f76:	0f 83 ec 00 00 00    	jae    402068 <EF_Printv+0x228>
  401f7c:	89 c2                	mov    %eax,%edx
  401f7e:	48 03 55 10          	add    0x10(%rbp),%rdx
  401f82:	83 c0 08             	add    $0x8,%eax
  401f85:	89 45 00             	mov    %eax,0x0(%rbp)
  401f88:	8b 1a                	mov    (%rdx),%ebx
  401f8a:	85 db                	test   %ebx,%ebx
  401f8c:	0f 88 17 01 00 00    	js     4020a9 <EF_Printv+0x269>
  401f92:	48 63 fb             	movslq %ebx,%rdi
  401f95:	be 0a 00 00 00       	mov    $0xa,%esi
  401f9a:	4c 89 f3             	mov    %r14,%rbx
  401f9d:	e8 0e 02 00 00       	callq  4021b0 <printNumber>
  401fa2:	e9 b9 fe ff ff       	jmpq   401e60 <EF_Printv+0x20>
  401fa7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  401fae:	00 00 
  401fb0:	8b 45 00             	mov    0x0(%rbp),%eax
  401fb3:	83 f8 30             	cmp    $0x30,%eax
  401fb6:	0f 83 94 00 00 00    	jae    402050 <EF_Printv+0x210>
  401fbc:	89 c2                	mov    %eax,%edx
  401fbe:	48 03 55 10          	add    0x10(%rbp),%rdx
  401fc2:	83 c0 08             	add    $0x8,%eax
  401fc5:	89 45 00             	mov    %eax,0x0(%rbp)
  401fc8:	8b 3a                	mov    (%rdx),%edi
  401fca:	be 10 00 00 00       	mov    $0x10,%esi
  401fcf:	4c 89 f3             	mov    %r14,%rbx
  401fd2:	e8 d9 01 00 00       	callq  4021b0 <printNumber>
  401fd7:	e9 84 fe ff ff       	jmpq   401e60 <EF_Printv+0x20>
  401fdc:	0f 1f 40 00          	nopl   0x0(%rax)
  401fe0:	8b 45 00             	mov    0x0(%rbp),%eax
  401fe3:	83 f8 30             	cmp    $0x30,%eax
  401fe6:	73 58                	jae    402040 <EF_Printv+0x200>
  401fe8:	89 c2                	mov    %eax,%edx
  401fea:	48 03 55 10          	add    0x10(%rbp),%rdx
  401fee:	83 c0 08             	add    $0x8,%eax
  401ff1:	89 45 00             	mov    %eax,0x0(%rbp)
  401ff4:	48 8b 1a             	mov    (%rdx),%rbx
  401ff7:	48 89 df             	mov    %rbx,%rdi
  401ffa:	e8 91 ec ff ff       	callq  400c90 <strlen@plt>
  401fff:	48 89 de             	mov    %rbx,%rsi
  402002:	48 89 c2             	mov    %rax,%rdx
  402005:	bf 02 00 00 00       	mov    $0x2,%edi
  40200a:	e8 21 ed ff ff       	callq  400d30 <write@plt>
  40200f:	4c 89 f3             	mov    %r14,%rbx
  402012:	e9 49 fe ff ff       	jmpq   401e60 <EF_Printv+0x20>
  402017:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  40201e:	00 00 
  402020:	ba 01 00 00 00       	mov    $0x1,%edx
  402025:	4c 89 e6             	mov    %r12,%rsi
  402028:	bf 02 00 00 00       	mov    $0x2,%edi
  40202d:	e8 fe ec ff ff       	callq  400d30 <write@plt>
  402032:	4c 89 f3             	mov    %r14,%rbx
  402035:	e9 26 fe ff ff       	jmpq   401e60 <EF_Printv+0x20>
  40203a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  402040:	48 8b 55 08          	mov    0x8(%rbp),%rdx
  402044:	48 8d 42 08          	lea    0x8(%rdx),%rax
  402048:	48 89 45 08          	mov    %rax,0x8(%rbp)
  40204c:	eb a6                	jmp    401ff4 <EF_Printv+0x1b4>
  40204e:	66 90                	xchg   %ax,%ax
  402050:	48 8b 55 08          	mov    0x8(%rbp),%rdx
  402054:	48 8d 42 08          	lea    0x8(%rdx),%rax
  402058:	48 89 45 08          	mov    %rax,0x8(%rbp)
  40205c:	e9 67 ff ff ff       	jmpq   401fc8 <EF_Printv+0x188>
  402061:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  402068:	48 8b 55 08          	mov    0x8(%rbp),%rdx
  40206c:	48 8d 42 08          	lea    0x8(%rdx),%rax
  402070:	48 89 45 08          	mov    %rax,0x8(%rbp)
  402074:	e9 0f ff ff ff       	jmpq   401f88 <EF_Printv+0x148>
  402079:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  402080:	48 8b 55 08          	mov    0x8(%rbp),%rdx
  402084:	48 8d 42 08          	lea    0x8(%rdx),%rax
  402088:	48 89 45 08          	mov    %rax,0x8(%rbp)
  40208c:	e9 b7 fe ff ff       	jmpq   401f48 <EF_Printv+0x108>
  402091:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  402098:	48 8b 55 08          	mov    0x8(%rbp),%rdx
  40209c:	48 8d 42 08          	lea    0x8(%rdx),%rax
  4020a0:	48 89 45 08          	mov    %rax,0x8(%rbp)
  4020a4:	e9 71 fe ff ff       	jmpq   401f1a <EF_Printv+0xda>
  4020a9:	ba 01 00 00 00       	mov    $0x1,%edx
  4020ae:	4c 89 ee             	mov    %r13,%rsi
  4020b1:	bf 02 00 00 00       	mov    $0x2,%edi
  4020b6:	c6 44 24 0f 2d       	movb   $0x2d,0xf(%rsp)
  4020bb:	f7 db                	neg    %ebx
  4020bd:	e8 6e ec ff ff       	callq  400d30 <write@plt>
  4020c2:	e9 cb fe ff ff       	jmpq   401f92 <EF_Printv+0x152>
  4020c7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  4020ce:	00 00 

00000000004020d0 <EF_Abortv>:
  4020d0:	55                   	push   %rbp
  4020d1:	31 c0                	xor    %eax,%eax
  4020d3:	48 89 f5             	mov    %rsi,%rbp
  4020d6:	53                   	push   %rbx
  4020d7:	48 89 fb             	mov    %rdi,%rbx
  4020da:	48 8d 3d 56 06 00 00 	lea    0x656(%rip),%rdi        # 402737 <version+0x77>
  4020e1:	48 83 ec 08          	sub    $0x8,%rsp
  4020e5:	e8 b6 fc ff ff       	callq  401da0 <EF_Print>
  4020ea:	48 89 ee             	mov    %rbp,%rsi
  4020ed:	48 89 df             	mov    %rbx,%rdi
  4020f0:	e8 4b fd ff ff       	callq  401e40 <EF_Printv>
  4020f5:	48 8d 3d 55 06 00 00 	lea    0x655(%rip),%rdi        # 402751 <version+0x91>
  4020fc:	31 c0                	xor    %eax,%eax
  4020fe:	e8 9d fc ff ff       	callq  401da0 <EF_Print>
  402103:	31 c0                	xor    %eax,%eax
  402105:	e8 76 fc ff ff       	callq  401d80 <do_abort>
  40210a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000402110 <EF_Abort>:
  402110:	48 81 ec d8 00 00 00 	sub    $0xd8,%rsp
  402117:	84 c0                	test   %al,%al
  402119:	48 89 74 24 28       	mov    %rsi,0x28(%rsp)
  40211e:	48 89 54 24 30       	mov    %rdx,0x30(%rsp)
  402123:	48 89 4c 24 38       	mov    %rcx,0x38(%rsp)
  402128:	4c 89 44 24 40       	mov    %r8,0x40(%rsp)
  40212d:	4c 89 4c 24 48       	mov    %r9,0x48(%rsp)
  402132:	74 37                	je     40216b <EF_Abort+0x5b>
  402134:	0f 29 44 24 50       	movaps %xmm0,0x50(%rsp)
  402139:	0f 29 4c 24 60       	movaps %xmm1,0x60(%rsp)
  40213e:	0f 29 54 24 70       	movaps %xmm2,0x70(%rsp)
  402143:	0f 29 9c 24 80 00 00 	movaps %xmm3,0x80(%rsp)
  40214a:	00 
  40214b:	0f 29 a4 24 90 00 00 	movaps %xmm4,0x90(%rsp)
  402152:	00 
  402153:	0f 29 ac 24 a0 00 00 	movaps %xmm5,0xa0(%rsp)
  40215a:	00 
  40215b:	0f 29 b4 24 b0 00 00 	movaps %xmm6,0xb0(%rsp)
  402162:	00 
  402163:	0f 29 bc 24 c0 00 00 	movaps %xmm7,0xc0(%rsp)
  40216a:	00 
  40216b:	48 8d 84 24 e0 00 00 	lea    0xe0(%rsp),%rax
  402172:	00 
  402173:	48 8d 74 24 08       	lea    0x8(%rsp),%rsi
  402178:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
  40217d:	48 8d 44 24 20       	lea    0x20(%rsp),%rax
  402182:	c7 44 24 08 08 00 00 	movl   $0x8,0x8(%rsp)
  402189:	00 
  40218a:	c7 44 24 0c 30 00 00 	movl   $0x30,0xc(%rsp)
  402191:	00 
  402192:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
  402197:	e8 34 ff ff ff       	callq  4020d0 <EF_Abortv>
  40219c:	48 81 c4 d8 00 00 00 	add    $0xd8,%rsp
  4021a3:	c3                   	retq   
  4021a4:	66 90                	xchg   %ax,%ax
  4021a6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4021ad:	00 00 00 

00000000004021b0 <printNumber>:
  4021b0:	41 55                	push   %r13
  4021b2:	41 54                	push   %r12
  4021b4:	55                   	push   %rbp
  4021b5:	48 89 f5             	mov    %rsi,%rbp
  4021b8:	53                   	push   %rbx
  4021b9:	48 89 fb             	mov    %rdi,%rbx
  4021bc:	48 83 ec 48          	sub    $0x48,%rsp
  4021c0:	49 89 e5             	mov    %rsp,%r13
  4021c3:	4c 8d 64 24 3f       	lea    0x3f(%rsp),%r12
  4021c8:	eb 26                	jmp    4021f0 <printNumber+0x40>
  4021ca:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  4021d0:	83 c2 30             	add    $0x30,%edx
  4021d3:	48 89 d8             	mov    %rbx,%rax
  4021d6:	41 88 14 24          	mov    %dl,(%r12)
  4021da:	31 d2                	xor    %edx,%edx
  4021dc:	48 f7 f5             	div    %rbp
  4021df:	48 85 c0             	test   %rax,%rax
  4021e2:	48 89 c3             	mov    %rax,%rbx
  4021e5:	74 2e                	je     402215 <printNumber+0x65>
  4021e7:	49 83 ec 01          	sub    $0x1,%r12
  4021eb:	4d 39 ec             	cmp    %r13,%r12
  4021ee:	74 50                	je     402240 <printNumber+0x90>
  4021f0:	31 d2                	xor    %edx,%edx
  4021f2:	48 89 d8             	mov    %rbx,%rax
  4021f5:	48 f7 f5             	div    %rbp
  4021f8:	48 83 fa 09          	cmp    $0x9,%rdx
  4021fc:	76 d2                	jbe    4021d0 <printNumber+0x20>
  4021fe:	83 c2 57             	add    $0x57,%edx
  402201:	48 89 d8             	mov    %rbx,%rax
  402204:	41 88 14 24          	mov    %dl,(%r12)
  402208:	31 d2                	xor    %edx,%edx
  40220a:	48 f7 f5             	div    %rbp
  40220d:	48 85 c0             	test   %rax,%rax
  402210:	48 89 c3             	mov    %rax,%rbx
  402213:	75 d2                	jne    4021e7 <printNumber+0x37>
  402215:	48 8d 54 24 40       	lea    0x40(%rsp),%rdx
  40221a:	4c 29 e2             	sub    %r12,%rdx
  40221d:	85 d2                	test   %edx,%edx
  40221f:	7e 10                	jle    402231 <printNumber+0x81>
  402221:	48 63 d2             	movslq %edx,%rdx
  402224:	4c 89 e6             	mov    %r12,%rsi
  402227:	bf 02 00 00 00       	mov    $0x2,%edi
  40222c:	e8 ff ea ff ff       	callq  400d30 <write@plt>
  402231:	48 83 c4 48          	add    $0x48,%rsp
  402235:	5b                   	pop    %rbx
  402236:	5d                   	pop    %rbp
  402237:	41 5c                	pop    %r12
  402239:	41 5d                	pop    %r13
  40223b:	c3                   	retq   
  40223c:	0f 1f 40 00          	nopl   0x0(%rax)
  402240:	48 8d 3d 29 05 00 00 	lea    0x529(%rip),%rdi        # 402770 <version+0xb0>
  402247:	31 c0                	xor    %eax,%eax
  402249:	e8 c2 fe ff ff       	callq  402110 <EF_Abort>
  40224e:	eb a0                	jmp    4021f0 <printNumber+0x40>

0000000000402250 <EF_Exitv>:
  402250:	55                   	push   %rbp
  402251:	31 c0                	xor    %eax,%eax
  402253:	48 89 f5             	mov    %rsi,%rbp
  402256:	53                   	push   %rbx
  402257:	48 89 fb             	mov    %rdi,%rbx
  40225a:	48 8d 3d f2 04 00 00 	lea    0x4f2(%rip),%rdi        # 402753 <version+0x93>
  402261:	48 83 ec 08          	sub    $0x8,%rsp
  402265:	e8 36 fb ff ff       	callq  401da0 <EF_Print>
  40226a:	48 89 ee             	mov    %rbp,%rsi
  40226d:	48 89 df             	mov    %rbx,%rdi
  402270:	e8 cb fb ff ff       	callq  401e40 <EF_Printv>
  402275:	48 8d 3d d5 04 00 00 	lea    0x4d5(%rip),%rdi        # 402751 <version+0x91>
  40227c:	31 c0                	xor    %eax,%eax
  40227e:	e8 1d fb ff ff       	callq  401da0 <EF_Print>
  402283:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  402288:	e8 a3 e9 ff ff       	callq  400c30 <_exit@plt>
  40228d:	0f 1f 00             	nopl   (%rax)

0000000000402290 <EF_Exit>:
  402290:	48 81 ec d8 00 00 00 	sub    $0xd8,%rsp
  402297:	84 c0                	test   %al,%al
  402299:	48 89 74 24 28       	mov    %rsi,0x28(%rsp)
  40229e:	48 89 54 24 30       	mov    %rdx,0x30(%rsp)
  4022a3:	48 89 4c 24 38       	mov    %rcx,0x38(%rsp)
  4022a8:	4c 89 44 24 40       	mov    %r8,0x40(%rsp)
  4022ad:	4c 89 4c 24 48       	mov    %r9,0x48(%rsp)
  4022b2:	74 37                	je     4022eb <EF_Exit+0x5b>
  4022b4:	0f 29 44 24 50       	movaps %xmm0,0x50(%rsp)
  4022b9:	0f 29 4c 24 60       	movaps %xmm1,0x60(%rsp)
  4022be:	0f 29 54 24 70       	movaps %xmm2,0x70(%rsp)
  4022c3:	0f 29 9c 24 80 00 00 	movaps %xmm3,0x80(%rsp)
  4022ca:	00 
  4022cb:	0f 29 a4 24 90 00 00 	movaps %xmm4,0x90(%rsp)
  4022d2:	00 
  4022d3:	0f 29 ac 24 a0 00 00 	movaps %xmm5,0xa0(%rsp)
  4022da:	00 
  4022db:	0f 29 b4 24 b0 00 00 	movaps %xmm6,0xb0(%rsp)
  4022e2:	00 
  4022e3:	0f 29 bc 24 c0 00 00 	movaps %xmm7,0xc0(%rsp)
  4022ea:	00 
  4022eb:	48 8d 84 24 e0 00 00 	lea    0xe0(%rsp),%rax
  4022f2:	00 
  4022f3:	48 8d 74 24 08       	lea    0x8(%rsp),%rsi
  4022f8:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
  4022fd:	48 8d 44 24 20       	lea    0x20(%rsp),%rax
  402302:	c7 44 24 08 08 00 00 	movl   $0x8,0x8(%rsp)
  402309:	00 
  40230a:	c7 44 24 0c 30 00 00 	movl   $0x30,0xc(%rsp)
  402311:	00 
  402312:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
  402317:	e8 34 ff ff ff       	callq  402250 <EF_Exitv>
  40231c:	48 81 c4 d8 00 00 00 	add    $0xd8,%rsp
  402323:	c3                   	retq   
  402324:	66 90                	xchg   %ax,%ax
  402326:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40232d:	00 00 00 

0000000000402330 <EF_InternalError>:
  402330:	53                   	push   %rbx
  402331:	48 81 ec d0 00 00 00 	sub    $0xd0,%rsp
  402338:	84 c0                	test   %al,%al
  40233a:	48 89 74 24 28       	mov    %rsi,0x28(%rsp)
  40233f:	48 89 54 24 30       	mov    %rdx,0x30(%rsp)
  402344:	48 89 4c 24 38       	mov    %rcx,0x38(%rsp)
  402349:	4c 89 44 24 40       	mov    %r8,0x40(%rsp)
  40234e:	4c 89 4c 24 48       	mov    %r9,0x48(%rsp)
  402353:	74 37                	je     40238c <EF_InternalError+0x5c>
  402355:	0f 29 44 24 50       	movaps %xmm0,0x50(%rsp)
  40235a:	0f 29 4c 24 60       	movaps %xmm1,0x60(%rsp)
  40235f:	0f 29 54 24 70       	movaps %xmm2,0x70(%rsp)
  402364:	0f 29 9c 24 80 00 00 	movaps %xmm3,0x80(%rsp)
  40236b:	00 
  40236c:	0f 29 a4 24 90 00 00 	movaps %xmm4,0x90(%rsp)
  402373:	00 
  402374:	0f 29 ac 24 a0 00 00 	movaps %xmm5,0xa0(%rsp)
  40237b:	00 
  40237c:	0f 29 b4 24 b0 00 00 	movaps %xmm6,0xb0(%rsp)
  402383:	00 
  402384:	0f 29 bc 24 c0 00 00 	movaps %xmm7,0xc0(%rsp)
  40238b:	00 
  40238c:	48 89 fb             	mov    %rdi,%rbx
  40238f:	48 8d 3d fa 03 00 00 	lea    0x3fa(%rip),%rdi        # 402790 <version+0xd0>
  402396:	31 c0                	xor    %eax,%eax
  402398:	e8 03 fa ff ff       	callq  401da0 <EF_Print>
  40239d:	48 8d 84 24 e0 00 00 	lea    0xe0(%rsp),%rax
  4023a4:	00 
  4023a5:	48 8d 74 24 08       	lea    0x8(%rsp),%rsi
  4023aa:	48 89 df             	mov    %rbx,%rdi
  4023ad:	c7 44 24 08 08 00 00 	movl   $0x8,0x8(%rsp)
  4023b4:	00 
  4023b5:	c7 44 24 0c 30 00 00 	movl   $0x30,0xc(%rsp)
  4023bc:	00 
  4023bd:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
  4023c2:	48 8d 44 24 20       	lea    0x20(%rsp),%rax
  4023c7:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
  4023cc:	e8 6f fa ff ff       	callq  401e40 <EF_Printv>
  4023d1:	48 8d 3d 79 03 00 00 	lea    0x379(%rip),%rdi        # 402751 <version+0x91>
  4023d8:	31 c0                	xor    %eax,%eax
  4023da:	e8 c1 f9 ff ff       	callq  401da0 <EF_Print>
  4023df:	31 c0                	xor    %eax,%eax
  4023e1:	e8 9a f9 ff ff       	callq  401d80 <do_abort>

00000000004023e6 <_Z10stack_flowv>:
  4023e6:	55                   	push   %rbp
  4023e7:	48 89 e5             	mov    %rsp,%rbp
  4023ea:	48 83 ec 10          	sub    $0x10,%rsp
  4023ee:	c7 45 fc 20 00 00 00 	movl   $0x20,-0x4(%rbp)
  4023f5:	ba 14 00 00 00       	mov    $0x14,%edx
  4023fa:	48 8d 45 f0          	lea    -0x10(%rbp),%rax
  4023fe:	be 00 00 00 00       	mov    $0x0,%esi
  402403:	48 89 c7             	mov    %rax,%rdi
  402406:	e8 f5 e7 ff ff       	callq  400c00 <memset@plt>
  40240b:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40240e:	89 c6                	mov    %eax,%esi
  402410:	bf 00 41 60 00       	mov    $0x604100,%edi
  402415:	e8 d6 e7 ff ff       	callq  400bf0 <_ZNSolsEi@plt>
  40241a:	be 20 0d 40 00       	mov    $0x400d20,%esi
  40241f:	48 89 c7             	mov    %rax,%rdi
  402422:	e8 d9 e8 ff ff       	callq  400d00 <_ZNSolsEPFRSoS_E@plt>
  402427:	c9                   	leaveq 
  402428:	c3                   	retq   

0000000000402429 <main>:
  402429:	55                   	push   %rbp
  40242a:	48 89 e5             	mov    %rsp,%rbp
  40242d:	e8 b4 ff ff ff       	callq  4023e6 <_Z10stack_flowv>
  402432:	be ec 27 40 00       	mov    $0x4027ec,%esi
  402437:	bf 00 41 60 00       	mov    $0x604100,%edi
  40243c:	e8 3f e8 ff ff       	callq  400c80 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
  402441:	be 20 0d 40 00       	mov    $0x400d20,%esi
  402446:	48 89 c7             	mov    %rax,%rdi
  402449:	e8 b2 e8 ff ff       	callq  400d00 <_ZNSolsEPFRSoS_E@plt>
  40244e:	b8 00 00 00 00       	mov    $0x0,%eax
  402453:	5d                   	pop    %rbp
  402454:	c3                   	retq   

0000000000402455 <_Z41__static_initialization_and_destruction_0ii>:
  402455:	55                   	push   %rbp
  402456:	48 89 e5             	mov    %rsp,%rbp
  402459:	48 83 ec 10          	sub    $0x10,%rsp
  40245d:	89 7d fc             	mov    %edi,-0x4(%rbp)
  402460:	89 75 f8             	mov    %esi,-0x8(%rbp)
  402463:	83 7d fc 01          	cmpl   $0x1,-0x4(%rbp)
  402467:	75 27                	jne    402490 <_Z41__static_initialization_and_destruction_0ii+0x3b>
  402469:	81 7d f8 ff ff 00 00 	cmpl   $0xffff,-0x8(%rbp)
  402470:	75 1e                	jne    402490 <_Z41__static_initialization_and_destruction_0ii+0x3b>
  402472:	bf a0 42 60 00       	mov    $0x6042a0,%edi
  402477:	e8 94 e7 ff ff       	callq  400c10 <_ZNSt8ios_base4InitC1Ev@plt>
  40247c:	ba 48 25 40 00       	mov    $0x402548,%edx
  402481:	be a0 42 60 00       	mov    $0x6042a0,%esi
  402486:	bf 70 0c 40 00       	mov    $0x400c70,%edi
  40248b:	e8 b0 e7 ff ff       	callq  400c40 <__cxa_atexit@plt>
  402490:	c9                   	leaveq 
  402491:	c3                   	retq   

0000000000402492 <_GLOBAL__sub_I__Z10stack_flowv>:
  402492:	55                   	push   %rbp
  402493:	48 89 e5             	mov    %rsp,%rbp
  402496:	be ff ff 00 00       	mov    $0xffff,%esi
  40249b:	bf 01 00 00 00       	mov    $0x1,%edi
  4024a0:	e8 b0 ff ff ff       	callq  402455 <_Z41__static_initialization_and_destruction_0ii>
  4024a5:	5d                   	pop    %rbp
  4024a6:	c3                   	retq   
  4024a7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  4024ae:	00 00 

00000000004024b0 <__libc_csu_init>:
  4024b0:	41 57                	push   %r15
  4024b2:	41 89 ff             	mov    %edi,%r15d
  4024b5:	41 56                	push   %r14
  4024b7:	49 89 f6             	mov    %rsi,%r14
  4024ba:	41 55                	push   %r13
  4024bc:	49 89 d5             	mov    %rdx,%r13
  4024bf:	41 54                	push   %r12
  4024c1:	4c 8d 25 08 19 20 00 	lea    0x201908(%rip),%r12        # 603dd0 <__frame_dummy_init_array_entry>
  4024c8:	55                   	push   %rbp
  4024c9:	48 8d 2d 10 19 20 00 	lea    0x201910(%rip),%rbp        # 603de0 <__init_array_end>
  4024d0:	53                   	push   %rbx
  4024d1:	4c 29 e5             	sub    %r12,%rbp
  4024d4:	31 db                	xor    %ebx,%ebx
  4024d6:	48 c1 fd 03          	sar    $0x3,%rbp
  4024da:	48 83 ec 08          	sub    $0x8,%rsp
  4024de:	e8 cd e6 ff ff       	callq  400bb0 <_init>
  4024e3:	48 85 ed             	test   %rbp,%rbp
  4024e6:	74 1e                	je     402506 <__libc_csu_init+0x56>
  4024e8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4024ef:	00 
  4024f0:	4c 89 ea             	mov    %r13,%rdx
  4024f3:	4c 89 f6             	mov    %r14,%rsi
  4024f6:	44 89 ff             	mov    %r15d,%edi
  4024f9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  4024fd:	48 83 c3 01          	add    $0x1,%rbx
  402501:	48 39 eb             	cmp    %rbp,%rbx
  402504:	75 ea                	jne    4024f0 <__libc_csu_init+0x40>
  402506:	48 83 c4 08          	add    $0x8,%rsp
  40250a:	5b                   	pop    %rbx
  40250b:	5d                   	pop    %rbp
  40250c:	41 5c                	pop    %r12
  40250e:	41 5d                	pop    %r13
  402510:	41 5e                	pop    %r14
  402512:	41 5f                	pop    %r15
  402514:	c3                   	retq   
  402515:	90                   	nop
  402516:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40251d:	00 00 00 

0000000000402520 <__libc_csu_fini>:
  402520:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000402524 <_fini>:
  402524:	48 83 ec 08          	sub    $0x8,%rsp
  402528:	48 83 c4 08          	add    $0x8,%rsp
  40252c:	c3                   	retq   
