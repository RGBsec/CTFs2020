
void Java_com_keekle_guard_MainActivity_decrypt(long *param_1,undefined8 param_2,_jstring *param_3)

{
  size_t sVar1;
  uchar *puVar2;
  size_t __n;
  long lVar3;
  long lVar4;
  char *__s;
  char *__s_00;
  long lVar5;
  ulong uVar6;
  long in_FS_OFFSET;
  AES aAStack88 [16];
  undefined4 local_48;
  undefined4 uStack68;
  undefined4 uStack64;
  undefined4 uStack60;
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  __s_00 = (char *)g((_JNIEnv *)param_1,param_3);
  sVar1 = strlen(__s_00);
  lVar5 = sVar1 - 1;
  __s = __s_00;
  if (lVar5 != 0) {
    lVar3 = 0;
    do {
      lVar4 = lVar3;
      if (__s_00[lVar3] != ' ') break;
      lVar3 = lVar3 + 1;
      lVar4 = lVar5;
    } while (lVar5 != lVar3);
    if (lVar4 != 0) {
      uVar6 = lVar5 - lVar4;
      __s = (char *)_Znam(uVar6);
      memcpy(__s,__s_00 + lVar4,uVar6 + 1);
      operator.delete[](__s_00);
      __s[uVar6 + 1] = '\0';
    }
  }
  sVar1 = strlen(__s);
  do {
    __n = sVar1;
    sVar1 = __n - 1;
  } while (__s[__n - 1] == ' ');
  sVar1 = strlen(__s);
  __s_00 = __s;
  if (sVar1 - 1 != __n - 1) {
    __s_00 = (char *)_Znam(__n + 1);
    memcpy(__s_00,__s,__n);
    operator.delete[](__s);
    __s_00[__n] = '\0';
  }
  sVar1 = strlen(__s_00);
  if (sVar1 == 0x10) {
    puVar2 = (uchar *)_Znam(0x10);
    lVar5 = 1;
    do {
      if (__s_00[lVar5 + -1] != b[*(long *)(b + lVar5 * 8 + 0x3f8)]) {
LAB_0010d5f7:
        operator.delete[](puVar2);
        goto LAB_0010d5ff;
      }
      puVar2[lVar5 + -1] = __s_00[lVar5 + -1];
      if (__s_00[lVar5] != b[*(long *)(c + lVar5 * 8)]) goto LAB_0010d5f7;
      puVar2[lVar5] = __s_00[lVar5];
      lVar5 = lVar5 + 2;
    } while (lVar5 != 0x11);
    AES(aAStack88,0x80);
    local_48 = 0;
    uStack68 = 0;
    uStack64 = 0;
    uStack60 = 0;
    __s = (char *)DecryptCBC(aAStack88,a,0x30,puVar2,(uchar *)&local_48);
    operator.delete[](puVar2);
    sVar1 = strlen(__s);
    if (sVar1 != 0) {
      __n = 0;
      do {
        if (0x5e < (byte)(__s[__n] - 0x20U)) {
          __s = "";
          break;
        }
        __n = __n + 1;
      } while (sVar1 != __n);
    }
    lVar5 = *param_1;
  }
  else {
LAB_0010d5ff:
    lVar5 = *param_1;
    __s = "";
  }
  (**(code **)(lVar5 + 0x538))(param_1,__s);
  if (*(long *)(in_FS_OFFSET + 0x28) != local_30) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

