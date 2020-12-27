# Basic Info

Lets start by running `file impossible_password.bin`. We get the following output:

```
impossible_password.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=ba116ba1912a8c3779ddeb579404e2fdf34b1568, stripped
```
Runnign `strings impossible_password.bin` we get some common strings, however one string namely `SuperSeKretKey` looks special. 

Running the binary, we need to pass some input to it before we can continue.

# Reverse Engineering

So lets open the file in Ghidra, using the default analysis. As the binary is stripped we dont have the function names, so in order to find the main function we can just
look at each function name that starts with **FUN_\** and try to find a main function that might look like a main function.

From my observation the function **FUN_0040085d** looks like the main function

```
void FUN_0040085d(void)

{
  int iVar1;
  char *__s2;
  undefined local_48;
  undefined local_47;
  undefined local_46;
  undefined local_45;
  undefined local_44;
  undefined local_43;
  undefined local_42;
  undefined local_41;
  undefined local_40;
  undefined local_3f;
  undefined local_3e;
  undefined local_3d;
  undefined local_3c;
  undefined local_3b;
  undefined local_3a;
  undefined local_39;
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined local_35;
  char local_28 [20];
  int local_14;
  char *local_10;
  
  local_10 = "SuperSeKretKey";
  local_48 = 0x41;
  local_47 = 0x5d;
  local_46 = 0x4b;
  local_45 = 0x72;
  local_44 = 0x3d;
  local_43 = 0x39;
  local_42 = 0x6b;
  local_41 = 0x30;
  local_40 = 0x3d;
  local_3f = 0x30;
  local_3e = 0x6f;
  local_3d = 0x30;
  local_3c = 0x3b;
  local_3b = 0x6b;
  local_3a = 0x31;
  local_39 = 0x3f;
  local_38 = 0x6b;
  local_37 = 0x38;
  local_36 = 0x31;
  local_35 = 0x74;
  printf("* ");
  __isoc99_scanf(&DAT_00400a82,local_28);
  printf("[%s]\n",local_28);
  local_14 = strcmp(local_28,local_10);
  if (local_14 != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("** ");
  __isoc99_scanf(&DAT_00400a82,local_28);
  __s2 = (char *)FUN_0040078d(0x14);
  iVar1 = strcmp(local_28,__s2);
  if (iVar1 == 0) {
    FUN_00400978(&local_48);
  }
  return;
}
```

Again we can see the string **SuperSeKretKey**. Lets first clean up the function before continuing

```

void main(void)

{
  int second_pw_check;
  char *second_pw;
  undefined local_48;
  undefined local_47;
  undefined local_46;
  undefined local_45;
  undefined local_44;
  undefined local_43;
  undefined local_42;
  undefined local_41;
  undefined local_40;
  undefined local_3f;
  undefined local_3e;
  undefined local_3d;
  undefined local_3c;
  undefined local_3b;
  undefined local_3a;
  undefined local_39;
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined local_35;
  char input_buffer [20];
  int first_pw_check;
  char *first_pw;
  
  first_pw = "SuperSeKretKey";
  local_48 = 'A';
  local_47 = ']';
  local_46 = 'K';
  local_45 = 'r';
  local_44 = '=';
  local_43 = '9';
  local_42 = 'k';
  local_41 = '0';
  local_40 = '=';
  local_3f = '0';
  local_3e = 'o';
  local_3d = '0';
  local_3c = ';';
  local_3b = 'k';
  local_3a = '1';
  local_39 = '?';
  local_38 = 'k';
  local_37 = '8';
  local_36 = '1';
  local_35 = 't';
  printf("* ");
  __isoc99_scanf(&string_format,input_buffer);
  printf("[%s]\n",input_buffer);
  first_pw_check = strcmp(input_buffer,first_pw);
  if (first_pw_check != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("** ");
  __isoc99_scanf(&string_format,input_buffer);
  second_pw = generate_second_pw(0x14);
  second_pw_check = strcmp(input_buffer,second_pw);
  if (second_pw_check == 0) {
    create_flag(&local_48);
  }
  return;
}
```

So as we can see the binary is doing the following:
1. First it checks if the input is equal to "SuperSeKretKey"
2. If it is a second password is generated
3. Now we are asked again for a input. If our second input matches the newly created password we may continiue
4. If we make it this far, a last function is called that generates the flag for us

So we have the first password, but whats the second?

Heres the code for this function (names are cleaned up)

```
char * generate_second_pw(int param_1)

{
  int iVar1;
  time_t cur_time;
  char *malloc_p;
  int counter;
  
  cur_time = time((time_t *)0x0);
  DAT_00601074 = DAT_00601074 + 1;
  srand(DAT_00601074 + (int)cur_time * param_1);
  malloc_p = (char *)malloc((long)(param_1 + 1));
  if (malloc_p != (char *)0x0) {
    counter = 0;
    while (counter < param_1) {
      iVar1 = rand();
      malloc_p[counter] = (char)(iVar1 % 0x5e) + '!';
      counter = counter + 1;
    }
    malloc_p[param_1] = '\0';
    return malloc_p;
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

So the second password is created by generating random chars. The seed is the current time and some other values. As the challenge is called **impossible passowrd** 
I have guessed that it is not the goal to understand how the second password is created but rather to somehow break it. 

My solution was patching

## Patching

So the only left to do, so the binary calls the flag generation function is to pass the second password which we do not have. After the second password is generated it
is compared with our passed password with the `cmp` function (in x86) and then `JNE`is called. If both strings are equal the flag creation function is called else not
. So what if we just change the call from `JNE`to `JE` i.e if our passed string is **NOT** equal to the second password, call the flag generation function. 

Patching in Ghidra is easy, we just need to select the instruction and the click on `patch instruction`. However as we want to run this patched binary we need
to export it. I used the following [script](https://github.com/schlafwandler/ghidra_SavePatch) to export the patched binary.

Running the binary with anything as second password (except the correct one :) ) prints the flag to the terminal
