prog = "Good luck reading this lol uDZD0 MDOD1 MA$ZF JDTD2 MDLDF5F*F1 MA$LF JEepbeepQ10 ZA$OF JC LA$TF JEepbeepQ02 ZA$OF JC LDWDF$LF+F1 MA$WF JDNDF13F*F70 MDNDF$NF+F1 MA$NF JA1 JDPD0 MDKD0 MEepbeepQ20 ZDPDF$PF+F1 MDKDF$KF+F1 MC LEepbeep22 ZDKDF$KF+F1 MC LDKDF$KF*F$PF MA$KF JA2 JA2 JDLDF$LF-F5 MA$LF JA$LF JDAD1 MDTD1 MEepbeepQ11 ZDPDF2F*F$AF MDPDF$PF+F1 MDTDF$TF+F$PF MDADF$AF+F1 MC LA$TF J!!!"

INIT = "Good luck reading this lol u"

if not prog.startswith(INIT):
    raise ValueError("Start missing")

prog = prog.lstrip(INIT)


def split_to_cmds():
    current_command = ""
    for c in prog:
        current_command += c
        if current_command == "!!!":
            print("Finished!")
            break
        if ord(current_command[0]) + 9 == ord(c) or current_command.startswith('Eepbeep') and c == 'L':
            print(current_command)
            current_command = ''
    if current_command:
        print(current_command)


variables = dict()


def get_or_default(key, default='L'):
    if key in variables:
        return variables[key]
    return default


def a(key):
    if key in variables:
        print(str(variables[key])[::-1], end='')
    else:
        assert False
        # print(chr(ord('L') - 1))


def translated():
    # DZD0 M
    variables['Z'] = 0

    # DOD1 M
    variables['O'] = 1

    # A$ZF J
    a('Z')

    # DTD2 M
    variables['T'] = 2

    # DLDF5F*F1 M
    variables['L'] = 5 * 1

    # A$LF J
    a('L')

    # EepbeepQ10 ZA$OF JC L
    for _ in range(int('10', 3)):
        a('O')

    # A$TF J
    a('T')

    # EepbeepQ02 ZA$OF JC L
    for _ in range(int('02', 3)):
        a('O')

    # DWDF$LF+F1 M
    variables['W'] = get_or_default('L') + 1

    # A$WF J
    a('W')

    # DNDF13F*F70 M
    variables['N'] = 13 * 70

    # DNDF$NF+F1 M
    variables['N'] = get_or_default('N') + 1

    # A$NF J
    a('N')

    # A1 J
    print('0', end='')

    # DPD0 M
    variables['P'] = 0

    # DKD0 M
    variables['K'] = 0

    # EepbeepQ20 ZDPDF$PF+F1 MDKDF$KF+F1 MC L
    for _ in range(int('20', 3)):
        variables['P'] = get_or_default('P') + 1
        variables['K'] = get_or_default('K') + 1

    # Eepbeep22 ZDKDF$KF+F1 MC L
    for _ in range(int('22', 3)):
        variables['K'] = get_or_default('K') + 1

    # DKDF$KF*F$PF M
    variables['K'] = get_or_default('K') * get_or_default('P')

    # A$KF J
    a('K')

    # A2 J
    print('1', end='')

    # A2 J
    print('1', end='')

    # DLDF$LF-F5 M
    variables['L'] = get_or_default('L') - 5

    # A$LF J
    a('L')

    # A$LF J
    a('L')

    # DAD1 M
    variables['A'] = 1

    # DTD1 M
    variables['T'] = 1

    # EepbeepQ11 ZDPDF2F*F$AF MDPDF$PF+F1 MDTDF$TF+F$PF MDADF$AF+F1 MC L
    for _ in range(int('11', 3)):
        variables['P'] = 2 * get_or_default('A')
        variables['P'] = get_or_default('P') + 1
        variables['T'] = get_or_default('T') + get_or_default('P')
        variables['A'] = get_or_default('A') + 1

    # A$TF J
    a('T')

split_to_cmds()
translated()

s = "051112116119048110052"
num = ""
flag = ""
for c in s:
    num += c
    if int(num) > 32:
        flag += chr(int(num))
        num = ""
print()
print(num)
print("flag{" + flag + "}")