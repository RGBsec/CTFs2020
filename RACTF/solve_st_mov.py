# s = ''.join(["00011010011110001110", "00001011001100100001", "00000100100101100011", "01100110100010000011", '1',
#              "11100010110010110001", "0010001101001", '1',"1111001", "11010010000001011000", "011000000010"])
s = "00011010011110001110000010110011001000010000010010010110001101100110100010000011111000101100101100010010001101001111100111010010000001011000011000000010"
s = s.replace('0', 'a')
s = s.replace('1', '0')
s = s.replace('a', '1')


def to_chars(string: str) -> str:
    out = ''
    SZ = 7
    nums = []
    for i in range(0, len(string), SZ):
        n = string[i:i + SZ]
        n = int(n, 2)
        nums.append(n)
        out += chr(n)
    return out


flags = set()
for i in range(len(s)):
    for j in range(i, len(s)):
        for ins_bits in ['00', '01', '10', '11']:
            chars = to_chars(s[:i] + ins_bits[0] + s[i:j] + ins_bits[1] + s[j:])
            if chars.startswith('ractf{') and chars.endswith(
                    '}') and chars.isprintable() and 'video' in chars and 'time' in chars and 'bois' in chars:
                flags.add(chars)
for flag in flags:
    print(flag)

# check = "00011010011110001110000010110011001000010000010010010110001101100110100010000011111000101100101100010010001101001111100111010010000001011000011000000010"
# assert s == check
