from utils.morseCode import from_morse_code, to_morse_code

d = {
    "nya": '.',
    "meow": '-',
    "purr": ' '
}


def to_cat(s: str, escaped="") -> str:
    for k,v in d.items():
        if v in escaped:
            continue
        s = s.replace(v, k)
    return s


def from_cat(s: str, escaped="") -> str:
    for k,v in d.items():
        if k in escaped:
            continue
        s = s.replace(k, v)
    return s


def translate_from_file() -> list:
    ret = []
    with open("cat-chat_messages", 'r') as messages:
        for w in messages:
            w = w.replace("nya", '.').replace("meow", '-').replace("purr", '_')
            ret.append(from_morse_code(w, "_"))
    return ret


if __name__ == "__main__":
    # print(to_cat(to_morse_code("636274425917865984"), ' '))
    print(translate_from_file())
