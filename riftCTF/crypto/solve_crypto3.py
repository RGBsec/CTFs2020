from utils.codon import dna_to_protein, anticodon

with open("crypto3.txt", 'r') as f:
    s = f.read()
    print(len(s))
    assert len(s) % 3 == 0

    # s = anticodon(s)

    for i in range(0, len(s), 3):
        print(dna_to_protein[s[i:i+3]])
    for i in range(0, len(s), 3):
        print(dna_to_protein[s[i:i+3]][0], end='')