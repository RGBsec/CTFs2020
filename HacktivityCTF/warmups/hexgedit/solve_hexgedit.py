from utils.basics import hex_to_ascii

format = "flag{"
print([hex(ord(c)) for c in format])

ans = "666c61677b6f70746963616c5f68657861646563696d616c5f7265636f676e6974696f6e5f616d69726974657d"
print(hex_to_ascii(ans))