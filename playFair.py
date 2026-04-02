def createMatrix(keyList):
    table = [[0 for i in range(5)] for j in range(5)]

    for i in range(5):
        for j in range(5):
            table[i][j] = keyList[i * 5 + j]

    return table

def printMatrix(table):
    #printing the table
    for i in range(5):
        for j in range(5):
            print (table[i][j], end = " ")
        print()


def enterKey(key):
    alphabet = "abcdefghijklmnopqrstuvxyz"# w mkach
    key = key.replace(" ", "")
    key = key.lower()
    used = set()
    result = []
    
    for ch in key:
        if ch in alphabet and ch not in used:
            result.append(ch)
            used.add(ch)
    
    for ch in alphabet:
        if ch not in used:
            result.append(ch)
            used.add(ch)
    
    return result

def encrypt(text, table):
    text = text.replace(" ", "")
    text = text.lower()
    i = 0
    while i < len(text) - 1:
        if text[i] == text[i + 1]:
            text = text[:i + 1] + 'x' + text[i + 1:]
            i += 2  # Skip the inserted 'x'
        else:
            i += 1
    
    encryptedText = ""
    
    for i in range(0, len(text), 2):
        doubleChar = text[i:i + 2]
        char1 = doubleChar[0]
        char2 = doubleChar[1] if len(doubleChar) > 1 else 'x'  # Pad with 'x' if there's an odd character   
        if char1 in table and char2 in table :
            row1, col1 = [(row, col) for row in range(5) for col in range(5) if table[row][col] == char1][0]
            row2, col2 = [(row, col) for row in range(5) for col in range(5) if table[row][col] == char2][0]
            
            if row1 == row2:
                encryptedText += table[row1][(col1 + 1) % 5]
                encryptedText += table[row2][(col2 + 1) % 5]
            elif col1 == col2:
                encryptedText += table[(row1 + 1) % 5][col1]
                encryptedText += table[(row2 + 1) % 5][col2]
            else:
                encryptedText += table[row1][col2]
                encryptedText += table[row2][col1]





def main():
    print("Welcome to the Playfair cipher program!")
    key = input("Enter the key: ")
    keyList = enterKey(key)
    table = createMatrix(keyList)
    printMatrix(table)
    print("enter the text to encrypt : ")
    text = input()
    encrypt(text, table)


if __name__ == "__main__":
    main()