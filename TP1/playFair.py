def createMatrix(keyList):
    """Create 5x5 Playfair matrix from key list"""
    table = [[0 for i in range(5)] for j in range(5)]
    for i in range(5):
        for j in range(5):
            table[i][j] = keyList[i * 5 + j]
    return table

def printMatrix(table):
    """Print the Playfair matrix"""
    print("\nPlayfair Key Matrix:")
    for i in range(5):
        for j in range(5):
            print(table[i][j], end=" ")
        print()

def enterKey():
    """Generate Playfair matrix from user key"""
    key = input("Enter the key: ")
    
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    key = key.replace(" ", "")
    key = key.lower()
    used = set()
    result = []
    
    # Add unique letters from key
    for ch in key:
        if ch in alphabet and ch not in used:
            result.append(ch)
            used.add(ch)
    
    # Add remaining letters (except j, or combine i/j)
    for ch in alphabet:
        if ch not in used and ch != 'j':
            result.append(ch)
            used.add(ch)
    
    return result

def find_position(matrix, char):
    """Find position of character in matrix"""
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j
    return -1, -1

def encrypt(plaintext, key):
    """Encrypt using Playfair cipher"""
    # Generate key matrix
    keylist = enterKey()
    matrix = createMatrix(keylist)
    printMatrix(matrix)
    
    # Prepare plaintext: remove spaces, add x between duplicates
    plaintext = plaintext.replace(" ", "").lower()
    plaintext = plaintext.replace("j", "i")
    
    # Process pairs
    ciphertext = ""
    i = 0
    while i < len(plaintext):
        # Get pair of letters
        char1 = plaintext[i]
        if i + 1 < len(plaintext):
            char2 = plaintext[i + 1]
        else:
            char2 = 'x'  # Padding
        
        # If same letter, insert x
        if char1 == char2:
            char2 = 'x'
            i += 1
        else:
            i += 2
        
        # Find positions
        row1, col1 = find_position(matrix, char1)
        row2, col2 = find_position(matrix, char2)
        
        # Apply Playfair rules
        if row1 == row2:  # Same row
            ciphertext += matrix[row1][(col1 + 1) % 5]
            ciphertext += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # Same column
            ciphertext += matrix[(row1 + 1) % 5][col1]
            ciphertext += matrix[(row2 + 1) % 5][col2]
        else:  # Rectangle
            ciphertext += matrix[row1][col2]
            ciphertext += matrix[row2][col1]
    
    return ciphertext

def decrypt(ciphertext, key):
    """Decrypt using Playfair cipher"""
    # Generate key matrix
    keylist = enterKey()
    matrix = createMatrix(keylist)
    printMatrix(matrix)
    
    ciphertext = ciphertext.replace(" ", "").lower()
    
    # Process pairs
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        if i + 1 < len(ciphertext):
            char1 = ciphertext[i]
            char2 = ciphertext[i + 1]
            
            # Find positions
            row1, col1 = find_position(matrix, char1)
            row2, col2 = find_position(matrix, char2)
            
            # Apply Playfair rules (reverse)
            if row1 == row2:  # Same row
                plaintext += matrix[row1][(col1 - 1) % 5]
                plaintext += matrix[row2][(col2 - 1) % 5]
            elif col1 == col2:  # Same column
                plaintext += matrix[(row1 - 1) % 5][col1]
                plaintext += matrix[(row2 - 1) % 5][col2]
            else:  # Rectangle
                plaintext += matrix[row1][col2]
                plaintext += matrix[row2][col1]
    
    return plaintext

def menu():
    """Interactive menu for Playfair cipher"""
    print("=" * 50)
    print("         Playfair Cipher — Encrypt / Decrypt")
    print("=" * 50)
    
    while True:
        print("\nOptions:")
        print("  1. Encrypt")
        print("  2. Decrypt")
        print("  3. Exit")
        choice = input("\nChoose [1-3]: ").strip()
        
        if choice == '3':
            print("Exiting...")
            break
        
        if choice == '1':
            plaintext = input("Enter plaintext: ")
            key = input("Enter key (will be regenerated): ")
            ciphertext = encrypt(plaintext, key)
            print(f"\nCiphertext: {ciphertext}")
        
        elif choice == '2':
            ciphertext = input("Enter ciphertext: ")
            key = input("Enter key: ")
            plaintext = decrypt(ciphertext, key)
            print(f"\nPlaintext: {plaintext}")
        
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    menu()
    
    for ch in alphabet:
        if ch not in used:
            result.append(ch)
            used.add(ch)
    
    return result

def inTheTable (char , table):
    x = False 
    for i in range (5):
        for j in range (5):
            if char == table[i][j] :
                x = True
    return x



def encrypt(table):
    
    print("enter the text to encrypt : ")
    text = input()
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
        if char1 =='w' or char2 == 'w':
            print("The letter 'w' is not allowed in the Playfair cipher. it will be replaced by x.")
            if char1 == 'w':
                char1 = 'x'
            if char2 == 'w':
                char2 = 'x'

        if inTheTable(char1, table) and inTheTable(char2, table):
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
    return encryptedText

def decrypt (table):
    text = input ("enter encrypted text to decrypted : ")
    text = text.replace(" ", "")
    text = text.lower()

    decryptedText = ""
    for i in range(0 , len(text) , 2):
        doubleChar = text [i : i+2]
        char1 = doubleChar[0]
        char2 = doubleChar[1]

        if inTheTable(char1, table) and inTheTable(char2, table):
            row1 , col1 = [(row , col) for row in range (5)for col in range (5) if table[row][col] == char1][0]
            row2 , col2 = [(row , col) for row in range (5)for col in range (5) if table[row][col] == char2][0]
            if row1 == row2:
                decryptedText += table[row1][(col1 - 1) % 5]
                decryptedText += table[row2][(col2 - 1) % 5]
            elif col1 == col2:
                decryptedText += table[(row1 - 1) % 5][col1]
                decryptedText += table[(row2 - 1) % 5][col2]
            else:
                decryptedText += table[row1][col2]
                decryptedText += table[row2][col1]
    if 'x' in decryptedText:
        print("The letter 'x' was used for padding.")
        y = int (input("do you want to remove the 'x' that was added for padding ? 1 for yes and 2 for no : "))
        if y == 1:
            decryptedText = decryptedText.replace('x', '')

    return decryptedText


def main():
    print("Welcome to the Playfair cipher program!")
    while True:
        print("Enter 1 for encryption, 2 for decryption, or 3 to exit: ")
        choice = input()
        if choice == "3":
            break
        elif choice == "1":

            keyList = enterKey()
            table = createMatrix(keyList)
            printMatrix(table)
            print("the encrypted text : " + encrypt(table))
        elif choice == "2":
            keyList = enterKey()
            table = createMatrix(keyList)
            printMatrix(table)
            print("the decrypted text : " + decrypt(table))

if __name__ == "__main__":
    main()