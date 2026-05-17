from calculateInverse import cal_iverse 

def isInteger(s):
    try:
        int(s)
        return True
    except ValueError:
        return False
def charToNum(char):
    return ord(char) - ord('a')
def numToChar(num):
    return chr(num + ord('a'))






def matrix_det_2x2(key):
    a, b, c, d = int(key[0]), int(key[1]), int(key[2]), int(key[3])
    return (a * d - b * c) % 26

def matrix_inverse_2x2(key):
    a, b, c, d = int(key[0]), int(key[1]), int(key[2]), int(key[3])
    det = (a * d - b * c) % 26
    det_inv = cal_iverse(det, 26)
    if det_inv is None:
        return None
    # Inverse = det_inv * [[d, -b], [-c, a]]
    inv = [
        (det_inv * d) % 26,
        (det_inv * (-b)) % 26,
        (det_inv * (-c)) % 26,
        (det_inv * a) % 26
    ]
    return inv

def matrix_det_3x3(key):
    matrix = [[int(key[i*3+j]) for j in range(3)] for i in range(3)]
    det = (matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]) -
           matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]) +
           matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0])) % 26
    return det

def matrix_inverse_3x3(key):
    matrix = [[int(key[i*3+j]) for j in range(3)] for i in range(3)]
    det = matrix_det_3x3(key)
    det_inv = cal_iverse(det, 26)
    if det_inv is None:
        return None
    
    # Calculate adjugate matrix
    adj = [
        (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]) % 26,
        (matrix[0][2] * matrix[2][1] - matrix[0][1] * matrix[2][2]) % 26,
        (matrix[0][1] * matrix[1][2] - matrix[0][2] * matrix[1][1]) % 26,
        (matrix[1][2] * matrix[2][0] - matrix[1][0] * matrix[2][2]) % 26,
        (matrix[0][0] * matrix[2][2] - matrix[0][2] * matrix[2][0]) % 26,
        (matrix[0][2] * matrix[1][0] - matrix[0][0] * matrix[1][2]) % 26,
        (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]) % 26,
        (matrix[0][1] * matrix[2][0] - matrix[0][0] * matrix[2][1]) % 26,
        (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26
    ]
    
    # Multiply adjugate by determinant inverse
    inv = [(det_inv * adj[i]) % 26 for i in range(9)]
    return inv

def decrypt():
    print("enter the matrix size \n 1: 2x2 \n 2: 3x3  ")
    while True:
            n = int(input())
            if n == 1 or n == 2:
                size = (n+1) * (n+1)
                break
            else:
                print("Invalid size. Please enter 1 or 2.")
    print("enter the key to fill the matrix (only numbers) : ")
    if n == 1:
        while True:
            try:
                key = input()
                if not isInteger(key):
                    print("Invalid input. Please enter only numbers.")
                    return
                if len(key) != 4:
                    print("Invalid key length. Please enter 4 numbers for a 2x2 matrix.")
                else:
                    break
            except ValueError:
                print("Invalid input. Please enter only numbers.")
    else:
        while True:
            try:
                key = input()
                if not isInteger(key):
                    print("Invalid input. Please enter only numbers.")
                    return
                if len(key) != 9:
                    print("Invalid key length. Please enter 9 numbers for a 3x3 matrix.")
                else:
                    break
            except ValueError:
                print("Invalid input. Please enter only numbers.")

    print("the matrix is : ")
    for i in range(size//(n+1)):
        for j in range(size//(n+1)):
            print(key[i*(n+1)+j], end=" ")
        print()
    
    # Calculate inverse matrix
    if n == 1:
        inv_key = matrix_inverse_2x2(key)
    else:
        inv_key = matrix_inverse_3x3(key)
    
    if inv_key is None:
        print("Error: The matrix is not invertible modulo 26.")
        return
    
    print("Inverse matrix is : ")
    for i in range(size//(n+1)):
        for j in range(size//(n+1)):
            print(inv_key[i*(n+1)+j], end=" ")
        print()
        
    print("enter the text to decrypt : ")
    text = input()
    text = text.replace(" ", "")
    text = text.lower()
    
    decryptedText = ""
    i = 0
    if n == 1:
        while i < len(text):
            double = text[i] + text[i+1]
            firstchar = charToNum(double[0])
            secondchar = charToNum(double[1])
            # Perform decryption using the inverse key matrix
            decryptedFirstChar = (firstchar * inv_key[0] + secondchar * inv_key[1]) % 26
            decryptedSecondChar = (firstchar * inv_key[2] + secondchar * inv_key[3]) % 26
            
            decryptedText += numToChar(decryptedFirstChar) + numToChar(decryptedSecondChar)
            
            i += 2
    else:
        while i < len(text):
            triple = text[i] + text[i+1] + text[i+2]
            firstchar = charToNum(triple[0])
            secondchar = charToNum(triple[1])
            thirdchar = charToNum(triple[2])
            # Perform decryption using the inverse key matrix
            decryptedFirstChar = (firstchar * inv_key[0] + secondchar * inv_key[1] + thirdchar * inv_key[2]) % 26
            decryptedSecondChar = (firstchar * inv_key[3] + secondchar * inv_key[4] + thirdchar * inv_key[5]) % 26
            decryptedThirdChar = (firstchar * inv_key[6] + secondchar * inv_key[7] + thirdchar * inv_key[8]) % 26
            
            decryptedText += numToChar(decryptedFirstChar) + numToChar(decryptedSecondChar) + numToChar(decryptedThirdChar)
            
            i += 3
    
    print("Decrypted text: ", decryptedText)

def encrypt():
    print("enter the matrix size \n 1: 2x2 \n 2: 3x3  ")
    while True:
            n = int(input())
            if n == 1 or n == 2:
                size = (n+1) * (n+1)
                break
            else:
                print("Invalid size. Please enter 1 or 2.")
    print("enter the key to fill the matrix (only numbers) : ")
    if n == 1:
        while True:
            try:
                key = input()
                if not isInteger(key):
                    print("Invalid input. Please enter only numbers.")
                    return
                if len(key) != 4:
                    print("Invalid key length. Please enter 4 numbers for a 2x2 matrix.")
                else:
                    break
            except ValueError:
                print("Invalid input. Please enter only numbers.")
    else:
        while True:
            try:
                key = input()
                if not isInteger(key):
                    print("Invalid input. Please enter only numbers.")
                    return
                if len(key) != 9:
                    print("Invalid key length. Please enter 9 numbers for a 3x3 matrix.")
                else:
                    break
            except ValueError:
                print("Invalid input. Please enter only numbers.")

    print("the matrix is : ")
    for i in range(size//(n+1)):
        for j in range(size//(n+1)):
            print(key[i*(n+1)+j], end=" ")
        print()
        
    print("enter the text to encrypt : ")
    text = input()
    text = text.replace(" ", "")
    text = text.lower()
    if n == 1:
        if len(text) % 2 != 0:
            text += 'x'  # Add padding if the length of the text is odd
    else:
        while len(text) % 3 != 0:
            text += 'x'  # Add padding if the length of the text is not a multiple of 3
            
    encryptedText = ""
    i = 0
    while i < len(text) and n == 1:
        double = text [i] + text [i+1]
        firstchar = charToNum(double[0])
        secondchar = charToNum(double[1])
        # Perform encryption using the key matrix
        encrypetedFirstChar = ( firstchar * int(key[0]) + secondchar * int(key[1])) % 26
        encrypetedSecondChar = (firstchar * int(key[2]) + secondchar * int(key[3])) % 26
        
        encryptedText += numToChar(encrypetedFirstChar) + numToChar(encrypetedSecondChar)
        
        i += 2
    while i < len(text) and n == 2:
        triple = text [i] + text [i+1] + text [i+2]
        firstchar = charToNum(triple[0])
        secondchar = charToNum(triple[1])
        thirdchar = charToNum(triple[2])
        # Perform encryption using the key matrix
        encrypetedFirstChar = ( firstchar * int(key[0]) + secondchar * int(key[1]) + thirdchar * int(key[2])) % 26
        encrypetedSecondChar = (firstchar * int(key[3]) + secondchar * int(key[4]) + thirdchar * int(key[5])) % 26
        encrypetedThirdChar = (firstchar * int(key[6]) + secondchar * int(key[7]) + thirdchar * int(key[8])) % 26
        
        encryptedText += numToChar(encrypetedFirstChar) + numToChar(encrypetedSecondChar) + numToChar(encrypetedThirdChar)
        
        i += 3
        
        
    print("Encrypted text: ", encryptedText)



def main():
    print("Welcome to the Hill Cipher!")
    while True:
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            encrypt()
        elif choice == '2':
            decrypt()
        elif choice == '3':
            print("Exiting the program. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()