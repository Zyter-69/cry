alphabet = " abcdefghijklmnopqrstuvwxyz?!.,;:()[]{}-_'\"/\\|@#$%^&*~`"


def caesar(textClear, shiftNbr):
    encryptedText = ""
    for i in range(len(textClear)):
        for j in range(len(alphabet)):
            if textClear[i]==alphabet[j]:
                encryptedText += alphabet[(j + shiftNbr) % len(alphabet)]
    return encryptedText

def deCaesar (textEncrypted, shiftNbr):
    decryptedText = ""
    for i in range(len(textEncrypted)):
        for j in range(len(alphabet)):
            if textEncrypted[i]==alphabet[j]:
                decryptedText += alphabet[(j - shiftNbr) % len(alphabet)]
    return decryptedText
            

def encrypt():
    textClear = input ("enter text to enrypt : ")
    print("The text you entered is: " + textClear)
    shiftNbr = int(input ("enter the number of shift : "))
    print(caesar(textClear, shiftNbr))

def decrypt():
    textEncrypted = input ("enter text to decrypt : ")
    print("The text you entered is: " + textEncrypted)
    shiftNbr = int(input ("enter the number of shift : "))
    print(deCaesar(textEncrypted, shiftNbr))
    
while True :
    print ("Welcome to the Caesar cipher program!")

    x= int(input("enter 1 for encryption and 2 for decryption 3 to exit : "))

    if x == 1:
        encrypt()
    elif x == 2:
        decrypt()
    elif x == 3:
        print("Good bye!")
        break
    else:
        print("invalid input")


