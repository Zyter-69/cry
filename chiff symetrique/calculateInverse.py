class nbrAndCoff:
    def __init__(self, nbr, coff):
        self.nbr = nbr
        self.coff = coff
        
    def __add__(self, other):
        if isinstance(other, nbrAndCoff):
            if self.nbr == other.nbr:
                return nbrAndCoff(self.nbr, self.coff + other.coff)
            else:
                raise ValueError("Cannot sum nbrAndCoff with different nbr values")
        else:
            raise ValueError("Can only sum with another nbrAndCoff instance")
    
    def __repr__(self):
        return f"nbrAndCoff(nbr={self.nbr}, coff={self.coff})"

listOfB = []
listOfCoff = []
listOfA = []
        
def ecludianDiv(a , b):
    global listOfB, listOfCoff, listOfA
    if a % b == 0:
        return b
    listOfB.append(a%b)
    listOfCoff.append(a // b)
    listOfA.append(a)
    return ecludianDiv(b, a % b)

def calculateSomething(a, b, coff):

    if coff == 1:
        return -b//coff + a
    else:
        return  (a - b) // coff
def retunIndexOfNbrInList(list_items, nbr):

    for i, item in enumerate(list_items):
        if abs(item.nbr) == abs(nbr):
            return i
    return -1
def cacculateSumCoffInList(list_items):
    consolidated = {}
    
    for item in list_items:
        if item.nbr in consolidated:
            consolidated[item.nbr] += item.coff
        else:
            consolidated[item.nbr] = item.coff
    
    return [nbrAndCoff(nbr, coff) for nbr, coff in consolidated.items()]
def calculate_invrse ( listOfB , listOfCoff , listOfA , z , m):

    firsta = listOfA.pop()
    firstcoff = listOfCoff.pop()
    firstb = listOfB.pop()
    total = [nbrAndCoff(firsta, 1) , nbrAndCoff( -calculateSomething(firsta, firstb, firstcoff) , firstcoff)]

    


    while listOfB:

        a = listOfA.pop()
        coff = listOfCoff.pop()
        b = listOfB.pop()
        totali = [nbrAndCoff(a, 1) , nbrAndCoff(-calculateSomething(a, b, coff) , coff)]

        index = retunIndexOfNbrInList(total, b)

        if total[index].nbr < 0: 
            totali[0].nbr = -totali[0].nbr
            totali[1].nbr = -totali[1].nbr
        totali[0].coff = totali[0].coff * total[index].coff
        totali[1].coff = totali[1].coff * total[index].coff
        
        total.pop(index)
        total.extend(totali)
        total = cacculateSumCoffInList(total)
    index1 = retunIndexOfNbrInList(total, z)
    
    
    if total[index1].nbr < 0:
        return (((  -total[index1].coff % m) + m) % m)
    else:
        return total[index1].coff % m
    
def cal_iverse(a, m):
    global listOfB, listOfCoff, listOfA
    listOfB = []
    listOfCoff = []
    listOfA = []
    ecludianDiv(m, a)
    return calculate_invrse(listOfB, listOfCoff, listOfA, a, m)





def main():
    print("Enter a number and a modulus to calculate the modular inverse:")
    a = int(input("Number (a): "))
    m = int(input("Modulus (m): "))
    g = ecludianDiv(m, a)

    if g != 1:
        print("No inverse exists")
        return
    print("The inverse of", a, "mod", m, "is:", cal_iverse(a, m))
    
if __name__ == "__main__":
    main()