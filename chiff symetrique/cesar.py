# Common French words for validation
FRENCH_WORDS = {
    'le', 'de', 'un', 'et', 'a', 'que', 'est', 'en', 'pour', 'que', 'du',
    'la', 'les', 'des', 'se', 'il', 'ce', 'dans', 'par', 'je', 'qui',
    'on', 'vous', 'nous', 'me', 'te', 'lui', 'au', 'aux', 'ont', 'etre',
    'avoir', 'faire', 'aller', 'dire', 'pouvoir', 'vouloir', 'devoir',
    'je', 'tu', 'il', 'elle', 'nous', 'vous', 'ils', 'elles', 'moi', 'toi',
    'lire', 'ecrire', 'voir', 'entendre', 'parler', 'donner', 'prendre',
    'venir', 'partir', 'arriver', 'rester', 'tomber', 'lever', 'baisser',
    'montrer', 'trouver', 'chercher', 'demander', 'repondre', 'connaitre'
    , 'savoir', 'comprendre', 'aimer', 'detester', 'penser', 'croire',
    'espérer', 'attendre', 'travailler', 'jouer', 'manger', 'boire', 'dormir', 'vivre', 'mourir', 'naître', 'grandir',
    'petit', 'beau', 'joli', 'moche', 'bon', 'mauvais', 'heureux', 'triste', 'fort', 'faible', 'rapide', 'lent', 'jeune', 'vieux', 'nouveau', 'ancien', 'premier', 'dernier', 'prochain', 'loin', 'près'
, 'ici', 'là', 'partout', 'nulle part', 'toujours', 'jamais', 'souvent', 'parfois', 'rarement', 'tous', 'aucun', 'plus', 'moins', 'autre', 'même', 'seul', 'ensemble', 'différent', 'semblable', 'possible', 'impossible', 'important', 'intéressant', 'ennuyeux', 'facile', 'difficile'
    ,'bonjour', 'au revoir', 'merci', 's’il vous plaît', 'excusez-moi', 'félicitations', 'bienvenue', 'bonne chance', 'bonne nuit', 'à bientôt', 'à demain', 'à tout à l’heure'
}

def chiffrer_caesar(texte, k):
    """Encrypt text using Caesar cipher (a-z only, ignore spaces/case)"""
    texte = texte.lower()
    result = ""
    for char in texte:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + k) % 26 + ord('a'))
        elif char == ' ':
            result += ' '
    return result

def dechiffrer_caesar(texte, k):
    """Decrypt text using Caesar cipher (a-z only, ignore spaces/case)"""
    texte = texte.lower()
    result = ""
    for char in texte:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') - k) % 26 + ord('a'))
        elif char == ' ':
            result += ' '
    return result

def count_french_words(texte):
    """Count valid French words in text"""
    texte = texte.lower()
    words = texte.split()
    if not words:
        words = [texte.replace(' ', '')]
    
    count = 0
    for word in words:
        if len(word) > 2 and word in FRENCH_WORDS:
            count += 1
    return count

def brute_force_attack():
    """Try all 26 possible keys and identify valid French text"""
    textEncrypted = input("Enter encrypted text: ").lower()
    print("\n" + "="*60)
    print("BRUTE FORCE ATTACK - All 26 possible decryptions:")
    print("="*60)
    
    candidates = []
    
    for k in range(26):
        decrypted = dechiffrer_caesar(textEncrypted, k)
        word_count = count_french_words(decrypted)
        candidates.append((k, decrypted, word_count))
        
        marker = " <-- LIKELY" if word_count > 0 else ""
        print(f"Key {k:2d}: {decrypted}{marker}")
    
    print("\n" + "="*60)
    # Find best candidate
    best = max(candidates, key=lambda x: x[2])
    if best[2] > 0:
        print(f"\nBest candidate: Key = {best[0]}")
        print(f"Decrypted text: {best[1]}")
        print(f"French words found: {best[2]}")
    else:
        print("\nNo clear French text found. Manual inspection recommended.")

def calculate_ic(texte):
    """Calculate Index of Coincidence for frequency analysis"""
    texte = texte.lower()
    # Count only letters
    letter_count = {}
    total_letters = 0
    
    for char in texte:
        if 'a' <= char <= 'z':
            letter_count[char] = letter_count.get(char, 0) + 1
            total_letters += 1
    
    if total_letters < 2:
        return 0
    
    # IC = Σ(n_i * (n_i - 1)) / (N * (N - 1))
    ic = 0
    for count in letter_count.values():
        ic += count * (count - 1)
    
    ic /= (total_letters * (total_letters - 1))
    return ic

def frequency_analysis():
    """Frequency analysis attack using Index of Coincidence"""
    textEncrypted = input("Enter encrypted text: ").lower()
    
    print("\n" + "="*60)
    print("FREQUENCY ANALYSIS - Index of Coincidence (IC)")
    print("="*60)
    print(f"French IC ≈ 0.0745 (reference)")
    print(f"Random IC ≈ 0.0385\n")
    
    ic_results = []
    
    for k in range(26):
        decrypted = dechiffrer_caesar(textEncrypted, k)
        ic = calculate_ic(decrypted)
        ic_results.append((k, ic, decrypted))
        
        # Deviation from French IC
        deviation = abs(ic - 0.0745)
        marker = " <-- MOST LIKELY" if deviation < 0.01 else ""
        print(f"Key {k:2d}: IC = {ic:.4f} (deviation: {deviation:.4f}){marker}")
    
    print("\n" + "="*60)
    # Find best key (closest to French IC)
    best = min(ic_results, key=lambda x: abs(x[1] - 0.0745))
    print(f"\nBest key by IC: {best[0]}")
    print(f"IC value: {best[1]:.4f}")
    print(f"Decrypted text: {best[2]}")

def encrypt():
    textClear = input("Enter text to encrypt: ")
    shiftNbr = int(input("Enter the shift key (0-25): "))
    result = chiffrer_caesar(textClear, shiftNbr)
    print(f"Encrypted text: {result}")

def decrypt():
    textEncrypted = input("Enter text to decrypt: ")
    shiftNbr = int(input("Enter the shift key (0-25): "))
    result = dechiffrer_caesar(textEncrypted, shiftNbr)
    print(f"Decrypted text: {result}")
    
while True:
    print("\n" + "="*60)
    print("Welcome to the Caesar Cipher Program!")
    print("="*60)
    print("1. Encrypt (with known key)")
    print("2. Decrypt (with known key)")
    print("3. Brute Force Attack (try all 26 keys + French dictionary)")
    print("4. Frequency Analysis (Index of Coincidence method)")
    print("5. Exit")
    print("="*60)

    x = int(input("Enter your choice: "))

    if x == 1:
        encrypt()
    elif x == 2:
        decrypt()
    elif x == 3:
        brute_force_attack()
    elif x == 4:
        frequency_analysis()
    elif x == 5:
        print("Goodbye!")
        break
    else:
        print("Invalid input. Please try again.")


