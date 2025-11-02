#!/usr/bin/env python3
"""
SecurePass Analyzer - Simple Password Strength Checker
Author: Asmit Patil
"""

import re
import hashlib
import math
from colorama import Fore, Style, init

init(autoreset=True)

def calculate_entropy(password: str) -> float:
    """
    Rough entropy estimate based on character sets present.
    Not perfect, but good to show understanding.
    """
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'\d', password):
        pool += 10
    if re.search(r'[^A-Za-z0-9]', password):
        # common printable symbols ≈ 32
        pool += 32
    if pool == 0:
        return 0.0
    # entropy bits = length * log2(pool)
    return len(password) * math.log2(pool)

def check_strength(password: str):
    """
    Analyze password and return structured result.
    Score is based on presence of categories + length + entropy.
    """
    length = len(password)
    score = 0
    suggestions = []

    # length scoring
    if length < 8:
        suggestions.append("Use at least 8 characters.")
    elif 8 <= length < 12:
        score += 1
    else:  # >=12
        score += 2

    # character classes
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        suggestions.append("Add uppercase letters (A-Z).")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        suggestions.append("Add lowercase letters (a-z).")

    if re.search(r'\d', password):
        score += 1
    else:
        suggestions.append("Include some numbers (0-9).")

    if re.search(r'[^A-Za-z0-9]', password):
        score += 1
    else:
        suggestions.append("Include special characters like @, #, $, %, &.")

    # common pattern check
    lower = password.lower()
    if any(x in lower for x in ("password","1234","qwerty","admin","letmein")):
        suggestions.append("Avoid common words/patterns like 'password', '1234', or 'qwerty'.")

    # entropy
    entropy = calculate_entropy(password)
    if entropy >= 60:
        score += 2
    elif entropy >= 40:
        score += 1
    else:
        suggestions.append("Increase variety/length to raise entropy.")

    # final strength label
    if score <= 3:
        strength = "Weak"
        color = Fore.RED
    elif score <= 6:
        strength = "Moderate"
        color = Fore.YELLOW
    else:
        strength = "Strong"
        color = Fore.GREEN

    return {
        "length": length,
        "score": score,
        "strength": strength,
        "color": color,
        "suggestions": suggestions,
        "entropy_bits": round(entropy, 2)
    }

def hash_password(password: str) -> str:
    """Return SHA-256 hash (hex). Demonstrates hashing concept only."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def suggest_stronger(password: str, max_suggestions: int = 3) -> list:
    """
    Provide simple, actionable suggestions that the user can apply
    to produce stronger password variants.
    This does NOT generate a secure password for storing — it guides creation.
    """
    suggestions = []
    # If short, propose lengthening
    if len(password) < 12:
        suggestions.append(password + "!" * (12 - len(password) if len(password) < 12 else 1))
    # Add uppercase if missing
    if not re.search(r'[A-Z]', password):
        suggestions.append(password.capitalize() + "1!")
    # Add digits if missing
    if not re.search(r'\d', password):
        suggestions.append(password + "2025")
    # Add symbol if missing
    if not re.search(r'[^A-Za-z0-9]', password):
        suggestions.append(password + "@#")
    # Tweak common patterns
    if "password" in password.lower():
        suggestions.append(password.replace("password", "p@ssw0rd"))
    # Return unique suggestions up to limit
    unique = []
    for s in suggestions:
        if s not in unique:
            unique.append(s)
        if len(unique) >= max_suggestions:
            break
    return unique

def interactive():
    print(Fore.CYAN + "\n🔒 SecurePass Analyzer 🔒")
    print(Fore.CYAN + "----------------------------")
    pw = input("\nEnter a password to analyze: ").strip()
    if not pw:
        print(Fore.RED + "No password entered. Exiting.")
        return

    result = check_strength(pw)
    hashed = hash_password(pw)
    suggestions = suggest_stronger(pw)

    print("\n📊 Password Strength Report:")
    print(f"  Length: {result['length']} characters")
    print(f"  Entropy: {result['entropy_bits']} bits (estimate)")
    print(f"  Score: {result['score']}/10")
    print(f"  Strength: {result['color']}{result['strength']}{Style.RESET_ALL}")

    if result["suggestions"]:
        print("\n💡 Suggestions to improve:")
        for s in result["suggestions"]:
            print("  - " + s)
    else:
        print(Fore.GREEN + "\n✅ Your password looks strong!")

    if suggestions:
        print("\n🔧 Quick stronger-password examples you can use or adapt:")
        for s in suggestions:
            print("  - " + s)

    print(Fore.CYAN + "\n🔐 SHA-256 Hash (demo only):")
    print(hashed)
    print("\n----------------------------\n")

if __name__ == "__main__":
    interactive()