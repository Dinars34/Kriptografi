"""
Encryption Statistics Module
Implements Entropy, NPCR, UACI, and Histogram analysis based on the provided reference paper.
"""

import numpy as np
import pandas as pd
from collections import Counter
import math

class EncryptionStats:
    
    @staticmethod
    def calculate_entropy(data_bytes: bytes) -> float:
        """
        Calculate Shannon Entropy.
        Based on Equation (6) in the paper: H(m) = Sum(P(mi) * log2(1/P(mi)))[cite: 203].
        Ideal value for 8-bit data is 8.0.
        """
        if not data_bytes:
            return 0.0
            
        # Count frequency of each byte value (0-255)
        counter = Counter(data_bytes)
        length = len(data_bytes)
        
        entropy = 0.0
        for count in counter.values():
            p_x = count / length
            entropy += - p_x * math.log2(p_x)
            
        return entropy

    @staticmethod
    def calculate_histogram(data_bytes: bytes) -> np.ndarray:
        """
        Calculate Histogram data (Frequency of values 0-255).
        Encrypted images should have a uniform (flat) histogram.
        """
        counts = np.bincount(list(data_bytes), minlength=256)
        return counts

    @staticmethod
    def calculate_npcr(img1_bytes: bytes, img2_bytes: bytes) -> float:
        """
        Calculate Number of Pixels Change Rate (NPCR).
        Based on Equation (7) in the paper[cite: 211].
        Measures sensitivity to small changes in plaintext.
        Ideal value is close to 100%[cite: 219].
        """
        if len(img1_bytes) != len(img2_bytes):
            raise ValueError("Images must have the same size for NPCR")
            
        arr1 = np.frombuffer(img1_bytes, dtype=np.uint8)
        arr2 = np.frombuffer(img2_bytes, dtype=np.uint8)
        
        # D(i,j) = 1 if C1 != C2, else 0 [cite: 212]
        diff = (arr1 != arr2).astype(int)
        
        # NPCR = (Sum(D) / (M*N)) * 100%
        npcr = (np.sum(diff) / len(arr1)) * 100.0
        return npcr

    @staticmethod
    def calculate_uaci(img1_bytes: bytes, img2_bytes: bytes) -> float:
        """
        Calculate Unified Average Changing Intensity (UACI).
        Standard metric for image encryption sensitivity.
        """
        if len(img1_bytes) != len(img2_bytes):
            raise ValueError("Images must have the same size for UACI")
            
        arr1 = np.frombuffer(img1_bytes, dtype=np.uint8).astype(float)
        arr2 = np.frombuffer(img2_bytes, dtype=np.uint8).astype(float)
        
        # Calculate absolute difference normalized by 255
        abs_diff = np.abs(arr1 - arr2) / 255.0
        
        # Average * 100%
        uaci = np.mean(abs_diff) * 100.0
        return uaci

    @staticmethod
    def calculate_avalanche_text(text1_bytes: bytes, text2_bytes: bytes) -> float:
        """
        Calculate Avalanche Effect for text (Bit Error Rate).
        Ideal value is 50% (changing 1 bit in input changes 50% bits in output).
        """
        # Ensure same length (padding if necessary just for comparison, though usually AES output is blocked)
        min_len = min(len(text1_bytes), len(text2_bytes))
        
        diff_bits = 0
        total_bits = min_len * 8
        
        for i in range(min_len):
            # XOR to find differing bits
            xor_val = text1_bytes[i] ^ text2_bytes[i]
            # Count set bits (hamming weight)
            diff_bits += bin(xor_val).count('1')
            
        return (diff_bits / total_bits) * 100.0