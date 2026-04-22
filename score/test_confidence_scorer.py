#!/usr/bin/env python3
"""
Unit tests for confidence_scorer.py
Tests risk threshold calculations and scoring logic
"""

import unittest
import sys
import os
import tempfile
import json

# Add the score directory to the path to import the module
sys.path.insert(0, os.path.dirname(__file__))

class TestConfidenceScorer(unittest.TestCase):
    """Test cases for confidence_scorer.py"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_input_file = os.path.join(self.temp_dir, 'test_ids.txt')
        
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_high_risk_threshold(self):
        """Test that high-risk identifiers (suspicious names) score above 70"""
        # Create test input with suspicious identifiers
        with open(self.test_input_file, 'w') as f:
            f.write("com.apple.backupd\n")
            f.write("com.apple.update\n")
            f.write("com.apple.security\n")
        
        # Import the module (if it exists)
        try:
            from confidence_scorer import calculate_score
            score = calculate_score(self.test_input_file)
            self.assertGreater(score, 70, "Suspicious identifiers should score above 70")
        except ImportError:
            self.skipTest("confidence_scorer.py module not found")
    
    def test_low_risk_threshold(self):
        """Test that low-risk identifiers (known legitimate) score below 30"""
        # Create test input with known legitimate identifiers
        with open(self.test_input_file, 'w') as f:
            f.write("com.apple.Safari\n")
            f.write("com.apple.finder\n")
            f.write("com.apple.dock\n")
        
        try:
            from confidence_scorer import calculate_score
            score = calculate_score(self.test_input_file)
            self.assertLess(score, 30, "Known legitimate identifiers should score below 30")
        except ImportError:
            self.skipTest("confidence_scorer.py module not found")
    
    def test_empty_input(self):
        """Test that empty input returns score of 0"""
        with open(self.test_input_file, 'w') as f:
            f.write("")
        
        try:
            from confidence_scorer import calculate_score
            score = calculate_score(self.test_input_file)
            self.assertEqual(score, 0, "Empty input should return score of 0")
        except ImportError:
            self.skipTest("confidence_scorer.py module not found")
    
    def test_namespace_squatting_detection(self):
        """Test detection of namespace squatting (com.apple prefix but not Apple binary)"""
        # Create test input with namespace squatting indicators
        with open(self.test_input_file, 'w') as f:
            f.write("com.apple.backupd\n")
            f.write("com.apple.security\n")
        
        try:
            from confidence_scorer import calculate_score
            score = calculate_score(self.test_input_file)
            self.assertGreater(score, 50, "Namespace squatting should score above 50")
        except ImportError:
            self.skipTest("confidence_scorer.py module not found")

if __name__ == '__main__':
    unittest.main()
