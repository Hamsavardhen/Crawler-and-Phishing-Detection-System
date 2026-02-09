import json
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from src.image_analyzer import ImageAnalyzer
from src.domain_analyzer import DomainAnalyzer
from src.crawler import Crawler
import numpy as np

class PhishingDetector:
    def __init__(self, config_path="config.json"):
        self.load_config(config_path)
        self.setup_driver()
        self.image_analyzer = ImageAnalyzer()
        self.domain_analyzer = DomainAnalyzer(self.config["known_banks"])
        self.crawler = Crawler(self.driver, self.config["crawling"])
        
    def load_config(self, config_path):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
    
    def setup_driver(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument(f"user-agent={self.config['crawling']['user_agent']}")
        
        self.driver = webdriver.Chrome(options=chrome_options)
    
    def analyze_url(self, url):
        """Main method to analyze a URL for phishing"""
        print(f"Analyzing {url}...")
        
        # Capture screenshot
        screenshot = self.crawler.capture_screenshot(url)
        if not screenshot:
            return {"error": "Failed to capture screenshot"}
        
        # Analyze domain similarity
        domain_results = self.domain_analyzer.analyze_domain(url)
        
        # Analyze image similarity
        image_results = self.image_analyzer.analyze_screenshot(screenshot, self.config["known_banks"])
        
        # Combine results
        combined_results = self.combine_results(domain_results, image_results, url)
        
        return combined_results
    
    def combine_results(self, domain_results, image_results, url):
        """Combine domain and image analysis results"""
        results = {
            "url": url,
            "timestamp": self.image_analyzer.get_timestamp(),
            "domain_analysis": domain_results,
            "image_analysis": image_results,
            "is_phishing": False,
            "confidence": 0,
            "target_bank": None
        }
        
        # Calculate overall similarity
        max_similarity = 0
        target_bank = None
        
        for bank in self.config["known_banks"]:
            bank_short_name = bank["short_name"]
            
            domain_sim = domain_results["similarities"].get(bank_short_name, 0)
            image_sim = image_results["similarities"].get(bank_short_name, {}).get("feature_similarity", 0)
            structural_sim = image_results["similarities"].get(bank_short_name, {}).get("structural_similarity", 0)
            
            overall_sim = (
                self.config["detection"]["domain_similarity_weight"] * domain_sim +
                self.config["detection"]["image_similarity_weight"] * image_sim +
                self.config["detection"]["structural_similarity_weight"] * structural_sim
            )
            
            if overall_sim > max_similarity:
                max_similarity = overall_sim
                target_bank = bank_short_name
        
        results["confidence"] = max_similarity
        results["is_phishing"] = max_similarity > self.config["detection"]["phishing_threshold"]
        
        if target_bank:
            results["target_bank"] = target_bank
            results["target_bank_name"] = next(
                (b["name"] for b in self.config["known_banks"] if b["short_name"] == target_bank), 
                "Unknown"
            )
        
        return results
    
    def crawl_and_analyze(self, seed_urls):
        """Crawl from seed URLs and analyze each page"""
        return self.crawler.crawl_and_analyze(seed_urls, self.analyze_url)
    
    def close(self):
        """Clean up resources"""
        self.driver.quit()