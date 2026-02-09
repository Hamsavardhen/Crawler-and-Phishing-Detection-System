import argparse
import json
import sys
import os

# Add the parent directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detector import PhishingDetector
from src.utils import save_results, generate_report

def main():
    parser = argparse.ArgumentParser(description="Phishing Detection System for Indian Banks")
    parser.add_argument("--url", help="Single URL to analyze")
    parser.add_argument("--file", help="File containing URLs to analyze (one per line)")
    parser.add_argument("--crawl", action="store_true", help="Crawl from seed URLs")
    parser.add_argument("--output", default="phishing_results.json", help="Output file for results")
    
    args = parser.parse_args()
    
    # Initialize detector
    print("🚀 Initializing Phishing Detector...")
    detector = PhishingDetector()
    
    try:
        if args.url:
            # Analyze single URL
            print(f"🔍 Analyzing URL: {args.url}")
            result = detector.analyze_url(args.url)
            results = [result]
        
        elif args.file:
            # Analyze multiple URLs from file
            print(f"📁 Analyzing URLs from file: {args.file}")
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            results = []
            for url in urls:
                print(f"🔍 Analyzing: {url}")
                result = detector.analyze_url(url)
                results.append(result)
        
        elif args.crawl:
            # Crawl from seed URLs
            print("🌐 Starting web crawling...")
            seed_urls = [
                "https://www.google.com/search?q=sbi+netbanking+login",
                "https://www.google.com/search?q=idfc+bank+login", 
                "https://www.google.com/search?q=hdfc+netbanking"
            ]
            results = detector.crawl_and_analyze(seed_urls)
        
        else:
            print("❌ Please specify a mode: --url, --file, or --crawl")
            return
        
        # Save results
        save_results(results, args.output)
        
        # Generate report
        generate_report(results, "phishing_report.html")
        
        print(f"✅ Results saved to {args.output}")
        print(f"📊 Report generated: phishing_report.html")
        
        # Print summary
        phishing_count = sum(1 for r in results if r.get("is_phishing", False))
        print(f"📈 Analyzed {len(results)} URLs, found {phishing_count} phishing sites")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        detector.close()

if __name__ == "__main__":
    main()