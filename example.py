 #!/usr/bin/env python3
"""
Example usage of the Pure Python URL Extractor
"""

from url_extractor import PureURLExtractor

def main():
    # Example 1: Basic usage
    print("Example 1: Basic URL extraction")
    print("-" * 40)

    extractor = PureURLExtractor(
        target_url="https://httpbin.org",
        verbose=True,
        max_pages=20,
        max_depth=2
    )

    extractor.extract()
    extractor.print_summary()

    print("\n" + "="*60)

    # Example 2: With output file
    print("Example 2: With JSON output")
    print("-" * 40)

    extractor2 = PureURLExtractor(
        target_url="https://example.com",
        output_file="example_results.json",
        verbose=False,
        max_pages=10,
        max_depth=1
    )

    extractor2.extract()
    extractor2.print_summary()
    extractor2.save_results()

    print("\nResults saved to: example_results.json")

if __name__ == '__main__':
    main()