import sys
import json
import os

# Try to import curl_cffi, fallback to standard requests if it fails
try:
    from curl_cffi import requests
    USE_CURL_CFFI = True
except ImportError:
    import requests
    USE_CURL_CFFI = False

from bs4 import BeautifulSoup

def scrape_amazon(url):
    cookies = {
        "i18n-prefs": "EUR",
        "lc-acbe": "de_DE",
    }

    headers = {
        "accept-language": "de-DE,de;q=0.9,en;q=0.8",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }

    try:
        if USE_CURL_CFFI:
            response = requests.get(
                url, impersonate="chrome110", cookies=cookies, headers=headers, timeout=30
            )
        else:
            response = requests.get(
                url, cookies=cookies, headers=headers, timeout=30
            )

        if response.status_code != 200:
            return {"error": f"Request failed with status code: {response.status_code}"}

        soup = BeautifulSoup(response.content, "html.parser")

        title = soup.find("span", id="productTitle")
        title_text = title.get_text().strip() if title else "غير متوفر"

        current_price = "غير متوفر"
        # Try multiple selectors for price
        price_selectors = [
            "span.a-price span.a-offscreen",
            "span#priceblock_ourprice",
            "span#priceblock_dealprice",
            "span.a-color-price"
        ]
        for selector in price_selectors:
            price_span = soup.select_one(selector)
            if price_span:
                current_price = price_span.get_text().strip()
                break
        
        old_price = "لا يوجد خصم"
        old_price_selectors = [
            "span.a-price.a-text-price span.a-offscreen",
            "span.priceBlockStrikePriceString",
            "span.a-text-strike"
        ]
        for selector in old_price_selectors:
            old_price_element = soup.select_one(selector)
            if old_price_element:
                old_price = old_price_element.get_text().strip()
                break

        description_text = ""
        description_div = soup.find("div", id="feature-bullets")
        if description_div:
            bullets = description_div.find_all("li")
            full_desc = " ".join([b.get_text().strip() for b in bullets])
            words = full_desc.split()
            description_text = " ".join(words[:100]) + "..."
        else:
            description_text = "الوصف غير متوفر"

        img_tag = soup.find("img", id="landingImage") or soup.find("img", id="imgBlkFront")
        img_url = img_tag.get("src") if img_tag else "الصورة غير متوفرة"

        return {
            "title": title_text,
            "current_price": current_price,
            "old_price": old_price,
            "description": description_text,
            "image_url": img_url
        }
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    try:
        if len(sys.argv) < 2:
            print(json.dumps({"error": "No URL provided"}))
            sys.exit(1)
        
        url = sys.argv[1]
        result = scrape_amazon(url)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": f"Fatal error: {str(e)}"}))
