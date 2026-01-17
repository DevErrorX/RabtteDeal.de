import sys
import json
import os
from curl_cffi import requests
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
        response = requests.get(
            url, impersonate="chrome110", cookies=cookies, headers=headers, timeout=30
        )

        if response.status_code != 200:
            return {"error": f"Request failed: {response.status_code}"}

        soup = BeautifulSoup(response.content, "html.parser")

        title = soup.find("span", id="productTitle")
        title_text = title.get_text().strip() if title else "غير متوفر"

        current_price = "غير متوفر"
        price_span = soup.select_one("span.a-price span.a-offscreen")
        if price_span:
            current_price = price_span.get_text().strip()
        
        old_price = "لا يوجد خصم"
        old_price_element = soup.select_one("span.a-price.a-text-price span.a-offscreen")
        if old_price_element:
            old_price = old_price_element.get_text().strip()

        description_text = ""
        description_div = soup.find("div", id="feature-bullets")
        if description_div:
            bullets = description_div.find_all("li")
            full_desc = " ".join([b.get_text().strip() for b in bullets])
            words = full_desc.split()
            description_text = " ".join(words[:100]) + "..."
        else:
            description_text = "الوصف غير متوفر"

        img_tag = soup.find("img", id="landingImage")
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
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No URL provided"}))
        sys.exit(1)
    
    url = sys.argv[1]
    result = scrape_amazon(url)
    print(json.dumps(result))
