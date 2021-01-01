from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.keys import Keys
from time import sleep

with open("enc.txt") as f:
    coords = f.read().strip().split(')')
    coords = [x.strip('(') for x in coords]
    coords = [(float(x.split(',')[0]), float(x.split(',')[1])) for x in coords if x]
print(len(coords))


def scrape():
    browser = webdriver.Chrome()
    browser.get("https://www.google.com/maps")

    input_box = browser.find_element_by_id("searchboxinput")

    for coord in coords:
        input_box.clear()
        input_box.send_keys(str(coord))
        input_box.send_keys(Keys.ENTER)

        for i in range(100):
            sleep(0.05)
            try:
                address_box = browser.find_element_by_css_selector(
                    "#pane > div > div.widget-pane-content.scrollable-y > div > div > div:nth-child(8) > div > div.section-info-line > span.section-info-text > span.widget-pane-link")
                if not address_box.text:
                    continue
                break
            except NoSuchElementException:
                pass
        with open("addresses.txt", 'a') as f:
            f.write(address_box.text + '\n')

    input("Hit enter to exit")
    browser.quit()


ans = ""
with open("addresses.txt") as f:
    for i, line in enumerate(f):
        country = line.split(',')[-1].strip()
        if country.endswith("Hungary"):
            country = "Hungary"
        elif country == "92825":
            country = "Ukraine"
        elif country == "6VF8FWQ6+35":
            country = "Nauru"
        elif country == "South Pacific Ocean" and round(coords[i][0]) == -20 and round(coords[i][1]) == -174:
            country = "Tonga"
        elif country == "Lake Kivu":
            country = "Rwanda"
        print(country, coords[i])
        ans += country[0]
print("nactf{" + ans + "}")
