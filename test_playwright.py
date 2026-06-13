import asyncio
from playwright.async_api import async_playwright

async def test():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.goto("https://example.com")
        await page.screenshot(path="test.png")
        await browser.close()
        print("Done!")

asyncio.run(test())