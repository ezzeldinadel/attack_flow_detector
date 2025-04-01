
const puppeteer = require('puppeteer');

async function visit() {

    // launch web browser with proper SSL key dump
    const browser = puppeteer.launch({
        args: ['--ssl-key-log-file=' + process.env.SSLKEYLOGFILE]
    });

    // run the bot logic
    browser.then(async browser => {
      const page = await browser.newPage();
      await page.goto('https://www.google.com');
      await browser.close();
    });
}

async function main() {
    await visit()
}

main()

