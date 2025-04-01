Puppet Master
=============

Uses Google Chrome's [Puppeteer](https://pptr.dev/#?product=Puppeteer&version=v1.15.0&show=api-class-browser) library in conjunction with [Alpine Chrome](https://github.com/Zenika/alpine-chrome) Docker image and dumps it's traffic.

Example Usage
=============

Build the Docker image:
```
./build.sh
```

Add your own Puppeteer script to `src` folder:

**src/sample.js**
```
const puppeteer = require('puppeteer');

async function visit() {
    puppeteer.launch().then(async browser => {
      const page = await browser.newPage();
      await page.goto('https://www.eeman.me/');
      await browser.close();
    });
}

async function main() {
    await visit()
}

main()

```

Run Docker container with script and output PCAP file name:

```
./run-script.sh sample output_file.pcap
```

