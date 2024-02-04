import flag from './flag.txt';

function sleep(time) {
  return new Promise(resolve => {
    setTimeout(resolve, time)
  })
}

export default {
  name: 'calculator admin bot',
  timeout: 15_000,
  handler: async (url, ctx) => {
    const page = await ctx.newPage();
    await page.setCookie({
      name: 'flag',
      value: flag.trim(),
      domain: "calculator.mc.ax"
    });
    await page.goto(url, { timeout: 5000, waitUntil: 'domcontentloaded' });
    await sleep(5000);
  }
}
