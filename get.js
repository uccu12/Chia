const axios = require('axios');
const fs = require('fs');

// Danh sách các API cung cấp proxy miễn phí (có thể thay đổi theo thời gian)
const proxySources = [
  'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=1000&country=all&ssl=all&anonymity=all',
];

async function fetchProxies() {
  let proxies = new Set();

  for (const url of proxySources) {
    try {
      const response = await axios.get(url);
      const lines = response.data.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#'));
      lines.forEach(proxy => proxies.add(proxy));
      console.log(`Fetched ${lines.length} proxies from ${url}`);
    } catch (err) {
      console.error(`Error fetching from ${url}:`, err.message);
    }
  }

  return Array.from(proxies);
}

async function saveProxiesToFile(filename, proxies) {
  fs.writeFileSync(filename, proxies.join('\n'), 'utf8');
  console.log(`Saved ${proxies.length} proxies to ${filename}`);
}

(async () => {
  const proxies = await fetchProxies();
  await saveProxiesToFile('s.txt', proxies);
})();
