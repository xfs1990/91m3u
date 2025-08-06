addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

const enableVerification = false; // true 开启验证，false 关闭验证
const secret = 'your-secret-key'; // 替换为你的密钥
const baseUrl = 'https://shark10g2.jiuse3.cloud'; // 源站地址

async function handleRequest(request) {
  const url = new URL(request.url);
  let path = url.pathname;

  // 只处理 /v/ 开头路径
  const newPathPrefix = '/v/';
  if (path.startsWith(newPathPrefix)) {
    path = path.replace(newPathPrefix, '/');
  } else {
    return new Response('无权访问91！', { status: 410, headers: getCORSHeaders() });
  }

  // 签名验证逻辑（只对 .m3u8 有效）
  if (enableVerification && path.endsWith('.m3u8')) {
    const expires = url.searchParams.get('expires');
    const signature = url.searchParams.get('signature');

    if (!expires || !signature) {
      return new Response('缺少有效期或签名', { status: 403, headers: getCORSHeaders() });
    }

    const now = Math.floor(Date.now() / 1000);
    if (now > parseInt(expires)) {
      return new Response('URL 已过期', { status: 403, headers: getCORSHeaders() });
    }

    const originalUrl = url.origin + url.pathname;
    const expectedSignature = await generateHmac(originalUrl + expires, secret);
    if (signature !== expectedSignature) {
      return new Response('签名无效', { status: 403, headers: getCORSHeaders() });
    }
  }

  // 请求头设置
  const headers = new Headers({
    "accept": "*/*",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site"
  });

  const targetUrl = `${baseUrl}${path}`;

  // 处理 .m3u8 文件（替换 .ts 为 .log）
  if (path.endsWith('.m3u8')) {
    const response = await fetch(targetUrl, {
      method: request.method,
      headers
    });

    const text = await response.text();
    const modifiedText = text.replace(/\.ts(\?[^"'\s]*)?/g, '.log$1');

    return new Response(modifiedText, {
      status: response.status,
      statusText: response.statusText,
      headers: {
        ...getCORSHeaders(),
        'Content-Type': 'application/vnd.apple.mpegurl'
      }
    });
  }

  // 处理 .log 分片（映射到 .ts）
  if (path.endsWith('.log')) {
    const tsPath = path.replace(/\.log$/, '.ts');
    const tsUrl = `${baseUrl}${tsPath}`;

    const response = await fetch(tsUrl, {
      method: request.method,
      headers
    });

    const headersClone = new Headers(response.headers);
    headersClone.set('Cache-Control', 'public, max-age=2592000'); // 30 天缓存

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: {
        ...getCORSHeaders(),
        ...headersClone
      }
    });
  }

  // 其他默认转发
  const response = await fetch(targetUrl, {
    method: request.method,
    headers
  });

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: {
      ...getCORSHeaders(),
      'Content-Type': response.headers.get('Content-Type') || 'application/octet-stream'
    }
  });
}

// CORS 响应头
function getCORSHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range',
    'Access-Control-Expose-Headers': 'Content-Length,Content-Range'
  };
}

// HMAC 签名生成函数
async function generateHmac(message, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}
