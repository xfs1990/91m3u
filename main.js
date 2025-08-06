addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  const targetHostname = 'missav.live' // 替换为目标站点的域名
  const targetUrl = url.href.replace(url.hostname, targetHostname)

  // 获取目标站点的响应
  const response = await fetch(targetUrl, {
    method: request.method,
    headers: request.headers
  })

  const contentType = response.headers.get('Content-Type')

  // 只处理 HTML 内容
  if (contentType && contentType.includes('text/html')) {
    const text = await response.text()

    // 替换目标站点域名为相对路径（防止泄露源站）
    let newText = text
      .replace(/https:\/\/missav\.live(\/[^\s"']*)/g, '$1')
      .replace(/https:\/\/missav\.live/g, '')

    // 替换 script 标签中的 type="text/javascript"
    newText = newText.replace(/<script\s+type="text\/javascript">/gi, '<ss>')

    // 获取当前 Worker 的完整域名，如 https://xxx.yourname.workers.dev
    const currentHost = url.origin.endsWith('/') ? url.origin : url.origin + '/'

    // 将相对路径替换为绝对路径，以当前 Worker 域名为前缀
    newText = newText
      .replace(/href="\/([^"]*)"/g, (_, path) => `href="${currentHost}${path}"`)
      .replace(/src="\/([^"]*)"/g, (_, path) => `src="${currentHost}${path}"`)

    return new Response(newText, {
      headers: response.headers,
      status: response.status,
      statusText: response.statusText
    })
  }

  // 非 HTML 内容直接返回
  return response
}
