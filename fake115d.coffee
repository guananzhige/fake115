`// ==UserScript==
// @name         fake 115Browser download
// @namespace    http://github.com/kkHAIKE/fake115
// @version      1.0.3
// @description  伪装115浏览器下载
// @author       kkhaike
// @match        *://115.com/*
// @match        *://v.anxia.com/*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @grant        GM_log
// @grant        GM_setClipboard
// @connect      proapi.115.com
// @require      https://peterolson.github.io/BigInteger.js/BigInteger.min.js
// @require      https://cdn.bootcdn.net/ajax/libs/blueimp-md5/2.18.0/js/md5.min.js
// @run-at       document-start
// ==/UserScript==
(function() {
    'use strict'`

getCryptoObject = ->
  return globalThis.crypto if typeof globalThis isnt 'undefined' and globalThis.crypto?.getRandomValues?
  null

cryptoObj = getCryptoObject()
randomByteBuffer = new Uint8Array 1

getRandomNonZeroByte = ->
  if cryptoObj?
    loop
      cryptoObj.getRandomValues randomByteBuffer
      return randomByteBuffer[0] if randomByteBuffer[0] isnt 0
  loop
    value = Math.floor Math.random() * 0x100
    return value if value isnt 0

class MyRsa
  constructor: ->
    @n = bigInt '8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683', 16
    @e = bigInt '10001', 16

  a2hex: (byteArray) ->
    (('0' + b.toString(16)).slice(-2) for b in byteArray).join ''

  hex2a: (hex) ->
    codes = []
    i = 0
    while i < hex.length
      codes.push parseInt(hex.substr(i, 2), 16)
      i += 2
    String.fromCharCode codes...

  pkcs1pad2: (s, n) ->
    return null if n < s.length + 11
    ba = []
    i = s.length - 1
    while i >= 0 and n > 0
      ba[--n] = s.charCodeAt(i--)
    ba[--n] = 0
    while n > 2
      ba[--n] = getRandomNonZeroByte()
    ba[--n] = 2
    ba[--n] = 0
    c = @a2hex ba
    bigInt c, 16

  pkcs1unpad2: (a) ->
    b = a.toString 16
    b = '0' + b if b.length % 2 isnt 0
    c = @hex2a b
    i = 1
    while c.charCodeAt(i) isnt 0
      i++
    c.slice i + 1

  encrypt: (text) ->
    m = @pkcs1pad2 text, 0x80
    c = m.modPow @e, @n
    h = c.toString 16
    while h.length < 0x80 * 2
      h = '0' + h
    h

  decrypt: (text) ->
    a = bigInt @a2hex(stringToBytes text), 16
    c = a.modPow @e, @n
    @pkcs1unpad2 c

new_rsa = new MyRsa()

activeDownloadDialog = null
downloadDialogKeyHandler = null
copyTimer = null

g_kts = [
    240, 229, 105, 174, 191, 220, 191, 138, 26, 69, 232, 190, 125, 166, 115, 184,
    222, 143, 231, 196, 69, 218, 134, 196, 155, 100, 139, 20, 106, 180, 241, 170,
    56, 1, 53, 158, 38, 105, 44, 134, 0, 107, 79, 165, 54, 52, 98, 166,
    42, 150, 104, 24, 242, 74, 253, 189, 107, 151, 143, 77, 143, 137, 19, 183,
    108, 142, 147, 237, 14, 13, 72, 62, 215, 47, 136, 216, 254, 254, 126, 134,
    80, 149, 79, 209, 235, 131, 38, 52, 219, 102, 123, 156, 126, 157, 122, 129,
    50, 234, 182, 51, 222, 58, 169, 89, 52, 102, 59, 170, 186, 129, 96, 72,
    185, 213, 129, 156, 248, 108, 132, 119, 255, 84, 120, 38, 95, 190, 232, 30,
    54, 159, 52, 128, 92, 69, 44, 155, 118, 213, 27, 143, 204, 195, 184, 245
]

g_key_s = [
  0x29, 0x23, 0x21, 0x5E
]

g_key_l = [
  120, 6, 173, 76, 51, 134, 93, 24, 76, 1, 63, 70
]

m115_getkey = (length, key) ->
  if key?
    return (((key[i] + g_kts[length * i]) & 0xff) ^ g_kts[length * (length - 1 - i)] for i in [0...length])
  if length is 12
    return g_key_l[..]
  g_key_s[..]

xor115_enc = (src, srclen, key, keylen) ->
  mod4 = srclen % 4
  ret = []
  if mod4 isnt 0
    for i in [0...mod4]
      ret.push src[i] ^ key[i % keylen]
  for i in [mod4...srclen]
    ret.push src[i] ^ key[(i - mod4) % keylen]
  ret

m115_sym_encode = (src, srclen, key1, key2) ->
  k1 = m115_getkey 4, key1
  k2 = m115_getkey 12, key2
  ret = xor115_enc src, srclen, k1, 4
  ret.reverse()
  xor115_enc ret, srclen, k2, 12

m115_sym_decode = (src, srclen, key1, key2) ->
  k1 = m115_getkey 4, key1
  k2 = m115_getkey 12, key2
  ret = xor115_enc src, srclen, k2, 12
  ret.reverse()
  xor115_enc ret, srclen, k1, 4

stringToBytes = (s) ->
  ret = []
  for i in [0...s.length]
    ret.push s.charCodeAt i
  ret

bytesToString = (b) ->
  ret = ''
  for i in b
    ret += String.fromCharCode i
  ret

m115_asym_encode = (src, srclen) ->
  m = 128 - 11
  ret = ''
  for i in [0...(srclen + m - 1) // m]
    ret += new_rsa.encrypt bytesToString src[i * m...Math.min((i + 1) * m, srclen)]
  window.btoa new_rsa.hex2a ret

m115_asym_decode = (src, srclen) ->
  m = 128
  ret = ''
  for i in [0...(srclen + m - 1) // m]
    ret += new_rsa.decrypt bytesToString src[i * m...Math.min((i + 1) * m, srclen)]
  stringToBytes ret

m115_encode = (src, tm) ->
  key = stringToBytes md5 "!@###@##{tm}DFDR@#@#"
  tmp = stringToBytes src
  tmp = m115_sym_encode tmp, tmp.length, key, null
  tmp = key[0...16].concat tmp
  {data:m115_asym_encode(tmp, tmp.length), key}

m115_decode = (src, key) ->
  tmp = stringToBytes window.atob src
  tmp = m115_asym_decode tmp, tmp.length
  bytesToString m115_sym_decode tmp[16..], tmp.length - 16, key, tmp[0...16]

buildDownloadUrlsText = (rs) ->
  (f.url.url for f in rs).join '\n'

ensureDownloadDialogStyle = ->
  return if document.getElementById 'fake115d-download-style'
  parent = document.head or document.body
  return unless parent?

  style = document.createElement 'style'
  style.id = 'fake115d-download-style'
  style.textContent = """
#fake115d-download-overlay {
  position: fixed;
  inset: 0;
  z-index: 2147483647;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: rgba(15, 23, 42, 0.42);
  backdrop-filter: blur(6px);
}
#fake115d-download-panel {
  width: min(720px, 100%);
  max-height: min(80vh, 760px);
  overflow: hidden;
  border-radius: 24px;
  border: 1px solid rgba(148, 163, 184, 0.28);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(248, 250, 252, 0.98));
  box-shadow: 0 24px 70px rgba(15, 23, 42, 0.22);
  color: #0f172a;
}
.fake115d-download-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 22px 24px 18px;
  border-bottom: 1px solid rgba(226, 232, 240, 0.95);
}
.fake115d-download-title {
  margin: 0;
  font-size: 20px;
  line-height: 1.2;
  font-weight: 700;
  color: #0f172a;
}
.fake115d-download-subtitle {
  margin: 6px 0 0;
  font-size: 13px;
  color: #64748b;
}
.fake115d-download-close {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border: 0;
  border-radius: 999px;
  background: rgba(148, 163, 184, 0.14);
  color: #475569;
  font-size: 22px;
  line-height: 1;
  cursor: pointer;
}
.fake115d-download-close:hover {
  background: rgba(148, 163, 184, 0.24);
}
.fake115d-download-body {
  padding: 20px 24px 24px;
}
.fake115d-download-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 16px;
}
.fake115d-download-copy {
  display: inline-flex;
  flex: none;
  align-items: center;
  justify-content: center;
  min-height: 40px;
  min-width: 124px;
  padding: 0 28px;
  border: 0;
  border-radius: 999px;
  background: linear-gradient(180deg, #1677ff, #0f6ce6);
  color: #fff;
  font-size: 13px;
  font-weight: 700;
  line-height: 1;
  letter-spacing: 0;
  white-space: nowrap;
  cursor: pointer;
  box-shadow: 0 10px 24px rgba(22, 119, 255, 0.22);
}
.fake115d-download-copy:hover {
  filter: brightness(1.04);
}
.fake115d-download-copy.is-copied {
  background: linear-gradient(180deg, #10b981, #059669);
  box-shadow: 0 10px 24px rgba(16, 185, 129, 0.22);
}
.fake115d-download-count {
  font-size: 13px;
  color: #64748b;
}
.fake115d-download-list {
  overflow: auto;
  max-height: min(56vh, 520px);
  padding-right: 4px;
}
.fake115d-download-item + .fake115d-download-item {
  margin-top: 10px;
}
.fake115d-download-link {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 14px 16px;
  border: 1px solid rgba(226, 232, 240, 0.96);
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.96);
  text-decoration: none;
  transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease, background-color .16s ease;
}
.fake115d-download-link:hover {
  transform: translateY(-1px);
  border-color: rgba(96, 165, 250, 0.7);
  background: #fff;
  box-shadow: 0 14px 28px rgba(15, 23, 42, 0.08);
}
.fake115d-download-file {
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 12px;
}
.fake115d-download-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: none;
  min-width: 46px;
  height: 32px;
  padding: 0 10px;
  border-radius: 12px;
  background: linear-gradient(180deg, #e0f2fe, #eff6ff);
  color: #0369a1;
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.03em;
  text-transform: uppercase;
}
.fake115d-download-name {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #0f172a;
  font-size: 14px;
  font-weight: 600;
}
.fake115d-download-hint {
  flex: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 72px;
  height: 30px;
  padding: 0 12px;
  border-radius: 999px;
  background: rgba(37, 99, 235, 0.08);
  color: #2563eb;
  font-size: 12px;
  font-weight: 700;
}
@media (max-width: 640px) {
  #fake115d-download-overlay {
    padding: 12px;
  }
  #fake115d-download-panel {
    width: 100%;
    max-height: 88vh;
    border-radius: 20px;
  }
  .fake115d-download-header,
  .fake115d-download-body {
    padding-left: 16px;
    padding-right: 16px;
  }
  .fake115d-download-link {
    align-items: flex-start;
  }
  .fake115d-download-hint {
    min-width: 58px;
  }
}
"""
  parent.appendChild style

closeDownloadDialog = ->
  clearTimeout copyTimer if copyTimer?
  copyTimer = null
  if downloadDialogKeyHandler?
    window.removeEventListener 'keydown', downloadDialogKeyHandler
    downloadDialogKeyHandler = null
  if activeDownloadDialog?.parentNode?
    activeDownloadDialog.parentNode.removeChild activeDownloadDialog
  activeDownloadDialog = null

showDownloadDialog = (rs) ->
  urlsText = buildDownloadUrlsText rs

  unless document?.body?
    return alert urlsText

  ensureDownloadDialogStyle()
  closeDownloadDialog()

  overlay = document.createElement 'div'
  overlay.id = 'fake115d-download-overlay'

  panel = document.createElement 'section'
  panel.id = 'fake115d-download-panel'

  header = document.createElement 'div'
  header.className = 'fake115d-download-header'

  title = document.createElement 'h3'
  title.className = 'fake115d-download-title'
  title.textContent = '下载链接'

  subtitle = document.createElement 'p'
  subtitle.className = 'fake115d-download-subtitle'
  subtitle.textContent = "#{rs.length} 个文件，单击任意一项即可下载单个文件"

  titleBox = document.createElement 'div'
  titleBox.appendChild title
  titleBox.appendChild subtitle

  closeBtn = document.createElement 'button'
  closeBtn.type = 'button'
  closeBtn.className = 'fake115d-download-close'
  closeBtn.textContent = '×'
  closeBtn.setAttribute 'aria-label', '关闭'
  closeBtn.addEventListener 'click', closeDownloadDialog

  header.appendChild titleBox
  header.appendChild closeBtn

  body = document.createElement 'div'
  body.className = 'fake115d-download-body'

  toolbar = document.createElement 'div'
  toolbar.className = 'fake115d-download-toolbar'

  count = document.createElement 'span'
  count.className = 'fake115d-download-count'
  defaultCountText = "已解析 #{rs.length} 个真实下载链接"
  count.textContent = defaultCountText

  defaultCopyText = '复制所有链接'
  copyBtn = document.createElement 'button'
  copyBtn.type = 'button'
  copyBtn.className = 'fake115d-download-copy'
  copyBtn.textContent = defaultCopyText
  copyBtn.addEventListener 'click', ->
    clearTimeout copyTimer if copyTimer?
    copyBtn.classList.add 'is-copied'
    copyBtn.textContent = '已复制'
    count.textContent = '下载链接已复制到剪贴板'
    GM_setClipboard urlsText
    copyTimer = setTimeout ->
      copyBtn.classList.remove 'is-copied'
      copyBtn.textContent = defaultCopyText
      count.textContent = defaultCountText
    , 1600

  toolbar.appendChild copyBtn
  toolbar.appendChild count

  list = document.createElement 'div'
  list.className = 'fake115d-download-list'

  for f in rs
    item = document.createElement 'div'
    item.className = 'fake115d-download-item'

    link = document.createElement 'a'
    link.className = 'fake115d-download-link'
    link.href = f.url.url
    link.target = '_blank'
    link.rel = 'noopener'
    do (f) ->
      link.addEventListener 'click', (event) ->
        event.preventDefault?()
        startSingleFileDownload f

    fileBox = document.createElement 'div'
    fileBox.className = 'fake115d-download-file'

    badge = document.createElement 'span'
    badge.className = 'fake115d-download-badge'
    parts = f.file_name.split '.'
    badge.textContent = if parts.length > 1 then parts.pop().slice(0, 4) else 'FILE'

    name = document.createElement 'span'
    name.className = 'fake115d-download-name'
    name.textContent = f.file_name

    hint = document.createElement 'span'
    hint.className = 'fake115d-download-hint'
    hint.textContent = '下载'

    fileBox.appendChild badge
    fileBox.appendChild name
    link.appendChild fileBox
    link.appendChild hint
    item.appendChild link
    list.appendChild item

  body.appendChild toolbar
  body.appendChild list
  panel.appendChild header
  panel.appendChild body
  overlay.appendChild panel

  overlay.addEventListener 'click', (event) ->
    closeDownloadDialog() if event.target is overlay

  downloadDialogKeyHandler = (event) ->
    closeDownloadDialog() if event.key is 'Escape'
  window.addEventListener 'keydown', downloadDialogKeyHandler

  document.body.appendChild overlay
  activeDownloadDialog = overlay

startSingleFileDownload = (file) ->
  link = document.createElement 'a'
  link.href = file.url.url
  link.download = file.file_name
  link.style.display = 'none'
  document.body.appendChild link
  link.click()
  link.parentNode.removeChild link

CreateDownloadTask_ = (f, cb) ->
  tmus = (new Date()).getTime()
  tm = tmus // 1000

  {data, key} = m115_encode JSON.stringify(
    pickcode: f.pc
    ), tm

  GM_xmlhttpRequest
    method: 'POST'
    url: "http://proapi.115.com/app/chrome/downurl?t=#{tm}"
    data: "data=#{encodeURIComponent(data)}"
    headers:
      'Content-Type': 'application/x-www-form-urlencoded'
    onload: (response)->
      json = JSON.parse response.responseText
      if not json.state
        alert json.msg
      else
        cb JSON.parse m115_decode json.data, key

CreateDownloadTask = (o) ->
  rs = []
  files = (f for f in o.list when not f.is_dir)
  n = files.length

  cb = (r) ->
    for x of r
      rs.push r[x]
      break

    if rs.length is n
      GM_log rs
      if rs.length is 1
        return startSingleFileDownload rs[0]
      showDownloadDialog rs

  for f in files
    CreateDownloadTask_ f, cb

browserInterface = unsafeWindow.browserInterface ? {}
browserInterface.CreateDownloadTask = (s) ->
  try
    CreateDownloadTask JSON.parse decodeURIComponent s
  catch error
    GM_log "#{error.message}\n#{error.stack}"

browserInterface.GetBrowserVersion = ->
  "100.0.0" # 目前（20210102）需要大于23.9.3

if typeof cloneInto isnt 'function'
  cloneInto = (x) -> x

unsafeWindow.browserInterface = cloneInto browserInterface, unsafeWindow, {cloneFunctions: true}

`})()`
