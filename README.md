<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetScout GitHub Yükleme Komutları</title>
<style>
  :root { --bg:#0b0f14; --kart:#0f151d; --kenar:#22303f; --yazi:#e6edf3; --soluk:#8b98a8; --vurgu:#5fd4ff; --uyari:#ffcc66; --yesil:#7ee787; }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f5f7fa; --kart:#ffffff; --kenar:#d6dde6; --yazi:#1b2430; --soluk:#5b6878; --vurgu:#0a6cb8; --uyari:#8a5a00; --yesil:#1a7f37; }
  }
  html, body { margin:0; background:var(--bg); color:var(--yazi); font-family: "DejaVu Sans", Arial, sans-serif; }
  .kap { max-width: 860px; margin: 0 auto; padding: 16px; }
  h1 { font-size: 24px; margin: 12px 0 4px; }
  h2 { font-size: 19px; color: var(--vurgu); margin: 26px 0 10px; }
  p, li { font-size: 15px; line-height: 1.55; color: var(--soluk); }
  .uyari { background: var(--kart); border: 1px solid var(--uyari); color: var(--uyari); border-radius: 10px; padding: 12px 14px; font-size: 14px; line-height: 1.5; }
  .blok { background: var(--kart); border: 1px solid var(--kenar); border-radius: 12px; margin: 10px 0 18px; overflow: hidden; }
  .blok-ust { display:flex; justify-content: space-between; align-items:center; padding: 8px 12px; border-bottom: 1px solid var(--kenar); }
  .blok-ust span { font-size: 13px; color: var(--soluk); }
  button { background: transparent; border: 1px solid var(--kenar); color: var(--yazi); border-radius: 8px; padding: 6px 12px; font-size: 13px; cursor: pointer; }
  button:active { transform: scale(0.97); }
  pre { margin: 0; padding: 14px; overflow-x: auto; font-family: "DejaVu Sans Mono", Menlo, Consolas, monospace; font-size: 14px; line-height: 1.6; color: var(--yesil); }
  pre .y { color: var(--soluk); }
  ol li { margin-bottom: 6px; }
  code { font-family: "DejaVu Sans Mono", monospace; font-size: 13px; color: var(--vurgu); }
</style>
</head>
<body>
<div class="kap">
  <h1>NetScout: GitHub'a yükleme</h1>
  <p>Hedef depo: <code>masterinmind26-cpu/NetScout</code></p>

  <div class="uyari">
    Önce GitHub'daki README düzenleme ekranında <b>Cancel changes</b> deyin. Ekrandaki <code>&lt;title&gt;Hello&lt;/title&gt;...</code> metni deneme metni, depoya yazmayın.
    <br><br>
    Önce <b>NetScout.py</b> dosyasını telefonunuza indirin. <code>cp</code> satırındaki yol, dosyanın indiği klasöre göre değişebilir.
  </div>

  <h2>1) Termux (Android)</h2>
  <div class="blok">
    <div class="blok-ust"><span>Termux</span><button onclick="kopyala(this,'termux')">Kopyala</button></div>
<pre id="termux"><span class="y"># Gerekli araçları kur</span>
pkg update -y && pkg install -y git python
termux-setup-storage

<span class="y"># Depoyu indir</span>
cd ~
git clone https://github.com/masterinmind26-cpu/NetScout.git
cd NetScout

<span class="y"># İndirilen dosyayı depoya kopyala</span>
cp /sdcard/Download/NetScout.py .

<span class="y"># Commit kimliği</span>
git config user.name "masterinmind26-cpu"
git config user.email "GITHUB_E_POSTANIZ"

<span class="y"># Gönder</span>
git add NetScout.py
git commit -m "NetScout.py: pasif site araştırması eklendi" -m "Co-Authored-By: Claude Haiku 5.5 &lt;noreply@anthropic.com&gt;" -m "Claude-Session: https://claude.ai/code/session_01VhWX1J88YrksXeNNdGeXUk"
git push</pre>
  </div>

  <h2>2) Kali Linux</h2>
  <div class="blok">
    <div class="blok-ust"><span>Kali</span><button onclick="kopyala(this,'kali')">Kopyala</button></div>
<pre id="kali"><span class="y"># Gerekli araçları kur</span>
sudo apt update && sudo apt install -y git python3

<span class="y"># Depoyu indir</span>
cd ~
git clone https://github.com/masterinmind26-cpu/NetScout.git
cd NetScout

<span class="y"># İndirilen dosyayı depoya kopyala</span>
cp ~/Downloads/NetScout.py .

<span class="y"># Commit kimliği</span>
git config user.name "masterinmind26-cpu"
git config user.email "GITHUB_E_POSTANIZ"

<span class="y"># Gönder</span>
git add NetScout.py
git commit -m "NetScout.py: pasif site araştırması eklendi" -m "Co-Authored-By: Claude Haiku 5.5 &lt;noreply@anthropic.com&gt;" -m "Claude-Session: https://claude.ai/code/session_01VhWX1J88YrksXeNNdGeXUk"
git push</pre>
  </div>

  <h2>Notlar</h2>
  <ol>
    <li><code>GITHUB_E_POSTANIZ</code> yerine GitHub hesabınızdaki e-postayı yazın.</li>
    <li><code>git push</code> sırasında şifre yerine <b>kişisel erişim jetonu (PAT)</b> istenir. GitHub'da <i>Settings → Developer settings → Personal access tokens</i> bölümünden <code>repo</code> yetkili bir jeton oluşturun. Jetonu kimseyle paylaşmayın.</li>
    <li>Terminal kullanmak istemezseniz GitHub'da depoya girip <b>Add file → Upload files</b> ile <code>NetScout.py</code> dosyasını yükleyebilirsiniz.</li>
  </ol>
</div>

<script>
  function kopyala(dugme, kimlik) {
    try {
      const metin = document.getElementById(kimlik).innerText;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(metin).then(
          () => { dugme.textContent = "Kopyalandı"; setTimeout(() => dugme.textContent = "Kopyala", 1500); },
          () => { dugme.textContent = "Kopyalanamadı"; }
        );
      } else {
        dugme.textContent = "Kopyalanamadı";
      }
    } catch (e) {
      dugme.textContent = "Kopyalanamadı";
    }
  }
</script>
</body>
</html>
