<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>NetScout GitHub Komutları</title>
</head>
<body>

<h2>Termux (Android)</h2>
<pre>
pkg update -y && pkg install -y git python
termux-setup-storage
cd ~
git clone https://github.com/masterinmind26-cpu/NetScout.git
cd NetScout
cp /sdcard/Download/NetScout.py .
git config user.name "masterinmind26-cpu"
git config user.email "GITHUB_E_POSTANIZ"
git add NetScout.py
git commit -m "NetScout.py: pasif site araştırması eklendi"
git push
</pre>

<h2>Kali Linux</h2>
<pre>
sudo apt update && sudo apt install -y git python3
cd ~
git clone https://github.com/masterinmind26-cpu/NetScout.git
cd NetScout
cp ~/Downloads/NetScout.py .
git config user.name "masterinmind26-cpu"
git config user.email "GITHUB_E_POSTANIZ"
git add NetScout.py
git commit -m "NetScout.py: pasif site araştırması eklendi"
git push
</pre>

</body>
</html>
