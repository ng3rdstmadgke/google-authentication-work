# 動かし方

```bash
# 環境変数にクライアントIDとクライアントシークレットを設定
cat <<EOF > app/.env
CLIENT_ID=xxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com
CLIENT_SECRET=xxxxxx-xxxxxxxxxxxxxxxxxxxxxxx-xxxx
EOF

# poetry インストール
pip install poetry

# アプリ起動
./bin/run.sh
```


ブラウザでアクセス
http://localhost:8000/
