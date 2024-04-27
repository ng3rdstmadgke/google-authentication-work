
class CommonUtils {
  /**
   * トークンを削除する
   */
  static revokeIdToken(key) {
    let idinfo = JSON.parse(localStorage.getItem(key))
    if (idinfo) {
      // - Google Identity - ウェブでGoogleでログイン - JavaScript API - メソッド: google.accounts.id.revoke
      //   https://developers.google.com/identity/gsi/web/reference/js-reference?hl=ja&authuser=1#google.accounts.id.revoke
      google.accounts.id.revoke(idinfo.sub, done => {
        localStorage.clear();
        location.reload();
      });
    }
  }

  /**
    * トークンを表示する
    */
  static displayIdToken(keys) {
    for (let key of keys) {
      let data = JSON.parse(localStorage.getItem(key))
      if (data) {
        let table = document.getElementById(key)
        Object.entries(data).forEach(([k, v]) => {
          table.insertAdjacentHTML("beforeend", `<tr><td>${k}</td><td width="600">${v}</td></tr>`)
        })
      }
    }
  }
}