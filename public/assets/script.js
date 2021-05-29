// ユーザー登録（鍵の登録）
async function registration() {

    // ユーザー名を取得
    const username = document.getElementById('username').value;
    if (!username) return false; // TODO onSubmit + requiredの方がいいのかも

    // 鍵生成のオプションをRPサーバーから取得
    const opResponse = await fetch('/registration-start', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username })
    });

    if (!opResponse.ok) {
        return console.error('ErrorResponse:', opResponse);
    }

    // 取得したオプションを認証器に渡し、鍵を生成してもらう
    const { options } = await opResponse.json();
    options.user.id = Uint8Array.from(options.user.id, c => c.charCodeAt(0));
    options.challenge = Uint8Array.from(options.challenge, c => c.charCodeAt(0));

    const credential = await navigator.credentials.create({ publicKey: options });

    // 登録する鍵をRPサーバーに送信
    const regResponse = await fetch('/registration', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            response: {
                attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))),
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON)))
            }
        })
    });

    // 結果を画面に表示
    const message = regResponse.ok ? '登録しました！ログインしてみてください' : 'エラーが発生しました';
    document.getElementById('message').innerText = message;
}

// ユーザー認証
async function authentication() {

    // ユーザー名を取得
    const username = document.getElementById('username').value;
    if (!username) return false; // TODO

    // 認証器からアサーションをもらうためのオプションを用意
    const opResponse = await fetch('/authentication-start', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username })
    });

    if (!opResponse.ok) {
        return console.error('ErrorResponse:', opResponse);
    }

    // 取得したオプションを認証器に渡しアサーションレスポンスをもらう
    const { options } = await opResponse.json();
    options.challenge = Uint8Array.from(options.challenge, c => c.charCodeAt(0));
    options.allowCredentials = options.allowCredentials.map(credential => Object.assign({},
        credential, {
        id: Uint8Array.from(atob(credential.id), c => c.charCodeAt(0))
    }));

    const credential = await navigator.credentials.get({ publicKey: options }).catch(err => {
        return console.log(err); // TODO
    });

    // RPサーバーにアサーションレスポンスを送り検証する
    const authResponse = await fetch('/authentication', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            credential: {
                id: btoa(String.fromCharCode(...new Uint8Array(credential.rawId)))
            },
            response: {
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                userHandle: btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle)))
            }
        })
    });

    // 結果を画面に表示
    const message = authResponse.ok ? 'ログイン成功！' : 'エラーが発生しました'; // TODO
    document.getElementById('message').innerText = message;
}

// イベントハンドラ登録
const regBtn = document.getElementById('reg');
regBtn.addEventListener('click', registration);

const authBtn = document.getElementById('auth');
authBtn.addEventListener('click', authentication);
