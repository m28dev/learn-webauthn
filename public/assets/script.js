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
        console.error('Error Response:', opResponse);
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
    const message = regResponse.ok ? '登録しました！ログインしてみましょう' : 'エラーが発生しました';
    document.getElementById('message').innerText = message;
}

// 認証を開始
async function authentication() {
    // TODO
    const op = await fetch('/authentication-start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            name: 'msy'
        })
    }).then(response => response.json());

    const options = {
        challenge: Uint8Array.from('randomString', c => c.charCodeAt(0)),
        allowCredentials: [{
            type: "public-key",
            id: Uint8Array.from(atob(op.credentialId), c => c.charCodeAt(0))
        }]
    }

    const credential = await navigator.credentials.get({ publicKey: options });

    // 認証する
    const result = await fetch('/authentication', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            credential: {
                id: op.credentialId
            },
            response: {
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                userHandle: btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle)))
            }
        })
    });
    console.log(result);
}

// イベントハンドラ登録
const regBtn = document.getElementById('reg');
regBtn.addEventListener('click', registration);

const authBtn = document.getElementById('auth');
authBtn.addEventListener('click', authentication);
