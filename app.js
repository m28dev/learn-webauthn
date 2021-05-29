const express = require('express');
const path = require('path');
const session = require('express-session');

const cbor = require('cbor');
const crypto = require('crypto');
const jsrsasign = require('jsrsasign');
const base64url = require('base64url');

// express
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.COOKIE_SECRET || 'A2ey6LdvDg5NRrvC',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: 'auto' }
}));

// credential storage
const storage = new Map();

// Values
const RPID = process.env.RPID || 'localhost';
const ORIGIN = process.env.ORIGIN || 'http://localhost:3000';

const COSE_ALGORITHM_ES256 = -7;
const COSE_ALGORITHM_RS256 = -257;
const PUB_KEYS = [
  {
    alg: COSE_ALGORITHM_ES256,
    type: "public-key",
    algName: "SHA256withECDSA"
  },
  {
    alg: COSE_ALGORITHM_RS256,
    type: "public-key",
    algName: "SHA256withRSA"
  }
];

/* registration-start: 鍵の登録を開始する */
app.post('/registration-start', async (req, res, next) => {
  try {
    // セッションを初期化
    await new Promise((resolve, reject) => {
      req.session.regenerate(err => {
        err ? reject(err) : resolve();
      });
    });

    // ユーザー名を取得
    const username = req.body.username;
    // ユーザーIDを生成
    // 本来はユーザーを特定できない識別子にすべき
    // サンプルの仕様上、あとで扱いやすいユーザー名をIDとしている
    const id = username/* crypto.randomUUID() */;

    // ユーザー情報をセッションに保存
    req.session.regUser = { id, username };

    // チャレンジを生成し、セッションに保存する
    const challenge = crypto.randomBytes(32).toString('hex');
    req.session.regChallenge = challenge;

    // `PublicKeyCredentialCreationOptions`を生成
    const options = {
      rp: {
        name: "learn-webauthn"
      },
      user: {
        id,
        displayName: username,
        name: username
      },
      challenge,
      pubKeyCredParams: PUB_KEYS.map(({ alg, type }) => {
        return { alg, type }
      }),
      timeout: 360000,
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred"
      },
      attestation: "none"
    }

    res.json({ options });

  } catch (err) {
    next(err);
  }
});

/* registration: 鍵を登録する */
app.post('/registration', (req, res) => {
  const attestationObject = Buffer.from(req.body.response.attestationObject, 'base64');
  const JSONtext = Buffer.from(req.body.response.clientDataJSON, 'base64').toString('utf8');
  const C = JSON.parse(JSONtext);

  // `C.type`の値が`webauthn.create`かどうか確認
  if (C.type !== "webauthn.create") {
    throw new Error('C.type is not "webauthn.create"');
  }

  // `C.challenge`が`options.challenge`をbase64urlエンコードしたものと一致するか確認
  const challengeValue = req.session.regChallenge;
  if (!challengeValue || C.challenge !== base64url.encode(challengeValue)) {
    throw new Error('C.challenge does not match');
  }

  // `C.origin`がRPのオリジンと一致するか確認
  if (C.origin !== ORIGIN) {
    throw new Error('C.origin does not match');
  }

  // TODO attestation関連

  // attestationObjectをCBORデコード
  const decodedAttestationObject = cbor.decodeAllSync(attestationObject)[0];
  let authData = decodedAttestationObject.authData;

  /*
   * authDataは下記を参考に分解していく
   * https://www.w3.org/TR/webauthn-2/#authenticator-data
   */

  // rpIdHashを取得
  const rpIdHash = authData.slice(0, 32);
  authData = authData.slice(32);
  // rpIdHashが想定しているRP IDのSHA-256ハッシュか確認
  const rpId = crypto.createHash('sha256').update(RPID).digest();
  if (!rpId.equals(rpIdHash)) {
    throw new Error('rpIdHash does not match the expected RP ID hash');
  }

  // flagsを取得
  const flags = authData.slice(0, 1).readUInt8(0);
  authData = authData.slice(1);

  // User Presentのフラグ（1bit目）が立っているか確認
  const up = !!(flags & 0x01);
  if (!up) {
    throw new Error('the user is not present');
  }

  // signCountを取得
  const signCount = authData.slice(0, 4);
  authData = authData.slice(4);

  // TODO Bit 6: Attested credential data included (AT). の確認もする？？
  // TODO これ以降、どこの何を取得しているのかコメントを残す（Attested credential dataのaaguidを取得してる。など）
  // https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data

  // aaguidを取得
  const aaguid = authData.slice(0, 16);
  authData = authData.slice(16);

  // credentialIdLengthを取得
  const credentialIdLength = authData.slice(0, 2).readUInt16BE(0);
  authData = authData.slice(2);

  // credentialIdを取得
  const credentialId = authData.slice(0, credentialIdLength);
  authData = authData.slice(credentialIdLength);

  // credentialPublicKeyを取得
  const credentialPublicKey = cbor.decodeAllSync(authData)[0];

  // algが鍵の作成時に`options.pubKeyCredParams`で指定したものになっているか確認する
  const alg = credentialPublicKey.get(3);
  const pubKeyParam = PUB_KEYS.find(obj => obj.alg == alg);
  if (!pubKeyParam) {
    throw new Error('alg does not match');
  }

  // TODO Extensionsは無視していることをコメントに残す？

  // TODO 18. のfmt判定は後で

  // TODO コメント書く → 今回はサンプルなので鍵をそのまま登録する
  // 手順.22に従い、同じ鍵が別のユーザーに登録されていないか確認する必要あり

  // ユーザーと鍵を登録する
  // credentialPublicKeyをJWKの形式に変換して保存する
  let pubkeyJwk;

  switch (alg) {
    case COSE_ALGORITHM_ES256:
      pubkeyJwk = {
        kty: "EC",
        crv: "P-256",
        x: base64url.encode(credentialPublicKey.get(-2)),
        y: base64url.encode(credentialPublicKey.get(-3))
      };
      break;

    case COSE_ALGORITHM_RS256:
      pubkeyJwk = {
        kty: "RSA",
        n: base64url.encode(credentialPublicKey.get(-1)),
        e: base64url.encode(credentialPublicKey.get(-2))
      };
      break;

    default:
      pubkeyJwk = null;
      break;
  }

  // TODO 保存する内容これでOK？ よむ： https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user
  const userid = req.session.regUser.id;
  const username = req.session.regUser.username

  storage.set(userid, {
    name: username,
    displayName: username,
    credentials: [{
      credentialId: credentialId.toString('base64'),
      credentialPublicKey: pubkeyJwk,
      credentialAlgorithm: pubKeyParam.algName,
      signCount: signCount.readUInt16BE(0)
    }]
  }); // TODO transports も保存したほうがいいかな？

  // DEBUG
  console.log('alg:', pubKeyParam.algName);

  // 登録完了
  res.sendStatus(200);
});

/* authentication-start: 認証開始 */
app.post('/authentication-start', async (req, res, next) => {
  try {
    // セッションを初期化
    await new Promise((resolve, reject) => {
      req.session.regenerate(err => {
        err ? reject(err) : resolve();
      });
    });

    // ユーザー名を取得
    const username = req.body.username;

    // ログインユーザー情報をDBから取得
    const userId = username;
    const userInfo = storage.get(userId);

    // ユーザーIDをセッションに保存
    req.session.authUserId = userId;

    // チャレンジを生成、セッションに保存
    const challenge = crypto.randomBytes(32).toString('hex');
    req.session.authChallenge = challenge;

    // ユーザーが登録している鍵のクレデンシャルIDを用意
    const allowCredentials = userInfo.credentials.map(cred => {
      return {
        type: 'public-key',
        id: cred.credentialId
        // TODO transportsがあるべき (7.2 - 1)
      };
    });

    // `PublicKeyCredentialRequestOptions`を生成
    const options = {
      challenge,
      timeout: 120000,
      allowCredentials,
      userVerification: 'preferred',
    }

    res.json({ options });

  } catch (err) {
    next(err);
  }
});

/* authentication: 認証する */
app.post('/authentication', (req, res) => {

  // `authentication-start`で受け取ったユーザーIDに対して認証を実施する
  const userid = req.session.authUserId;

  if (!userid || !storage.has(userid)) {
    throw new Error('User not found');
  }

  // 認証するユーザーの情報を取得
  const userInfo = storage.get(userid);

  /* 仕様に従い検証を行う
   * https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
   */

  // 5. `options.allowCredentials`で渡した中にあったcredential.idか確認
  const credentialId = req.body.credential.id;
  const credentialIndex = userInfo.credentials.findIndex(cred => cred.credentialId == credentialId);

  if (credentialIndex == -1) {
    throw new Error('Unkown Public Key Credential');
  }

  // 6. 認証するユーザーが`credential.id`の持ち主か確認する
  // すでに手順.5で持ち主である確認はできている
  // 認証器側のuser.idとRP側のuser.idが一致するかの確認のみ行う
  const userHandle = Buffer.from(req.body.response.userHandle, 'base64').toString();
  if (userHandle && userHandle != userid) {
    throw new Error('User is not the owner of credentialSource');
  }

  // 7. `credential.id`から対応する鍵を見つけ出す
  // 鍵の種類により検証方法が違うため、アルゴリズムの情報も取得しておく
  const credentialPublicKey = userInfo.credentials[credentialIndex].credentialPublicKey;
  const credentialAlgorithm = userInfo.credentials[credentialIndex].credentialAlgorithm;

  // 8. responseの内容を取得
  const cData = Buffer.from(req.body.response.clientDataJSON, 'base64');
  const authData = Buffer.from(req.body.response.authenticatorData, 'base64');
  const sig = Buffer.from(req.body.response.signature, 'base64');

  // 9 to 10. cDataをデコードしてJSONパースする
  const JSONtext = cData.toString('utf-8');
  const C = JSON.parse(JSONtext);

  // 11. `C.type`の値が`webauthn.get`かどうか確認
  if (C.type !== "webauthn.get") {
    throw new Error('C.type is not "webauthn.get"');
  }

  // 12. `C.challenge`が`options.challenge`をbase64urlエンコードしたものと一致するか確認
  const challengeValue = req.session.authChallenge;
  if (!challengeValue || C.challenge !== base64url.encode(challengeValue)) {
    throw new Error('C.challenge does not match');
  }

  // 13. `C.origin`がRPのオリジンと一致するか確認
  if (C.origin !== ORIGIN) {
    throw new Error('C.origin does not match');
  }

  // 15. rpIdHashを取得
  const rpIdHash = authData.slice(0, 32);
  // rpIdHashが想定しているRP IDのSHA-256ハッシュか確認
  const rpId = crypto.createHash('sha256').update(RPID).digest();
  if (!rpId.equals(rpIdHash)) {
    throw new Error('rpIdHash does not match the expected RP ID hash');
  }

  // flagsを取得
  const flags = authData.slice(32, 33).readUInt8(0);

  // 16. User Presentのフラグ（1bit目）が立っているか確認
  const up = !!(flags & 0x01);
  if (!up) {
    throw new Error('the user is not present');
  }

  // 19 to 20. 署名検証
  const hash = crypto.createHash('sha256').update(cData).digest();

  const signature = new jsrsasign.KJUR.crypto.Signature({ alg: credentialAlgorithm });
  signature.init(credentialPublicKey);
  signature.updateHex(Buffer.concat([authData, hash]).toString('hex'));

  const isValid = signature.verify(sig.toString('hex'));
  if (!isValid) {
    throw new Error('Signature validation failed');
  }

  // 21. signCountを更新
  const signCount = authData.slice(33, 37).readUInt32BE(0);
  const storedSignCount = userInfo.credentials[credentialIndex].signCount;

  // signCountが前回のsignCountと同じ、もしくは少ない場合はクローンされた認証器の利用が疑われる。エラーにしとく
  if ((signCount !== 0 || storedSignCount !== 0) &&
    (signCount == storedSignCount || signCount < storedSignCount)) {
    throw new Error('signCount is invalid');
  }

  // 問題なければ`authData.signCount`で更新
  userInfo.credentials[credentialIndex].signCount = signCount;

  // 認証完了
  res.sendStatus(200);

});

// error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.sendStatus(500);
});

// Starts the HTTP server listening for connections.
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
