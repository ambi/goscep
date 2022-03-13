# goscep

A SCEP implementation by Go.

- https://www.cisco.com/c/ja_jp/support/docs/security-vpn/public-key-infrastructure-pki/116167-technote-scep-00.html
- https://docs.microsoft.com/ja-jp/mem/intune/protect/certificate-authority-add-scep-overview
- https://help.okta.com/oie/ja-jp/Content/Topics/identity-engine/devices/okta-ca-delegated-scep-win-intune.htm
- https://help.okta.com/oie/en-us/Content/Topics/identity-engine/devices/okta-ca-static-scep-macos-jamf.htm
- https://docs.microsoft.com/en-us/mem/intune/protect/scep-libraries-apis
  - https://github.com/microsoft/Intune-Resource-Access

# [RFC 8894: Simple Certificate Enrolment Protocol](https://www.rfc-editor.org/rfc/rfc8894.html)

## 1 Introduction

SCEP プロトコルは、次の操作に対応している：

- CA 公開鍵の配布
- 証明書のエンロールメントと発行
- 証明書の更新
- 証明書の問い合わせ
- CRL の問い合わせ

## 2 SCEP Overview

### 2.1 SCEP Entities

SCEP ではクライアントと CA という２つのエンティティタイプを定義している。

クライアントは証明を要求するエンティティで、次の情報を持っていなければならない：

- CA の FQDN または IP アドレス。
- 証明書が発行される前に、CA が要求する識別・認可情報。3.3.1節参照。
- CA の認証に使う識別情報。3.2.1節参照。一般的には証明書のフィンガープリント。

CA（認証局）はクライアント証明書を署名するエンティティである。CA 証明書の keyUsage 拡張は、通常の CA の keyCertSign / cRLSign のほかに、digitalSignature と keyEncipherment について有効でなければならない。

### 2.2 CA Certificate Distribution

CA 証明書をまだ知らなければ、クライアントは PKI operation の前に CA 証明書を受け取らなければならない。

### 2.3 Client Authentication

署名操作をするには、クライアントは適切なローカルの証明書を使う：

- クライアントが適切な既存の証明書を持っていなければ、自己署名証明書をローカルで生成して使わなければならない。
- クライアントがすでに SCEP CA が発行した証明書を持っていて、CA が更新をサポートしていれば、その証明書を使うべき。
- クライアントが SCEP CA の発行した証明書を持っていないが、代替 CA からのクレデンシャルを持っていれば、その代替 CA が発行する証明書を使って更新リクエストをしてもよい。SCEP CA のポリシーによって、そのリクエストを受け入れるかどうか決まる。

### 2.4 Enrollment Authorisation

PKCS #10 は エンロールメントリクエストの challengePassword 属性を定義している。

SCEP クライアントは challengePassword を含めることをすすめるが、含めないことも許される。

SCEP CA は、自己署名証明書に基づくクライアントについては、証明書フィンガープリントなどのアウトオブバンドの手段を通して検証するまで、認証しようとしてはならない。

### 2.5 Certificate Enrolment/Renewal

クライアントは、PKCS #10 を使って証明書リクエストを作ることで、enrolment transaction を開始して、CMS を使って CA にリクエストを送信する。

CA が CertRep メッセージをを PENDING ステータスで返すと、クライアントは定期的に CertPoll メッセージを送信するポーリングモードに入る。これは、CA が手動の認証（リクエストの許可または否認）を完了するまで続く。ポーリングの頻度は、発行プロセスが自動的なら数秒から数分、手動の許可が必要なら数時間から数日と、多岐に渡る。

#### 2.5.1 Client State Transitions

SCEP 処理でのクライアントの状態遷移：

``` plantuml
@startuml

[*] --> [CERT-NONEXISTENT]
[CERT-NONEXISTENT] --> [CERT-REQ-PENDING] : PKCSReq, RenewalReq
[CERT-REQ-PENDING] --> [CERT-NONEXISTENT] : CertRep(FAILURE), Max-time/max-polls exceeded
[CERT-REQ-PENDING] --> [CERT-REQ-PENDING] : CertRep(PENDING)
[CERT-REQ-PENDING] --> [CERT-ISSUED] : CertRep(SUCCESS)
[CERT-ISSUED] --> [*]

@enduml
```

- クライアントは、PKI 証明書とともに PKCSReq メッセージをサーバに送信する。
- サーバは、必要であれば証明書発行するまで pkiStatus=PENDING とともに CertRep メッセージをクライアントに返す。
- サーバは、証明書発行が完了すると、pkiStatus=SUCCESS、証明書とともに CertRep メッセージをクライアントに返す。

### 2.6 Certificate Access

証明書問い合わせメッセージは、クライアントが CA から自身の証明書を取得するのに使われる。

- クライアントは、GetCert メッセージをサーバに送信する。
- サーバは、pkiStatus=SUCCESS、証明書とともに CertRep メッセージをクライアントに返す。

### 2.7 CRL Access

SCEP クライアントは以下の３つの方法のいずれかで CRL をリクエストできる：

1. CA が CRL Distribution Point (CRLDP, RFC5280) をサポートしていれば、CRLDP を使って CRL を取得できる。
2. CA が HTTP 証明書ストアアクセス (RFC4387) をサポートしていれば、証明書の AuthorityInfoAccess (RFC5280) を使って CRL を取得できる。
3. CA が CRLDP や HTTP アクセスをサポートしていないときのみ、失効状態を問い合わせている証明書の発行者名とシリアル番号を含んだ GetCRL メッセージを作って、CRL 問い合わせが行われる。

### 2.8 Certificate Revocation

SCEP では、証明書失効リクエストの方法は定義されていない。

### 2.9 Mandatory-to-Implement Functionality

最低でも、SCEP 実装は GetCACaps、GetCACert、PKCSReq、HTTP POST によるバイナリデータ通信、pkiMessages 用の AES128-CBC、SHA-256 アルゴリズムをサポートしなければならない。

歴史的理由により、HTTP GET によるバイナリデータ通信、トリプル DES-CBC、SHA-1 アルゴリズムをサポートしていてもよい。シングル DES と MD5 アルゴリズムはサポートしてはいけない。

## 3 SCEP Secure Message Objects

CMS は任意のデータを署名・暗号化して転送することを可能にするメカニズムである。SCEP メッセージは２層の CMS を使っている。

```
pkiMessage {
  contentType = signedData { pkcs-7 2 },
  content {
    digestAlgorithms,
    encapsulatedContentInfo {
      eContentType = data { pkcs-7 1 },
      eContent {           -- pkcsPKIEnvelope, optional
        contentType = envelopedData { pkcs-7 3 },
        content {
          recipientInfo,
          encryptedContentInfo {
            contentType = data { pkcs-7 1 },
            contentEncrAlgorithm,
            encryptedContent {
              messageData  -- Typically PKCS #10 request
              }
            }
          }
        }
      },
    certificates,          -- Optional
    crls,                  -- Optional
    signerInfo {
      signedAttrs {
        transactionID,
        messageType,
        pkiStatus,
        failInfo,          -- Optional
        senderNonce / recipientNonce,
        },
      signature
    }
  }
}
```

### 3.1 SCEP Message Object Processing

SCEP メッセージの作成はいくつかの段階に分かれる。まず messageData を暗号化して、次に暗号化された内容を署名する。

受信者の公開鍵が RSA なら、受信者の公開鍵を使って messageData を暗号化する。

### 3.2 SCEP pkiMessage

SCEP メッセージの基本的な構成要素は SCEP pkiMessage である。これは CMS SignedData コンテントタイプを含む。

#### 3.2.1 Signed Transaction Attributes

最低でも、すべてのメッセージは次の authenticatedAttributes を含んでいなければならない：

- transactionID 属性。
- messageType 属性。
- 新しい senderNonce 属性。
- CMS が必要とする全属性。

メッセージが CertRep の場合、次の authenticatedAttributes も含んでいなければならない：

- pkiStatus 属性。
- pkiStatus=FAILURE の場合、failInfo とオプショナルな failInfoText 属性。
- 対応するリクエストの senderNonce からコピーした recipientNonce 属性。

#### 3.2.2 SCEP pkcsPKIEnvelope

SCEP メッセージの情報部分は EnvelopedData コンテントタイプ内に含まれる。

### 3.3 SCEP pkiMessage types

#### 3.3.1 PKCSReq/RenewalReq

PKCSReq/RenewalReq タイプの messageData は、PKCS #10 Certificate Request を含む。証明書リクエストは少なくとも次を含んでいなければならない：

- サブジェクトの Distinguished Name。
- サブジェクトの公開鍵。
- PKCSReq の場合、共有シークレットにもとづく認可が使われていれば、challengePassword 属性。

それに加えて、3.2.1節の authenticatedAttributes を含んでいなければならない。

#### 3.3.2 CertRep

pkiStatus=SUCCESS の場合、CertRep タイプの messageData は、degenerate certificate-only CMS SignedData メッセージを含む。

- PKCSReq へのレスポンス: 少なくとも、SignedData の certificates フィールドに発行した証明書を含んでいなければならない。
- RenewalReq へのレスポンス: PKCSReq へのレスポンスと同じ。
- CertPoll へのレスポンス: PKCSReq へのレスポンスと同じ。
- GetCert へのレスポンス: 少なくとも、SignedData の certificates フィールドに要求した証明書を含んでいなければならない。
- GetCRL へのレスポンス: SignedData の crls フィールドに CRL を含んでいなければならない。

pkiStatus=FAILURE の場合、failInfo 属性も含んでいなければならない。failInfoText 属性も含んでいてもよい。

pkiStatus=PENDING の場合、pkcsPKIEnvelope は省略されなければならない。

#### 3.3.3 CertPoll

CertPoll タイプのメッセージは、証明書のポーリングに使われる。

#### 3.3.4 GetCert and GetCRL

GetCert/GetCRL タイプの messageData は、CMS で定義された IssuerAndSerialNumber を含んでいる。それに加えて、3.2.1節の authenticatedAttributes を含んでいなければならない。

### 3.4 Degenerate certificates-only CMS SignedData

### 3.5 CA Capabilities

## 4 SCEP Transactions

### 4.1 HTTP POST and GET Message Formats

SCEP は HTTP POST/GET メソッドを使って、CA と情報を交換する。

```
POSTREQUEST = "POST" SP SCEPPATH "?operation=" OPERATION SP HTTP-version CRLF
GETREQUEST = "GET" SP SCEPPATH "?operation=" OPERATION "&message=" MESSAGE SP HTTP-version CRLF
```

- SCEPPATH は CA にアクセスするための HTTP URL パスである。CA が別に指示しない限り、クライアントは SCEPPATH を `/cgi-bin/pkiclient.exe` と定義すべきである。
- OPERATION は SCEP トランザクションによる。
- HTTP-version は HTTP バージョンで、`HTTP/1.1` になる。
- SP と CRLF はスペースと改行である。

### 4.2 Get CA Certificate

CA 証明書を取得するには、クライアントは OPERATION を GetCACert にセットしてメッセージを送信する。

CA が中間 CA 証明書を含まない場合、レスポンスは：

```
"Content-Type: application/x-x509-ca-cert"

<binary X.509>
```

CA が中間 CA 証明書を含む場合、レスポンスは：

```
"Content-Type: application/x-x509-ca-ra-cert"

<binary CMS>
```

### 4.3 Certificate Enrolment/Renewal

クライアントは OPERATION を PKIOperation にセットして PKCSReq/RenewalReq メッセージを送信する。

```
POST /cgi-bin/pkiclient.exe?operation=PKIOperation HTTP/1.1
Content-Length: <length of data>
Content-Type: application/x-pki-message

<binary CMS data>
```

リクエストが許可されれば、CertRep SUCCESS メッセージが返される。

```
"Content-Type: application/x-pki-message"

<binary CertRep message>
```
