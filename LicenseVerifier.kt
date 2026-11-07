package com.example.license

import android.util.Base64
import org.json.JSONObject
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * 客户端验签器。
 *
 * 只持有公钥——即使被反编译，也拿不到能签发令牌的私钥。
 * 签名算法与 Python 服务端一致：ECDSA P-256 + SHA-256（DER 编码），
 * 因此 `Signature.getInstance("SHA256withECDSA")` 可以直接验。
 */
object LicenseVerifier {

    data class Claims(
        val sub: String,
        val dev: String,
        val plan: String,
        val features: List<String>,
        val issuedAt: Long,
        val notBefore: Long,
        val expiresAt: Long,
        val jti: String,
    )

    class LicenseException(message: String) : Exception(message)

    /** 从 PEM（BEGIN PUBLIC KEY）解析公钥；建议把 PEM 字符串做一次 R8/字符串混淆。 */
    fun parsePublicKey(pem: String): PublicKey {
        val body = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\\s".toRegex(), "")
        val der = Base64.decode(body, Base64.DEFAULT)
        return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der))
    }

    /**
     * 校验令牌。
     * @param token   header.payload.signature（base64url，无填充）
     * @param pubkeys kid -> PublicKey，可同时放多把以支持轮换
     * @param deviceId 本机指纹（与激活时一致），传 null 表示只验签不校验设备
     * @param skewSec 允许的时钟偏差，默认 120 秒
     */
    fun verify(
        token: String,
        pubkeys: Map<String, PublicKey>,
        deviceId: String?,
        skewSec: Long = 120,
        nowSec: Long = System.currentTimeMillis() / 1000,
    ): Claims {
        val parts = token.split('.')
        if (parts.size != 3) throw LicenseException("令牌结构错误")

        val header = JSONObject(String(b64u(parts[0])))
        if (header.optString("alg") != "ES256") throw LicenseException("算法不支持")

        val kid = header.optString("kid")
        val pub = pubkeys[kid] ?: throw LicenseException("未知签名密钥: $kid")

        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(pub)
            update("${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII))
            verify(b64u(parts[2]))
        }
        if (!ok) throw LicenseException("签名无效")

        val c = JSONObject(String(b64u(parts[1])))
        val nbf = c.optLong("nbf")
        val exp = c.optLong("exp")
        if (nowSec + skewSec < nbf) throw LicenseException("令牌尚未生效")
        if (nowSec - skewSec > exp) throw LicenseException("令牌已过期")
        if (deviceId != null && c.optString("dev") != deviceId) throw LicenseException("设备不匹配")

        val feats = c.optJSONArray("feat")?.let { arr ->
            List(arr.length()) { arr.getString(it) }
        } ?: emptyList()

        return Claims(
            sub = c.optString("sub"),
            dev = c.optString("dev"),
            plan = c.optString("plan"),
            features = feats,
            issuedAt = c.optLong("iat"),
            notBefore = nbf,
            expiresAt = exp,
            jti = c.optString("jti"),
        )
    }

    /** 剩余有效天数，用于"即将到期"提示。 */
    fun daysLeft(claims: Claims, nowSec: Long = System.currentTimeMillis() / 1000): Long =
        ((claims.expiresAt - nowSec) / 86400L).coerceAtLeast(0)

    private fun b64u(s: String): ByteArray {
        val pad = "=".repeat((4 - s.length % 4) % 4)
        return Base64.decode(s + pad, Base64.URL_SAFE or Base64.NO_PADDING)
    }
}

/**
 * 设备指纹：与服务端 core.device_fingerprint 必须逐字节一致。
 *
 * Android 8+ 的 ANDROID_ID 按 (签名, 用户) 隔离：换签名或换用户会变，
 * 正好用来做"一台设备一份授权"，而且不需要额外权限。
 */
object DeviceId {
    fun compute(context: android.content.Context, salt: String): String {
        val androidId = android.provider.Settings.Secure.getString(
            context.contentResolver, android.provider.Settings.Secure.ANDROID_ID) ?: ""
        val pkg = context.packageName
        val cert = context.packageManager
            .getPackageInfo(pkg, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
            .signingInfo
            .apkContentsSigners
            .joinToString("") { it.toByteArray().joinToString("") { b -> "%02X".format(b) } }
        val raw = "$salt|$androidId|$pkg|$cert".toByteArray()
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(raw)
        return digest.joinToString("") { "%02x".format(it) }.substring(0, 32)
    }
}

/**
 * 请求签名（可选增强）：用激活时下发的 per-device 密钥对请求体做 HMAC，
 * 服务器侧做同样计算即可拦截"只偷到设备指纹就伪造请求"的低成本攻击。
 * 注意：这层是**辅助**，真正的信任来自令牌签名 + 设备绑定。
 */
object RequestSigner {
    fun sign(body: ByteArray, deviceKey: ByteArray, nonce: String, ts: Long): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(deviceKey, "HmacSHA256"))
        mac.update(body)
        mac.update(nonce.toByteArray())
        mac.update(ts.toString().toByteArray())
        return mac.doFinal().joinToString("") { "%02x".format(it) }
    }
}