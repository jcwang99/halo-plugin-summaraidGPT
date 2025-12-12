package com.handsome.summary.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import com.handsome.summary.service.SettingConfigGetter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 加密工具类
 * <p>
 * 使用 AES-256-GCM 算法对摘要内容进行加密存储，提升数据安全性。
 * 加密格式：iv:authTag:encryptedText（十六进制编码，与 Node.js 实现兼容）
 * </p>
 * 
 * @author handsome
 */
@Slf4j
@Component
public class EncryptionUtils {
    
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int GCM_IV_LENGTH = 16; // 与 Node.js 实现保持一致
    private static final int GCM_TAG_LENGTH = 16; // GCM 认证标签长度 128 位
    private static final String DEFAULT_ENCRYPTION_KEY = "default-encryption-key-change-in-production";
    
    private final SettingConfigGetter settingConfigGetter;
    private SecretKey secretKey;
    
    /**
     * 构造函数，延迟初始化密钥
     */
    @Autowired
    public EncryptionUtils(SettingConfigGetter settingConfigGetter) {
        this.settingConfigGetter = settingConfigGetter;
        // 延迟初始化，在首次使用时从配置读取
        initializeKey();
    }
    
    /**
     * 初始化加密密钥
     */
    private void initializeKey() {
        settingConfigGetter.getBasicConfig()
            .map(config -> {
                String encryptionKey = config.getEncryptionKey();
                if (encryptionKey == null || encryptionKey.trim().isEmpty()) {
                    log.warn("未配置加密密钥，使用默认密钥（不推荐生产环境）");
                    encryptionKey = DEFAULT_ENCRYPTION_KEY;
                }
                return generateKeyFromString(encryptionKey);
            })
            .defaultIfEmpty(generateKeyFromString(DEFAULT_ENCRYPTION_KEY))
            .subscribe(key -> {
                this.secretKey = key;
                log.info("加密密钥初始化完成");
            }, error -> {
                log.error("初始化加密密钥失败，使用默认密钥", error);
                this.secretKey = generateKeyFromString(DEFAULT_ENCRYPTION_KEY);
            });
    }
    
    /**
     * 获取加密密钥（如果未初始化则使用默认值）
     */
    private SecretKey getSecretKey() {
        if (secretKey == null) {
            log.warn("加密密钥未初始化，使用默认密钥");
            secretKey = generateKeyFromString(DEFAULT_ENCRYPTION_KEY);
        }
        return secretKey;
    }
    
    /**
     * 从字符串生成 AES-256 密钥
     * 
     * @param keyString 密钥字符串
     * @return SecretKey 对象
     */
    private SecretKey generateKeyFromString(String keyString) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = sha.digest(keyString.getBytes(StandardCharsets.UTF_8));
            // 确保密钥长度为 32 字节（AES-256）
            return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        } catch (Exception e) {
            log.error("生成加密密钥失败", e);
            // 如果生成失败，使用默认密钥（不推荐）
            return generateDefaultKey();
        }
    }
    
    /**
     * 生成默认密钥（仅用于开发环境）
     */
    private SecretKey generateDefaultKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        } catch (Exception e) {
            log.error("生成默认密钥失败", e);
            throw new RuntimeException("无法初始化加密密钥", e);
        }
    }
    
    /**
     * 加密文本
     * <p>
     * 在 Java 的 GCM 模式下，doFinal 返回的字节数组包含：加密数据 + 认证标签
     * 认证标签在最后 GCM_TAG_LENGTH 字节
     * </p>
     * 
     * @param plaintext 明文
     * @return 加密后的字符串，格式为 "iv:authTag:encryptedText"（十六进制编码），如果加密失败返回 null
     */
    public String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            log.warn("明文为空，无法加密");
            return null;
        }
        
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            
            // 生成随机 IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            
            // 初始化加密器
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(), parameterSpec);
            
            // 执行加密
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            
            // 在 Java GCM 模式下，doFinal 返回的数据格式为：加密数据 + 认证标签
            // 认证标签在最后 GCM_TAG_LENGTH 字节
            int encryptedDataLength = encryptedBytes.length - GCM_TAG_LENGTH;
            byte[] encryptedData = new byte[encryptedDataLength];
            byte[] authTag = new byte[GCM_TAG_LENGTH];
            System.arraycopy(encryptedBytes, 0, encryptedData, 0, encryptedDataLength);
            System.arraycopy(encryptedBytes, encryptedDataLength, authTag, 0, GCM_TAG_LENGTH);
            
            // 转换为十六进制字符串（与 Node.js 实现保持一致）
            String ivHex = bytesToHex(iv);
            String authTagHex = bytesToHex(authTag);
            String encryptedHex = bytesToHex(encryptedData);
            
            // 组合：iv:authTag:encryptedText（十六进制格式，与 Node.js 保持一致）
            return ivHex + ":" + authTagHex + ":" + encryptedHex;
            
        } catch (Exception e) {
            log.error("加密失败", e);
            return null;
        }
    }
    
    /**
     * 解密文本
     * 
     * @param ciphertext 密文，格式为 "iv:authTag:encryptedText"（十六进制编码）
     * @return 解密后的明文，如果解密失败返回 null
     */
    public String decrypt(String ciphertext) {
        if (ciphertext == null || ciphertext.isEmpty()) {
            log.warn("密文为空，无法解密");
            return null;
        }
        
        try {
            // 解析密文格式：iv:authTag:encryptedText
            String[] parts = ciphertext.split(":");
            if (parts.length != 3) {
                log.error("密文格式错误，应为 iv:authTag:encryptedText，实际: {}", ciphertext);
                return null;
            }
            
            // 从十六进制字符串解析（与 Node.js 实现保持一致）
            byte[] iv = hexToBytes(parts[0]);
            byte[] authTag = hexToBytes(parts[1]);
            byte[] encryptedData = hexToBytes(parts[2]);
            
            // 初始化解密器
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), parameterSpec);
            
            // 组合加密数据和认证标签（认证标签在最后，与加密时保持一致）
            byte[] encryptedBytes = new byte[encryptedData.length + authTag.length];
            System.arraycopy(encryptedData, 0, encryptedBytes, 0, encryptedData.length);
            System.arraycopy(authTag, 0, encryptedBytes, encryptedData.length, authTag.length);
            
            // 执行解密（GCM 会自动验证认证标签）
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
            
        } catch (Exception e) {
            log.error("解密失败，可能是密钥错误或数据被篡改", e);
            return null;
        }
    }
    
    /**
     * 将字节数组转换为十六进制字符串
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
    
    /**
     * 将十六进制字符串转换为字节数组
     */
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
