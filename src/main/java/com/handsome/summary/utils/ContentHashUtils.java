package com.handsome.summary.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import lombok.extern.slf4j.Slf4j;

/**
 * 内容哈希工具类
 * <p>
 * 用于生成文章内容的 SHA-256 哈希值，用于缓存判断和内容变化检测。
 * </p>
 * 
 * @author handsome
 */
@Slf4j
public class ContentHashUtils {
    
    private static final String ALGORITHM = "SHA-256";
    
    /**
     * 生成内容的 SHA-256 哈希值
     * 
     * @param content 要哈希的内容
     * @return 十六进制字符串格式的哈希值，如果内容为空或发生错误则返回 null
     */
    public static String generateHash(String content) {
        if (content == null || content.trim().isEmpty()) {
            log.warn("内容为空，无法生成哈希值");
            return null;
        }
        
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] hashBytes = digest.digest(content.trim().getBytes(StandardCharsets.UTF_8));
            
            // 转换为十六进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte hashByte : hashBytes) {
                String hex = Integer.toHexString(0xff & hashByte);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA-256 算法不可用", e);
            return null;
        } catch (Exception e) {
            log.error("生成内容哈希失败", e);
            return null;
        }
    }
    
    /**
     * 比较两个哈希值是否相等
     * 
     * @param hash1 第一个哈希值
     * @param hash2 第二个哈希值
     * @return 如果两个哈希值相等（忽略大小写）则返回 true，否则返回 false
     */
    public static boolean isHashEqual(String hash1, String hash2) {
        if (hash1 == null || hash2 == null) {
            return false;
        }
        return hash1.equalsIgnoreCase(hash2);
    }
}

