package com.codegang.peviewer;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

/**
 * PE解析工具类
 * @author CodeGang
 * @since jdk1.8 2019/12/3
 */
public class Utils {
    private Utils(){}

    /**
     * 从目标文件中读取多个字节，并将其转换为长整型数字
     * @param reader 目标文件
     * @param buffer 存放读取的字节
     * @return 读取结果
     * @throws IOException 在文件进行读取数据时可能会抛出异常
     */
    public static long loadValue(RandomAccessFile reader, byte[] buffer) throws IOException {
        reader.read(buffer);
        Utils.reverseByteArray(buffer);
        return longFromBytes(buffer, 0);
    }

    /**
     * 将字节数组input中,从offset到最后一个字节的数据转换为长整型的数字
     * @param input 需要转换的字节数组
     * @param offset 从第几个字节开始转换
     * @return
     */
    public static long longFromBytes(byte[] input, int offset){
        return longFromBytes(input, offset, input.length);
    }

    /**
     * 将字节数组input中,从offset开始的length个字节数据转换为长整型的数字
     * @param input 需要转换的字节数组
     * @param offset 从第几个字节开始转换
     * @return
     */
    public static long longFromBytes(byte[] input, int offset,int length) {
        long value = 0;
        // 循环读取每个字节通过移位运算完成long的8个字节拼装
        for (int count = 0; count < length; ++count) {
            int shift = (length - 1 - count) << 3;
            value |= ((long) 0xff << shift) & ((long) input[offset + count] << shift);
        }
        return value;
    }


    /**
     * 将字节数组逆序
     * @param bytes 字节数组
     */
    public static void reverseByteArray(byte[] bytes) {
        byte tmp;
        int middle = bytes.length / 2;
        for (int i = 0; i < middle; i++) {
            tmp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = tmp;
        }
    }


    /**
     * 从字节数组获取字符串。
     * @param reader 目标文件
     * @return 读取的一个字符串
     * @throws IOException 读取错误
     */
    public static String getString(RandomAccessFile reader) throws IOException {
        List<Byte> content = new ArrayList<Byte>();
        Integer tmp = reader.read();
        while (tmp>0){
            content.add(tmp.byteValue());
            tmp = reader.read();
        }
        return new String(byteListToArray(content));
    }

    /**
     * 将字节列表按序转为字节数组
     * @param list 字节列表
     * @return 转换后的字节数组
     */
    private static byte[] byteListToArray(List<Byte> list){
        byte[] array = new byte[list.size()];
        int i =0;
        for(Byte b : list){
            array[i] = b;
            i++;
        }
        return array;
    }

    /**
     * 通过给定的地址raw，从目标文件中读取一个字符串(\0结尾的字节数组)。
     * @param raw 开始读取数据的首地址
     * @param reader 目标文件
     * @return 读取的字符串
     * @throws IOException 重定位文件指针和读取数据时可能出现异常
     */
    public static String getString(long raw,RandomAccessFile reader) throws IOException {
        //缓存当前文件指针的位置
        long offset = reader.getFilePointer();
        reader.seek(raw);
        String result = getString(reader);
        //恢复文件指针的位置
        reader.seek(offset);
        return result;
    }


    private static SectionHeader findSectionHeader(long rva, List<SectionHeader> sectionHeaders){
        for (SectionHeader header:sectionHeaders){
            if(header.virtualAddress<=rva && header.virtualAddress+header.virtualSize>rva){
                return header;
            }
        }
        return null;
    }

    /**
     * 根据内存中的虚拟地址，转换为文件中的地址。
     * @param rva 内存中的虚拟地址
     * @param sectionHeaders 节区头数组
     * @return 文件中的地址,如果找不到则返回-1
     */
    public static long rvaToRaw(long rva, List<SectionHeader> sectionHeaders){
        SectionHeader header = findSectionHeader(rva,sectionHeaders);
        if(header!=null) {
            return rva - header.virtualAddress + header.pointerToRawData;
        }else {
            return -1;
        }
    }


    /**
     * 判断字节数组是否全为'\0'
     * @param content 字节数组
     * @return true:不全为'\0'，false: 全为'\0'
     */
    public static boolean hasData(byte[] content){
        for (byte b :content){
            if(b!='\0'){
                return true;
            }
        }
        return false;
    }

    /**
     * 判断字符串是否为空
     * @param s 目标字符串
     * @return true:不是空字符串，false: 空字符串
     */
    public static boolean hasText(String s){
        if(s==null||s.length()==0||"".equals(s.trim())){
            return false;
        }else {
            return true;
        }
    }
}
