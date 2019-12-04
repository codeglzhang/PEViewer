package com.codegang.peviewer;

/**
 * 导出函数
 * @author CodeGang
 * @since jdk1.8 2019/12/3
 */
public class ExportItem {
    /**函数名*/
    public String name="null";

    /**导出序号*/
    public int ordinal;

    /** 在PE文件中的位置*/
    public long addressEat;

    /**导出函数的地址*/
    public long value;


    @Override
    public String toString(){
        return Long.toHexString(addressEat) + "\t\t" + name;
    }
}
