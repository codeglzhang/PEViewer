package com.codegang.peviewer;

/**
 * 导入函数
 * @author CodeGang
 * @since jdk1.8 2019/12/3
 */
public class ImportItem {
    /**导入函数名称*/
    public String name;
    /**导入函数序号*/
    public int hint;
    /**导入函数在IAT中的位置*/
    public long addressIat;
    /**导入函数在IAT中的值，即导入函数的入口地址*/
    public long value;

    @Override
    public String toString(){
        return Long.toHexString(addressIat) + "\t\t" + name;
    }
}
