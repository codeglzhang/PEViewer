package com.codegang.peviewer;

import java.util.ArrayList;
import java.util.List;

/**
 * 解析PE文件时，缓存的一些必要数据
 * @author CodeGang
 * @since jdk1.8 2019/12/3
 */
public class InitialParameters {
    /**NT头在PE文件中的地址*/
    static long NT_ADDRESS = 0L;

    /**节区的数目*/
    static long NUMBER_OF_SECTIONS = 0L;

    /**第一个节区头在PE文件中的地址*/
    static long SECTION_HEADER_ADDRESS = 0L;

    /**DATA DIRECTORY数组的大小*/
    static long NUMBER_OF_RVA_AND_SIZE = 0L;

    /**导入表在内存中的地址*/
    static long IMPORT_TABLE_RVA = 0L;
    static long IMPORT_TABLE_SIZE = 0L;
    /**导入表在文件中的地址*/
    static long IMPORT_TABLE_RAW = 0L;

    /**导出表在内存中的地址*/
    static long EXPORT_TABLE_RVA = 0L;
    static long EXPORT_TABLE_SIZE = 0L;
    /**导出表在文件中的地址*/
    static long EXPORT_TABLE_RAW = 0L;

    /**PE文件中的节区头*/
    static List<SectionHeader> SECTION_HEADERS = new ArrayList<SectionHeader>();

    /**导入表（导入表项的描述符数组）*/
    static List<ImportDescriptor> IMPORT_TABLE = new ArrayList<ImportDescriptor>();

    /**导出表*/
    static ExportDescriptor EXPORT_TABLE = null;

}
